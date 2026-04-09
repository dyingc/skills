#!/usr/bin/env python3
"""
PDF Figure Extraction via caption-anchored cropping (v4).

Academic papers reliably place figures near a caption that matches
"Figure N" / "Fig. N" / "Table N" / "Listing N". This script:

  1. Scans every page for caption lines using strict block-first-line regex on
     PyMuPDF text blocks. This avoids body-text false positives like
     "Figure 4. The former leads directly to the bug in the binary." which is
     a sentence mentioning Figure 4, not a caption.
  2. For each figure caption, clusters drawings / images / narrow text labels
     in the caption's COLUMN (narrow sub-column, half column, or full page
     width depending on caption width) starting from the rect nearest the
     caption and greedy-extending while the vertical gap stays below 45pt.
  3. For tables whose block contains the entire table + caption text (the
     common IEEE layout where PyMuPDF merges data rows and caption into one
     block), uses the block bbox directly.
  4. Renders the cropped region at the requested DPI to PNG.
  5. For listings, extracts the code as plain text to listings/ (code is
     embedded via markdown code fence, not as an image).
  6. Writes an extraction_index.json with caption metadata so that the
     Figure Analyst and chapter agents have an authoritative mapping from
     paper labels ("Figure 3") to local files.

Dependencies: pymupdf (>= 1.23), Pillow.
"""

from __future__ import annotations

import argparse
import hashlib
import io
import json
import re
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import List, Dict, Any, Optional, Tuple

import pymupdf
from PIL import Image


# ---------------------------------------------------------------------------
# Caption detection
# ---------------------------------------------------------------------------

# Strict caption patterns: the number must be followed by "." or ":".
# This avoids matching body-text mentions like "Figure 4, which shows..."
# or "Figure 10)" inside sentences.
FIGURE_CAPTION_RE = re.compile(
    r"^\s*Fig(?:ure|\.)\s+(\d+)\s*[.:]",
    re.IGNORECASE,
)
TABLE_CAPTION_RE = re.compile(
    r"^\s*TABLE\s+([IVXLCDM]+|\d+)\s*[.:]",
    re.IGNORECASE,
)
LISTING_CAPTION_RE = re.compile(
    r"^\s*Listing\s+(\d+)\s*[.:]",
    re.IGNORECASE,
)


@dataclass
class Caption:
    kind: str                    # "figure" | "table" | "listing"
    label: str                   # "Figure 1", "Table I", "Listing 7"
    number: str                  # "1", "I", "7"
    text: str                    # full line text (caption line)
    page: int                    # 0-indexed
    bbox: Tuple[float, float, float, float]  # block x0, y0, x1, y1

    @property
    def rect(self) -> pymupdf.Rect:
        return pymupdf.Rect(*self.bbox)


def _line_text(line: Dict[str, Any]) -> str:
    """Join the spans of a text line into a single string."""
    return "".join(span.get("text", "") for span in line.get("spans", []))


def find_captions(doc: pymupdf.Document) -> List[Caption]:
    """
    Scan every page and return a list of all captions found.

    Primary rule: the caption is the FIRST non-empty line of a text block.
    This eliminates body-text sentences that happen to start with "Figure N"
    mid-paragraph.

    Secondary rule (tables only): some tables have the caption embedded at
    a later line of a block whose earlier lines are the table data rows.
    For those cases, scan the remaining lines too.
    """
    captions: List[Caption] = []

    for page_idx, page in enumerate(doc):
        for block in page.get_text("dict").get("blocks", []):
            if block.get("type") != 0:  # 0 = text block
                continue

            # Keep only non-empty lines
            lines = [
                line for line in block.get("lines", [])
                if _line_text(line).strip()
            ]
            if not lines:
                continue

            bbox = tuple(block["bbox"])
            first_text = _line_text(lines[0]).strip()

            # Figure caption at first line
            m = FIGURE_CAPTION_RE.match(first_text)
            if m:
                captions.append(Caption(
                    kind="figure",
                    label=f"Figure {m.group(1)}",
                    number=m.group(1),
                    text=first_text[:240],
                    page=page_idx,
                    bbox=bbox,
                ))
                continue

            # Listing caption at first line
            m = LISTING_CAPTION_RE.match(first_text)
            if m:
                captions.append(Caption(
                    kind="listing",
                    label=f"Listing {m.group(1)}",
                    number=m.group(1),
                    text=first_text[:240],
                    page=page_idx,
                    bbox=bbox,
                ))
                continue

            # Table caption at first line
            m = TABLE_CAPTION_RE.match(first_text)
            if m:
                captions.append(Caption(
                    kind="table",
                    label=f"Table {m.group(1)}",
                    number=m.group(1),
                    text=first_text[:240],
                    page=page_idx,
                    bbox=bbox,
                ))
                continue

            # Table special case: data rows then caption inside one block
            for line in lines[1:]:
                ltext = _line_text(line).strip()
                m = TABLE_CAPTION_RE.match(ltext)
                if m:
                    captions.append(Caption(
                        kind="table",
                        label=f"Table {m.group(1)}",
                        number=m.group(1),
                        text=ltext[:240],
                        page=page_idx,
                        bbox=bbox,
                    ))
                    break

    # Dedup: keep the first occurrence per (kind, number). Sorted block-first
    # detection already avoids body-text duplicates, so first-wins is safe.
    seen: Dict[Tuple[str, str], Caption] = {}
    for cap in captions:
        key = (cap.kind, cap.number)
        if key not in seen:
            seen[key] = cap
    return sorted(seen.values(), key=lambda c: (c.page, c.bbox[1]))


# ---------------------------------------------------------------------------
# Region cropping
# ---------------------------------------------------------------------------

def _compute_column(
    page_rect: pymupdf.Rect,
    cap_bbox: Tuple[float, float, float, float],
) -> Tuple[float, float]:
    """
    Determine the horizontal column that contains a figure caption.

    - Wide captions (> 60% of page width)  → full page width (2-column fig)
    - Half-width captions (> 30%)          → left or right IEEE column
    - Narrow captions (≤ 30%)              → caption-centered sub-column
    """
    cx0, _, cx1, _ = cap_bbox
    cap_cx = (cx0 + cx1) / 2.0
    pw = page_rect.x1 - page_rect.x0
    mid = (page_rect.x0 + page_rect.x1) / 2.0
    cw = cx1 - cx0

    if cw > pw * 0.6:
        return (page_rect.x0 + 2, page_rect.x1 - 2)
    if cw > pw * 0.3:
        if cap_cx < mid:
            return (page_rect.x0 + 2, mid - 2)
        return (mid + 2, page_rect.x1 - 2)
    return (
        max(page_rect.x0 + 2, cx0 - 15),
        min(page_rect.x1 - 2, cx1 + 15),
    )


def crop_figure_region(
    page: pymupdf.Page,
    caption: Caption,
    *,
    max_height_pt: float = 560.0,
    gap_pt: float = 45.0,
) -> Optional[pymupdf.Rect]:
    """
    Compute a bounding box for the figure associated with a caption.

    Strategy:
        1. Tables whose block already contains the data rows (block height
           > 30pt) → use the block bbox directly.
        2. Otherwise: look above the caption (figures / listings) or below
           (IEEE tables with caption above data). Within the caption's
           column, collect drawings, raster images, and narrow text labels
           as "figure content". Cluster starting from the rect nearest the
           caption and extend while the gap stays below gap_pt. Return the
           tight bounding box of that cluster.
    """
    page_rect = page.rect
    cx0, cy0, cx1, cy1 = caption.bbox

    # ---- Case 1: table merged block ----
    if caption.kind == "table" and (cy1 - cy0) > 30:
        return pymupdf.Rect(
            max(page_rect.x0 + 2, cx0 - 3),
            max(page_rect.y0 + 2, cy0 - 3),
            min(page_rect.x1 - 2, cx1 + 3),
            min(page_rect.y1 - 2, cy1 + 3),
        )

    # ---- Case 2: caption-anchored crop ----
    col_x0, col_x1 = _compute_column(page_rect, caption.bbox)
    col_w = col_x1 - col_x0

    prefer_above = caption.kind != "table"
    if prefer_above:
        y_near = cy0
        y_far = max(page_rect.y0 + 2, cy0 - max_height_pt)
    else:
        y_near = cy1
        y_far = min(page_rect.y1 - 2, cy1 + max_height_pt)

    def in_region(ry0: float, ry1: float, rx0: float, rx1: float) -> bool:
        if max(rx0, col_x0) >= min(rx1, col_x1):
            return False
        if prefer_above:
            return ry1 <= y_near + 1 and ry1 >= y_far
        return ry0 >= y_near - 1 and ry0 <= y_far

    content: List[Tuple[float, float, float, float]] = []

    # Vector drawings
    for d in page.get_drawings():
        r = d.get("rect")
        if r is None:
            continue
        if r.width < 0.5 or r.height < 0.5:
            continue
        if in_region(r.y0, r.y1, r.x0, r.x1):
            content.append((r.x0, r.y0, r.x1, r.y1))

    # Raster images
    try:
        for img in page.get_image_info(hashes=False, xrefs=False):
            b = img.get("bbox")
            if not b:
                continue
            if in_region(b[1], b[3], b[0], b[2]):
                content.append(tuple(b))
    except Exception:
        pass

    # Narrow text labels (figure legends / node labels)
    for b in page.get_text("blocks"):
        if len(b) < 7:
            continue
        bx0, by0, bx1, by1, btext, _, btype = b[:7]
        if btype != 0:
            continue
        # Skip the caption block itself
        if (bx0, by0, bx1, by1) == caption.bbox:
            continue
        btxt = btext.strip()
        # Skip other caption-like blocks so they don't pull the bbox sideways
        if (btxt.startswith("Fig. ")
                or btxt.startswith("Figure ")
                or btxt.startswith("TABLE ")
                or btxt.startswith("Table ")
                or btxt.startswith("Listing ")):
            continue
        # Only narrow blocks are figure labels; wide blocks are body text
        if bx1 - bx0 > col_w * 0.75:
            continue
        if in_region(by0, by1, bx0, bx1):
            content.append((bx0, by0, bx1, by1))

    if not content:
        return None

    # Cluster: greedy from the rect nearest the caption
    if prefer_above:
        content.sort(key=lambda r: -r[3])
        cluster = [content[0]]
        cur_top = content[0][1]
        for r in content[1:]:
            if r[3] >= cur_top - gap_pt:
                cluster.append(r)
                cur_top = min(cur_top, r[1])
            else:
                break
    else:
        content.sort(key=lambda r: r[1])
        cluster = [content[0]]
        cur_bot = content[0][3]
        for r in content[1:]:
            if r[1] <= cur_bot + gap_pt:
                cluster.append(r)
                cur_bot = max(cur_bot, r[3])
            else:
                break

    min_x = min(r[0] for r in cluster)
    min_y = min(r[1] for r in cluster)
    max_x = max(r[2] for r in cluster)
    max_y = max(r[3] for r in cluster)

    min_x = max(col_x0, min_x - 3)
    max_x = min(col_x1, max_x + 3)
    min_y = max(page_rect.y0 + 2, min_y - 5)
    max_y = min(page_rect.y1 - 2, max_y + 5)

    if prefer_above:
        max_y = min(max_y, cy0 - 2)
    else:
        min_y = max(min_y, cy1 + 2)

    if max_y - min_y < 15 or max_x - min_x < 30:
        return None
    return pymupdf.Rect(min_x, min_y, max_x, max_y)


def render_region(page: pymupdf.Page, bbox: pymupdf.Rect, dpi: int = 200) -> bytes:
    """Render a page region to PNG bytes at the requested DPI."""
    zoom = dpi / 72.0
    matrix = pymupdf.Matrix(zoom, zoom)
    pix = page.get_pixmap(matrix=matrix, clip=bbox, alpha=False)
    return pix.tobytes("png")


# ---------------------------------------------------------------------------
# Listing extraction (text-only)
# ---------------------------------------------------------------------------

def extract_listing_text(page: pymupdf.Page, caption: Caption) -> str:
    """
    Extract the text of a listing by collecting text blocks near the caption.

    Listings are always above their caption in the same column; we use the
    caption column to filter and the caption y range to select nearby blocks.
    """
    page_rect = page.rect
    col_x0, col_x1 = _compute_column(page_rect, caption.bbox)
    cap = caption.rect

    collected: List[Tuple[float, str]] = []
    for block in page.get_text("dict").get("blocks", []):
        if block.get("type") != 0:
            continue
        bx0, by0, bx1, by1 = block["bbox"]
        bcx = (bx0 + bx1) / 2.0
        if not (col_x0 <= bcx <= col_x1):
            continue
        # Within 360pt above or below the caption
        if by1 < cap.y0 - 360 or by0 > cap.y1 + 360:
            continue

        block_lines = []
        for line in block.get("lines", []):
            ltext = _line_text(line)
            if not ltext.strip():
                continue
            if LISTING_CAPTION_RE.match(ltext.strip()):
                continue
            block_lines.append(ltext.rstrip())
        if block_lines:
            collected.append((by0, "\n".join(block_lines)))

    collected.sort(key=lambda t: t[0])
    return "\n\n".join(text for _, text in collected).strip()


# ---------------------------------------------------------------------------
# Main driver
# ---------------------------------------------------------------------------

def extract_all(pdf_path: str, output_dir: str, dpi: int = 200) -> Dict[str, Any]:
    """Run the full extraction pipeline."""
    out_root = Path(output_dir)
    out_figures = out_root / "figures"
    out_listings = out_root / "listings"
    out_figures.mkdir(parents=True, exist_ok=True)
    out_listings.mkdir(parents=True, exist_ok=True)

    doc = pymupdf.open(pdf_path)
    captions = find_captions(doc)

    figures_out: List[Dict[str, Any]] = []
    listings_out: List[Dict[str, Any]] = []
    seen_hashes: set = set()

    for cap in captions:
        page = doc[cap.page]

        if cap.kind == "listing":
            text = extract_listing_text(page, cap)
            if not text:
                continue
            filename = f"listing_{cap.number.zfill(2)}.txt"
            (out_listings / filename).write_text(text, encoding="utf-8")
            listings_out.append({
                "listing_id": f"listing_{cap.number}",
                "paper_label": cap.label,
                "number": cap.number,
                "page": cap.page + 1,
                "caption": cap.text,
                "file": f"listings/{filename}",
            })
            continue

        bbox = crop_figure_region(page, cap)
        if bbox is None:
            continue
        try:
            img_bytes = render_region(page, bbox, dpi=dpi)
        except Exception as exc:
            print(f"[warn] render failed for {cap.label} page {cap.page+1}: {exc}",
                  file=sys.stderr)
            continue

        h = hashlib.md5(img_bytes).hexdigest()
        if h in seen_hashes:
            continue
        seen_hashes.add(h)

        prefix = "table" if cap.kind == "table" else "figure"
        safe_num = re.sub(r"[^A-Za-z0-9]", "_", cap.number)
        filename = f"{prefix}_{safe_num}_{h[:8]}.png"
        (out_figures / filename).write_bytes(img_bytes)

        try:
            with Image.open(io.BytesIO(img_bytes)) as img:
                width, height = img.size
        except Exception:
            width = height = None

        figures_out.append({
            "figure_id": f"{prefix}_{cap.number}",
            "paper_label": cap.label,
            "kind": cap.kind,
            "number": cap.number,
            "page": cap.page + 1,
            "caption": cap.text,
            "file": f"figures/{filename}",
            "bbox": [round(v, 2) for v in (bbox.x0, bbox.y0, bbox.x1, bbox.y1)],
            "width_px": width,
            "height_px": height,
            "dpi": dpi,
            "extraction_method": "caption_anchored_v4",
            # belongs_to_chapter and level2_breakdown are populated later by
            # the Figure Analyst agent; left empty here.
            "belongs_to_chapter": None,
        })

    doc.close()

    index = {
        "source_pdf": str(Path(pdf_path).resolve()),
        "total_captions": len(captions),
        "figures": figures_out,
        "listings": listings_out,
    }

    (out_root / "extraction_index.json").write_text(
        json.dumps(index, indent=2, ensure_ascii=False),
        encoding="utf-8",
    )
    return index


def main() -> None:
    parser = argparse.ArgumentParser(description="Extract figures, tables, and listings from PDFs")
    parser.add_argument("pdf_path", help="Path to PDF file")
    parser.add_argument(
        "-o", "--output",
        default=".",
        help="Output directory (figures/ and listings/ will be created here)",
    )
    parser.add_argument("--dpi", type=int, default=200, help="Render DPI")
    args = parser.parse_args()

    index = extract_all(args.pdf_path, args.output, dpi=args.dpi)
    print(
        f"Extracted {len(index['figures'])} figures/tables and "
        f"{len(index['listings'])} listings from {index['total_captions']} captions."
    )
    for fig in index["figures"]:
        print(f"  [{fig['paper_label']}] p{fig['page']} -> {fig['file']}")
    for lst in index["listings"]:
        print(f"  [{lst['paper_label']}] p{lst['page']} -> {lst['file']}")


if __name__ == "__main__":
    main()
