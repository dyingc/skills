#!/usr/bin/env python3
"""
PDF Figure Extraction via caption-anchored cropping (v5).

Academic papers reliably place figures near a caption that matches
"Figure N" / "Fig. N" / "Table N" / "Listing N". This script:

  1. Scans every page for caption lines using strict block-first-line regex on
     PyMuPDF text blocks. This avoids body-text false positives like
     "Figure 4. The former leads directly to the bug in the binary." which is
     a sentence mentioning Figure 4, not a caption.
  2. For each figure caption, clusters drawings / images / narrow text labels
     around the caption. Instead of pre-deciding a "column" from caption
     width — which misclassifies wide figures whose caption happens to be a
     short line — the crop is computed by:
       (a) bounding the vertical search region by OTHER captions on the
           same page (a neighboring figure's caption cleanly separates
           this figure's content from that figure's content, without any
           manual column guessing);
       (b) anchoring on the rect closest to the caption and horizontally
           aligned with the caption's center (with generous slop so narrow
           captions still find their own full-width figure above);
       (c) iteratively growing the cluster through both y-proximity AND
           x-overlap — so a single-column figure never accretes the
           neighboring column's body text, but a full-page-width figure's
           cluster naturally reaches both edges.
     The resulting cluster bbox is the crop region — no post-hoc column
     clipping, no caption-width heuristic.
  3. For tables whose block contains the entire table + caption text (the
     common IEEE layout where PyMuPDF merges data rows and caption into one
     block), uses the block bbox directly.
  4. Renders the cropped region at the requested DPI to PNG.
  5. Each extraction records a `diagnostics` block with the chosen crop's
     caption-relative metrics (caption x-center vs. page midline, crop x
     extent, aspect ratio) so downstream validation can flag suspicious
     crops without re-reading the PDF.
  6. For listings, extracts the code as plain text to listings/ (code is
     embedded via markdown code fence, not as an image).
  7. Writes an extraction_index.json with caption metadata so that the
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

            # Table special case: data rows then caption inside one block.
            # GUARD: the line immediately preceding the match must end with
            # sentence-terminal punctuation (., !, ?). Body-text paragraphs
            # that happen to wrap on "Table N." do NOT satisfy this — their
            # previous line ends mid-phrase ("... as shown in"). Real
            # in-block captions are preceded by a table's last data row (a
            # period-ending footnote is fine) or by an empty/blank context.
            for i, line in enumerate(lines[1:], start=1):
                ltext = _line_text(line).strip()
                m = TABLE_CAPTION_RE.match(ltext)
                if not m:
                    continue
                prev_text = _line_text(lines[i - 1]).rstrip()
                if not prev_text.endswith((".", "!", "?")):
                    continue
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

# Body-text discriminator: a text block is considered a figure label / legend
# only if its width is below this fraction of the full page width AND its
# height fits within a few lines. A 2-column IEEE page has body-text columns
# at ~37% of page width; a tight filter (0.35) rejects them while still
# accepting long code listings and multi-line figure captions inside figures.
_LABEL_MAX_PAGE_FRACTION = 0.35
# Tables have data rows that commonly span ~70% of page width (a full table
# spans both columns minus margins). Use a much looser width cap for tables,
# but STILL apply the tall-and-wide body-text guard below.
_TABLE_LABEL_MAX_PAGE_FRACTION = 0.75
# Even if a block passes the width threshold (e.g. a half-column code block),
# body paragraphs are tall: more than ~4 lines at 10pt leading ≈ 50pt. Reject
# anything both wide-ish (>25% page width) and tall — that's body text.
_LABEL_BODY_WIDTH_FRACTION = 0.25
_LABEL_BODY_HEIGHT_PT = 50.0

# Horizontal slop for "cluster-overlap" checks. Small enough to NOT bridge the
# typical 2-column gutter (15-20pt) but generous enough to admit arrow
# connectors between adjacent figure parts (usually ≤ 10pt of visual gap).
_X_OVERLAP_SLOP_PT = 10.0
_CAPTION_ALIGN_FRACTION = 0.15
_CAPTION_ALIGN_MIN_PT = 50.0

# Margin added above/below the separator caption so neighbor figures don't
# accidentally bleed into each other by exactly 1pt.
_CAPTION_SEPARATOR_MARGIN_PT = 5.0


def _vertical_search_bounds(
    page_rect: pymupdf.Rect,
    caption: "Caption",
    other_captions: List["Caption"],
    *,
    max_height_pt: float,
    prefer_above: bool,
) -> Tuple[float, float]:
    """
    Compute the [y_far, y_near] search region for content that belongs to
    `caption`. The bound nearest the caption is fixed at the caption edge;
    the far bound is tightened by any OTHER caption on the same page that
    sits between `caption` and the max_height_pt limit. This is what cleanly
    separates neighboring figures on the same page, without any column
    guessing.
    """
    cx0, cy0, cx1, cy1 = caption.bbox

    if prefer_above:
        y_near = cy0
        y_far = max(page_rect.y0 + 2, cy0 - max_height_pt)
        for oc in other_captions:
            _, _, _, ocy1 = oc.bbox
            if ocy1 < cy0:
                y_far = max(y_far, ocy1 + _CAPTION_SEPARATOR_MARGIN_PT)
    else:
        y_near = cy1
        y_far = min(page_rect.y1 - 2, cy1 + max_height_pt)
        for oc in other_captions:
            ocx0, ocy0, _, _ = oc.bbox
            if ocy0 > cy1:
                y_far = min(y_far, ocy0 - _CAPTION_SEPARATOR_MARGIN_PT)

    return y_far, y_near


def _collect_content_candidates(
    page: pymupdf.Page,
    caption: "Caption",
    *,
    y_far: float,
    y_near: float,
    prefer_above: bool,
) -> List[Tuple[float, float, float, float]]:
    """
    Collect drawings, raster images, and narrow text labels within the
    vertical search band. No horizontal (column) filter is applied — the
    cluster's own x-overlap logic will naturally keep single-column figures
    tight and let full-width figures grow.
    """
    page_w = page.rect.x1 - page.rect.x0
    is_table = caption.kind == "table"
    label_max = page_w * (_TABLE_LABEL_MAX_PAGE_FRACTION
                          if is_table else _LABEL_MAX_PAGE_FRACTION)
    cx0, cy0, cx1, cy1 = caption.bbox

    def in_vertical_region(ry0: float, ry1: float) -> bool:
        if prefer_above:
            # Rect's TOP must be strictly above the caption top; the bottom
            # may slightly extend into the caption box by a few points (some
            # figures' outer dashed borders end 1-2pt below caption top).
            return ry0 < cy0 and ry1 < cy1 + 3 and ry1 >= y_far
        return ry1 > cy1 and ry0 > cy0 - 3 and ry0 <= y_far

    content: List[Tuple[float, float, float, float]] = []

    page_rect = page.rect
    for d in page.get_drawings():
        r = d.get("rect")
        if r is None:
            continue
        # Reject noise (dots / tiny artifacts). A horizontal rule line has
        # h=0 but w >> 0.5 — keep those: they anchor a table's vertical
        # extent when the data cells are text-only.
        if r.width < 0.5 and r.height < 0.5:
            continue
        # Reject drawings that extend off the page: these are almost always
        # background layers, crop marks, or rendering artifacts rather than
        # figure content (no paper actually draws outside the trim box).
        if r.x0 < page_rect.x0 - 2 or r.x1 > page_rect.x1 + 2:
            continue
        if r.y0 < page_rect.y0 - 2 or r.y1 > page_rect.y1 + 2:
            continue
        if in_vertical_region(r.y0, r.y1):
            content.append((r.x0, r.y0, r.x1, r.y1))

    try:
        for img in page.get_image_info(hashes=False, xrefs=False):
            b = img.get("bbox")
            if not b:
                continue
            if in_vertical_region(b[1], b[3]):
                content.append(tuple(b))
    except Exception:
        pass

    for b in page.get_text("blocks"):
        if len(b) < 7:
            continue
        bx0, by0, bx1, by1, btext, _, btype = b[:7]
        if btype != 0:
            continue
        if (bx0, by0, bx1, by1) == caption.bbox:
            continue
        btxt = btext.strip()
        if (btxt.startswith("Fig. ")
                or btxt.startswith("Figure ")
                or btxt.startswith("TABLE ")
                or btxt.startswith("Table ")
                or btxt.startswith("Listing ")):
            continue
        width = bx1 - bx0
        height = by1 - by0
        if width > label_max:
            continue
        # Body-text guard: a medium-width block that's also tall is almost
        # certainly a body paragraph that slipped under label_max.
        if (width > page_w * _LABEL_BODY_WIDTH_FRACTION
                and height > _LABEL_BODY_HEIGHT_PT):
            continue
        if in_vertical_region(by0, by1):
            content.append((bx0, by0, bx1, by1))

    return content


def _pick_anchor(
    content: List[Tuple[float, float, float, float]],
    caption: "Caption",
    page_rect: pymupdf.Rect,
    *,
    prefer_above: bool,
) -> Tuple[float, float, float, float]:
    """
    Pick the anchor rect: the candidate closest to the caption (in y) whose
    x-range overlaps the caption's x-center by at least the alignment slop.
    If none qualifies (caption sits over whitespace — uncommon for real
    figures), fall back to the y-nearest candidate.
    """
    cx0, _, cx1, _ = caption.bbox
    cap_cx = (cx0 + cx1) / 2.0
    page_w = page_rect.x1 - page_rect.x0
    slop = max(page_w * _CAPTION_ALIGN_FRACTION, _CAPTION_ALIGN_MIN_PT)
    cap_x_lo = cap_cx - slop
    cap_x_hi = cap_cx + slop

    if prefer_above:
        content.sort(key=lambda r: -r[3])  # largest bottom first
    else:
        content.sort(key=lambda r: r[1])   # smallest top first

    for r in content:
        if r[2] >= cap_x_lo and r[0] <= cap_x_hi:
            return r
    return content[0]


def _grow_cluster(
    content: List[Tuple[float, float, float, float]],
    anchor: Tuple[float, float, float, float],
    *,
    gap_pt: float,
) -> List[Tuple[float, float, float, float]]:
    """
    Iteratively grow the cluster outward from the anchor by (y-proximity,
    x-overlap). This is the key step that lets a full-width figure expand
    horizontally once an anchor is chosen, while a single-column figure
    never accretes cross-column body text.
    """
    cluster = [anchor]
    x0, y0, x1, y1 = anchor

    changed = True
    while changed:
        changed = False
        for r in content:
            if r in cluster:
                continue
            # y-gap: the rect must touch the cluster's y-extent with at
            # most gap_pt of slack in either direction.
            r_y0, r_y1 = r[1], r[3]
            if r_y1 < y0 - gap_pt or r_y0 > y1 + gap_pt:
                continue
            # x-overlap with the cluster (± slop).
            r_x0, r_x1 = r[0], r[2]
            if r_x1 < x0 - _X_OVERLAP_SLOP_PT or r_x0 > x1 + _X_OVERLAP_SLOP_PT:
                continue
            cluster.append(r)
            x0 = min(x0, r_x0)
            y0 = min(y0, r_y0)
            x1 = max(x1, r_x1)
            y1 = max(y1, r_y1)
            changed = True

    return cluster


def crop_figure_region(
    page: pymupdf.Page,
    caption: "Caption",
    *,
    max_height_pt: float = 560.0,
    gap_pt: float = 45.0,
    other_captions: Optional[List["Caption"]] = None,
) -> Optional[pymupdf.Rect]:
    """
    Compute a bounding box for the figure associated with a caption.

    Strategy:
        1. Tables whose block already contains the data rows (block height
           > 30pt) → use the block bbox directly.
        2. Otherwise: bound the vertical search region by the caption on the
           near side and by the nearest OTHER caption (if any) on the far
           side. Collect drawings + images + narrow labels in that band,
           pick an anchor rect aligned with the caption's x-center, and
           grow the cluster iteratively via y-proximity AND x-overlap.
           Return the cluster's tight bounding box.
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

    # ---- Case 2: caption-anchored crop (v5) ----
    prefer_above = caption.kind != "table"
    other_captions = [c for c in (other_captions or []) if c is not caption]

    y_far, y_near = _vertical_search_bounds(
        page_rect, caption, other_captions,
        max_height_pt=max_height_pt, prefer_above=prefer_above,
    )

    content = _collect_content_candidates(
        page, caption,
        y_far=y_far, y_near=y_near, prefer_above=prefer_above,
    )
    if not content:
        return None

    anchor = _pick_anchor(content, caption, page_rect, prefer_above=prefer_above)
    # Tables have tight row spacing (<5pt) and are followed by clear whitespace
    # (>10pt) before body text / section headings. A tighter gap threshold
    # prevents a footnote from bridging into the next section. Figures need
    # a generous gap to tolerate arrow-connector whitespace between boxes.
    effective_gap = 10.0 if caption.kind == "table" else gap_pt
    cluster = _grow_cluster(content, anchor, gap_pt=effective_gap)

    min_x = min(r[0] for r in cluster)
    min_y = min(r[1] for r in cluster)
    max_x = max(r[2] for r in cluster)
    max_y = max(r[3] for r in cluster)

    min_x = max(page_rect.x0 + 2, min_x - 3)
    max_x = min(page_rect.x1 - 2, max_x + 3)
    min_y = max(page_rect.y0 + 2, min_y - 5)
    max_y = min(page_rect.y1 - 2, max_y + 5)

    if prefer_above:
        max_y = min(max_y, cy0 - 2)
    else:
        min_y = max(min_y, cy1 + 2)

    if max_y - min_y < 15 or max_x - min_x < 30:
        return None
    return pymupdf.Rect(min_x, min_y, max_x, max_y)


def _compute_column(
    page_rect: pymupdf.Rect,
    cap_bbox: Tuple[float, float, float, float],
) -> Tuple[float, float]:
    """
    Legacy caption-width column heuristic.

    Kept only for listing extraction (`extract_listing_text`) — which still
    benefits from a coarse left-vs-right column classification to filter
    body blocks. Figure cropping no longer uses this function; use
    `crop_figure_region` instead, which determines horizontal extent from
    content rather than caption width.
    """
    cx0, _, cx1, _ = cap_bbox
    cap_cx = (cx0 + cx1) / 2.0
    pw = page_rect.x1 - page_rect.x0
    mid = (page_rect.x0 + page_rect.x1) / 2.0
    cw = cx1 - cx0

    if cw > pw * 0.6:
        return (page_rect.x0 + 2, page_rect.x1 - 2)
    if cw > pw * 0.3:
        # On a tie (caption centered exactly on page midline) prefer full
        # width — single-column figures always have a caption offset to one
        # side, so centered captions almost always indicate a wide figure.
        if cap_cx < mid - 0.5:
            return (page_rect.x0 + 2, mid - 2)
        if cap_cx > mid + 0.5:
            return (mid + 2, page_rect.x1 - 2)
        return (page_rect.x0 + 2, page_rect.x1 - 2)
    return (
        max(page_rect.x0 + 2, cx0 - 15),
        min(page_rect.x1 - 2, cx1 + 15),
    )


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

    # Group captions by page once so each crop can look at its neighbors on
    # the same page without re-scanning.
    captions_by_page: Dict[int, List[Caption]] = {}
    for cap in captions:
        captions_by_page.setdefault(cap.page, []).append(cap)

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

        other_caps = captions_by_page.get(cap.page, [])
        bbox = crop_figure_region(page, cap, other_captions=other_caps)
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

        page_rect = page.rect
        page_w = page_rect.x1 - page_rect.x0
        cap_cx = (cap.bbox[0] + cap.bbox[2]) / 2.0
        mid = (page_rect.x0 + page_rect.x1) / 2.0
        crop_w = bbox.x1 - bbox.x0
        crop_cx = (bbox.x0 + bbox.x1) / 2.0
        # Coarse crop class lets the validator flag surprising crops (e.g.
        # caption centered on midline but crop labeled half-width). We
        # distinguish between "half-column-aligned wide" and "centered wide"
        # because some paper templates place a table or figure centered
        # between the two columns (spanning ~55% of page width) rather than
        # aligned to a column edge; without this the validator would flag it.
        if crop_w > page_w * 0.6:
            crop_class = "full_width"
        elif crop_w > page_w * 0.3:
            if abs(crop_cx - mid) < page_w * 0.02:
                crop_class = "centered_wide"
            else:
                crop_class = "half_width_right" if crop_cx > mid else "half_width_left"
        else:
            crop_class = "narrow"

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
            "extraction_method": "caption_anchored_v5",
            # belongs_to_chapter and level2_breakdown are populated later by
            # the Figure Analyst agent; left empty here.
            "belongs_to_chapter": None,
            "diagnostics": {
                "page_width_pt": round(page_w, 2),
                "caption_cx_pt": round(cap_cx, 2),
                "page_mid_pt": round(mid, 2),
                "caption_offset_from_mid_pt": round(cap_cx - mid, 2),
                "crop_width_pt": round(crop_w, 2),
                "crop_width_ratio": round(crop_w / page_w, 3) if page_w else None,
                "crop_class": crop_class,
            },
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
