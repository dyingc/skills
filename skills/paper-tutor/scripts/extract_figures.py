#!/usr/bin/env python3
"""
PDF Figure Extraction Script

Extracts images (bitmap and vector graphics) from PDF files.
Handles image deduplication via hashing and size filtering.

Dependencies: pymupdf, Pillow (PIL), imagehash (optional for perceptual hashing)
Install: pip install pymupdf Pillow imagehash
"""

import pymupdf
import io
import hashlib
import argparse
import os
from pathlib import Path
from PIL import Image
from typing import List, Dict, Any, Optional, Tuple


class FigureExtractor:
    """Extract figures from PDF files with deduplication and filtering."""

    def __init__(
        self,
        min_width: int = 100,
        min_height: int = 100,
        min_area: int = 10000,
        output_dir: str = "figures"
    ):
        """
        Initialize the figure extractor.

        Args:
            min_width: Minimum width in pixels
            min_height: Minimum height in pixels
            min_area: Minimum area (width × height) in pixels
            output_dir: Directory to save extracted figures
        """
        self.min_width = min_width
        self.min_height = min_height
        self.min_area = min_area
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)

        # Track hashes for deduplication
        self.seen_hashes = set()

    def compute_image_hash(self, img: Image.Image) -> Dict[str, str]:
        """
        Compute hash for an image.

        Returns dict with 'md5' (exact match) and 'perceptual' (similarity detection).
        """
        # MD5 hash for exact deduplication
        img_bytes = img.tobytes()
        md5_hash = hashlib.md5(img_bytes).hexdigest()

        # Perceptual hash for similarity detection
        # Only if imagehash is available
        try:
            import imagehash
            perceptual_hash = str(imagehash.phash(img))
        except ImportError:
            # Fallback: use average color as simple perceptual hash
            perceptual_hash = self._simple_perceptual_hash(img)

        return {
            "md5": md5_hash,
            "perceptual": perceptual_hash
        }

    def _simple_perceptual_hash(self, img: Image.Image) -> str:
        """Simple fallback for perceptual hashing without imagehash library."""
        # Resize to small thumbnail and hash
        small = img.resize((8, 8), Image.Resampling.LANCZOS)
        return hashlib.md5(small.tobytes()).hexdigest()

    def is_too_small(self, img: Image.Image) -> Tuple[bool, Optional[str]]:
        """Check if image is too small to be useful."""
        width, height = img.size
        area = width * height

        if width < self.min_width or height < self.min_height or area < self.min_area:
            return True, f"Too small ({width}x{height}, area={area})"
        return False, None

    def is_diagram(self, cluster: Dict[str, Any]) -> bool:
        """
        Determine if a drawing cluster is a diagram (not decorative).

        Args:
            cluster: Drawing cluster from page.get_drawings() or page.cluster_drawings()
        """
        rect = cluster["rect"]
        items = cluster.get("items", [])

        # Check 1: Area filter
        area = rect.width * rect.height
        if area < self.min_area:
            return False

        # Check 2: Drawing instruction analysis
        if items:
            # Items format: [(type, ...), ...]
            # Types: 'l'=line, 'c'=curve, 're'=rect, 'Tz'=text, etc.
            line_count = sum(1 for item in items if item[0] in ['l', 'cs'])
            rect_count = sum(1 for item in items if item[0] == 're')

            # Has enough lines and rectangles -> likely a diagram
            if rect_count >= 3 and line_count >= 3:
                return True

        # Check 3: Aspect ratio (wide or tall images are more likely figures)
        aspect_ratio = rect.width / rect.height if rect.height > 0 else 0
        if aspect_ratio > 2 or aspect_ratio < 0.5:
            return True

        return False

    def extract_figures(self, pdf_path: str) -> List[Dict[str, Any]]:
        """
        Extract all figures (bitmap and vector) from a PDF file.

        Returns list of figure metadata dictionaries.
        """
        doc = pymupdf.open(pdf_path)
        figures = []

        for page_num, page in enumerate(doc):
            # 1. Extract bitmap images
            image_list = page.get_images()
            for img_index, img in enumerate(image_list):
                xref = img[0]

                try:
                    base_image = doc.extract_image(xref)
                    img_bytes = base_image["image"]
                    img_pil = Image.open(io.BytesIO(img_bytes))

                    # Size filtering
                    too_small, reason = self.is_too_small(img_pil)
                    if too_small:
                        continue

                    # Compute hash
                    img_hash = self.compute_image_hash(img_pil)

                    # Deduplication
                    if img_hash["md5"] in self.seen_hashes:
                        continue

                    self.seen_hashes.add(img_hash["md5"])

                    # Save image
                    filename = f"fig_{page_num}_{img_index}_{img_hash['md5'][:8]}.png"
                    filepath = self.output_dir / filename
                    img_pil.save(filepath)

                    figures.append({
                        "type": "bitmap",
                        "format": base_image["ext"],
                        "file": str(filepath),
                        "page": page_num,
                        "index": img_index,
                        "xref": xref,
                        "width": img_pil.width,
                        "height": img_pil.height,
                        "area": img_pil.width * img_pil.height,
                        "hash": img_hash
                    })

                except Exception as e:
                    print(f"Warning: Failed to extract image {xref} on page {page_num}: {e}")

            # 2. Extract vector graphics
            try:
                # Try cluster_drawings first (newer PyMuPDF versions)
                # Returns list of pymupdf.Rect objects
                raw_clusters = page.cluster_drawings()
                # Convert Rect objects to dict format for consistent handling
                clusters = []
                for c in raw_clusters:
                    if c is not None:
                        # pymupdf.Rect has x0, y0, x1, y1 attributes
                        clusters.append({
                            "rect": c,
                            "items": []  # No items info from cluster_drawings
                        })
            except AttributeError:
                # Fallback to get_drawings for older versions
                clusters = [{"rect": d["rect"], "items": d.get("items", [])}
                          for d in page.get_drawings()]

            for cluster_idx, cluster in enumerate(clusters):
                rect = cluster["rect"]

                # Ensure rect is a proper Rect object or has width/height attributes
                if hasattr(rect, 'width'):
                    rect_width = rect.width
                    rect_height = rect.height
                else:
                    # Assume it's a tuple or list (x0, y0, x1, y1)
                    rect_width = rect[2] - rect[0]
                    rect_height = rect[3] - rect[1]

                # Size filtering
                if rect_width < self.min_width or rect_height < self.min_height:
                    continue

                # Check if it's a diagram
                if not self.is_diagram(cluster):
                    continue

                try:
                    # Render vector graphics to bitmap
                    pix = page.get_pixmap(clip=rect)
                    img_data = pix.tobytes("png")
                    img_pil = Image.open(io.BytesIO(img_data))

                    # Compute hash
                    img_hash = self.compute_image_hash(img_pil)

                    # Deduplication
                    if img_hash["md5"] in self.seen_hashes:
                        continue

                    self.seen_hashes.add(img_hash["md5"])

                    # Save image
                    filename = f"vector_{page_num}_{cluster_idx}_{img_hash['md5'][:8]}.png"
                    filepath = self.output_dir / filename
                    img_pil.save(filepath)

                    figures.append({
                        "type": "vector",
                        "format": "rendered",
                        "file": str(filepath),
                        "page": page_num,
                        "cluster_index": cluster_idx,
                        "width": int(rect.width),
                        "height": int(rect.height),
                        "area": int(rect.width * rect.height),
                        "bbox": {
                            "x0": rect.x0,
                            "y0": rect.y0,
                            "x1": rect.x1,
                            "y1": rect.y1
                        },
                        "hash": img_hash
                    })

                except Exception as e:
                    print(f"Warning: Failed to extract vector graphic on page {page_num}: {e}")

        doc.close()
        return figures


def main():
    """CLI entry point."""
    parser = argparse.ArgumentParser(description="Extract figures from PDF files")
    parser.add_argument("pdf_file", help="Path to PDF file")
    parser.add_argument("-o", "--output", default="figures", help="Output directory for figures")
    parser.add_argument("--min-width", type=int, default=100, help="Minimum image width")
    parser.add_argument("--min-height", type=int, default=100, help="Minimum image height")
    parser.add_argument("--min-area", type=int, default=10000, help="Minimum image area")

    args = parser.parse_args()

    extractor = FigureExtractor(
        min_width=args.min_width,
        min_height=args.min_height,
        min_area=args.min_area,
        output_dir=args.output
    )

    figures = extractor.extract_figures(args.pdf_file)

    print(f"Extracted {len(figures)} figures to {args.output}/")
    for fig in figures:
        print(f"  - {fig['type']}: {fig['file']} ({fig['width']}x{fig['height']})")


if __name__ == "__main__":
    main()
