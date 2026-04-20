#!/usr/bin/env python3
"""
Paper Tutor Execution Validator

Validates that the Paper Tutor workflow was executed correctly by checking:
1. Figure analysis integrity
2. Chapter review approval
3. Workflow consistency across metadata/shared memory/files/final explanation
4. Chapter coverage floor (minimum content density)
"""

from __future__ import annotations

import json
import re
import sys
from pathlib import Path
from datetime import datetime
from typing import Tuple, List, Dict, Any, Optional


MIN_CHAPTER_CONTENT_UNITS = 180
MIN_CHAPTER_COVERAGE_RATIO = 0.35
MIN_FIGURE_TEACHING_UNITS = 150

# Regex: markdown image reference ![alt](path)
MD_IMAGE_RE = re.compile(r"!\[(?P<alt>[^\]]*)\]\((?P<path>[^)]+)\)")

# Regex: numbered chapter heading (H1 or H2) used to segment chapter bodies inside
# the merged paper_explanation.md.
NUMBERED_CHAPTER_HEADING_RE = re.compile(
    r"^(#{1,3})\s+第[一二三四五六七八九十百]+章",
    flags=re.MULTILINE,
)

# Regex: level-3 or level-4 markdown heading (### or ####). We match the heading
# text on the same line so we can check whether it names a figure/table/listing.
HEADING_LEVEL_3_OR_4_RE = re.compile(
    r"^(#{3,4})\s+(.+?)\s*$",
    flags=re.MULTILINE,
)

# Regex: forbidden figure-centric tokens inside a concept heading. If any of these
# appear in a ###/#### heading, it means the author turned the heading into a
# figure name instead of a proposition. This is the most common failure mode of
# the multi-modal chapter agents.
FORBIDDEN_HEADING_TOKENS_RE = re.compile(
    r"""(
        Figure\s*\d+                             # Figure 1, Figure 10
        | Fig\.\s*\d+                             # Fig. 1
        | Table\s+[IVXLCDM]+\b                    # Table I, Table IX (roman)
        | Table\s+\d+                             # Table 1, Table 10
        | Listing\s*\d+                           # Listing 1, Listing 10
        | 图\s*[0-9]+                             # 图 1, 图10
        | 图\s*[一二三四五六七八九十]+              # 图一, 图五
        | 表\s*[IVXLCDM]+\b                       # 表 I, 表 II
        | 表\s*\d+                                # 表 1
        | 表\s*[一二三四五六七八九十]+              # 表一
        | 清单\s*\d+                              # 清单 7
        | 清单\s*[一二三四五六七八九十]+            # 清单七
        | Venn\s*图                               # Venn 图 / Venn图
    )""",
    flags=re.IGNORECASE | re.VERBOSE,
)

# Structural H3 headings that are part of the Paper Tutor template and should NOT
# be checked against the concept-first rule. These are section dividers, not
# concept headings. Matching is via substring on the heading text.
STRUCTURAL_HEADING_SUBSTRINGS = (
    "前置知识",
    "本章核心",
    "核心概念",
    "本章概览",
    "章节概览",
    "外部资源",
    "术语表",
    "概念归属",
    "TL;DR",
    "附录",
)

# Regex: mermaid fenced code block (captures block contents)
MERMAID_BLOCK_RE = re.compile(
    r"```mermaid\s*\n(.*?)\n[ \t]*```",
    flags=re.DOTALL,
)

# Regex: single-uppercase-letter node definition inside a mermaid block.
# Matches patterns like `A[label]`, `B(label)`, `C{label}`, `D((label))`, `E>label]`
# where the identifier is exactly one uppercase Latin letter. These are the
# highest-risk IDs for leaking into prose as pseudo-references, because the
# rendered Mermaid image never shows the ID — readers only see the label.
# Multi-char IDs like `Comp1`, `StartNode`, `B1`, `C2` are too unlikely to
# appear as standalone prose references, so we skip them.
MERMAID_SINGLE_LETTER_NODE_RE = re.compile(
    r"(?<![A-Za-z0-9_])([A-Z])\s*[\[\(\{>]"
)

# Regex: standalone single uppercase letter in prose. The lookbehind and
# lookahead guard against matches inside words (e.g. the `A` in `AFL`) and
# against matches where the letter is glued to a digit (e.g. `X86`, `P2P`).
# Chinese punctuation/characters on either side are fine — they mark the
# letter as a standalone token, exactly the kind of reference we want to catch.
PROSE_STANDALONE_UPPERCASE_RE = re.compile(
    r"(?<![A-Za-z0-9_])([A-Z])(?![A-Za-z0-9_])"
)

# Mermaid reserved keywords that must never be treated as node IDs even if they
# happen to start with an uppercase letter. Kept conservative — only single-
# letter reserved words matter for our single-letter node ID check.
# (None today; keep the set for forward-compat when we widen the ID check.)
MERMAID_KEYWORDS_SINGLE_LETTER: frozenset = frozenset()

# Number of lines AFTER the closing Mermaid fence to scan for prose leaks.
# The window is cut short by the next heading or the next code fence, whichever
# comes first — so 15 lines is an upper bound, not a requirement.
MERMAID_LEAK_WINDOW_LINES = 15


def load_json(path: Path) -> Dict[str, Any]:
    """Load JSON file."""
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


def estimate_content_units(text: str) -> int:
    """
    Estimate multilingual content size.

    We use a robust proxy that works for Chinese and English:
    content_units = chinese_chars + english_words
    """
    chinese_chars = len(re.findall(r"[\u4e00-\u9fff]", text))
    english_words = len(re.findall(r"[A-Za-z]+", text))
    return chinese_chars + english_words


def chapter_file_from_id(output_dir: Path, chapter_id: str) -> Optional[Path]:
    """Map chapter_id like 'ch3' to chapters/chapter_03_output.md."""
    match = re.fullmatch(r"ch(\d+)", chapter_id or "")
    if not match:
        return None
    idx = int(match.group(1))
    return output_dir / "chapters" / f"chapter_{idx:02d}_output.md"


def iter_markdown_images(text: str):
    """Yield (match_object, path_string) for each markdown image reference."""
    for match in MD_IMAGE_RE.finditer(text):
        yield match, match.group("path").strip()


def classify_image_path(path: str) -> str:
    """Classify an image path: 'ok', 'parent_relative', 'absolute', 'url', 'bare', 'other'."""
    if path.startswith("../"):
        return "parent_relative"
    if path.startswith("/"):
        return "absolute"
    if path.startswith("http://") or path.startswith("https://"):
        return "url"
    if path.startswith("figures/"):
        return "ok"
    if "/" not in path:
        return "bare"
    return "other"


def teaching_paragraph_units_after(text: str, img_match: re.Match) -> int:
    """
    Count content units in the teaching paragraph that follows an embedded figure.

    The window starts immediately after the image line and extends until the next
    embedded image, the next H2/H3 heading, or at most ~40 lines later — whichever
    comes first. Content is measured in chinese_chars + english_words.
    """
    img_end = img_match.end()
    tail = text[img_end:]

    # Skip the current line (the image line itself)
    newline_pos = tail.find("\n")
    if newline_pos >= 0:
        tail = tail[newline_pos + 1:]

    # Truncate at the next image or next h2/h3 heading, whichever comes first.
    cutoff = len(tail)
    next_image = MD_IMAGE_RE.search(tail)
    if next_image:
        cutoff = min(cutoff, next_image.start())
    next_heading = re.search(r"^#{1,4}\s", tail, flags=re.MULTILINE)
    if next_heading:
        cutoff = min(cutoff, next_heading.start())

    # Also cap at ~40 lines to avoid counting entire chapter tail as "teaching"
    lines = tail[:cutoff].splitlines()
    if len(lines) > 40:
        lines = lines[:40]
    window = "\n".join(lines)
    return estimate_content_units(window)


def validate_figure_analysis(metadata: Dict[str, Any]) -> Tuple[bool, List[str]]:
    """
    Validate that figure analysis was performed by Figure Analyst.

    Key checks:
    1. If level1_summary exists, analyzed_by must be "figure_analyst_agent"
    2. analyzed_at timestamp must exist
    3. analysis_method must be specified
    """
    errors: List[str] = []

    image_analysis = metadata.get("image_analysis", {})
    figures = metadata.get("figures", [])

    # If no figures, check if image analysis was marked as unavailable
    if not figures:
        if image_analysis.get("status") != "unavailable":
            errors.append("No figures found but image_analysis.status is not 'unavailable'")
        return len(errors) == 0, errors

    # If figures exist, validate each one
    for fig in figures:
        fig_file = fig.get("file", "unknown")

        # If level1_summary exists, must have analyst signature
        if fig.get("level1_summary"):
            if fig.get("analyzed_by") != "figure_analyst_agent":
                errors.append(
                    f"Figure '{fig_file}' has level1_summary but analyzed_by is "
                    f"'{fig.get('analyzed_by')}' instead of 'figure_analyst_agent'. "
                    f"This indicates the figure was NOT analyzed by Figure Analyst."
                )

            if not fig.get("analyzed_at"):
                errors.append(f"Figure '{fig_file}' is missing analyzed_at timestamp")

            if not fig.get("analysis_method"):
                errors.append(f"Figure '{fig_file}' is missing analysis_method")

            # belongs_to_chapter is required so multimodal validator can enforce
            # per-chapter embedding.
            if not fig.get("belongs_to_chapter"):
                errors.append(
                    f"Figure '{fig_file}' is missing 'belongs_to_chapter'. "
                    f"Figure Analyst must assign every figure to a chapter id "
                    f"(e.g. 'ch2') so chapter agents know which figures to embed."
                )

            # level2_breakdown is required for the chapter agent's teaching paragraph.
            l2 = fig.get("level2_breakdown") or {}
            required_l2 = (
                "what_to_look_at",
                "axes_or_structure",
                "key_observations",
                "teaching_hook",
            )
            missing_l2 = [k for k in required_l2 if not l2.get(k)]
            if missing_l2:
                errors.append(
                    f"Figure '{fig_file}' is missing level2_breakdown sub-fields: "
                    f"{missing_l2}. All four ({list(required_l2)}) are required so "
                    f"chapter agents can write a complete teaching paragraph."
                )

    return len(errors) == 0, errors


# Visual-sanity thresholds. These surface obvious rendering failures (an empty
# crop, a near-blank crop, a crop whose diagnostics contradict its labelled
# class) BEFORE chapter agents embed them. They don't catch semantic errors —
# a pie chart with the wrong labels still renders normally.
_MIN_FIG_PIXELS_WIDTH = 80
_MIN_FIG_PIXELS_HEIGHT = 60
# ≥98% white is essentially blank paper: the crop landed on whitespace.
_MAX_WHITE_PIXEL_RATIO = 0.98
# crop_class → expected crop_width_ratio window (from extract_figures.py v5
# diagnostics). A "full_width" crop whose ratio is 0.12 is a bug.
_CROP_CLASS_RATIO_WINDOW: Dict[str, Tuple[float, float]] = {
    "full_width": (0.55, 1.01),
    "centered_wide": (0.35, 0.70),
    "half_width_left": (0.28, 0.62),
    "half_width_right": (0.28, 0.62),
    "narrow": (0.0, 0.35),
}


def _image_white_ratio(path: Path) -> Optional[float]:
    """Return the fraction of near-white pixels in an image (0..1), or None
    if the file can't be opened with PIL."""
    try:
        from PIL import Image  # type: ignore
    except ImportError:
        return None
    try:
        with Image.open(path) as img:
            gray = img.convert("L")
            # Downsample for speed — a blank crop is blank at any resolution.
            gray.thumbnail((256, 256))
            raw = gray.tobytes()
    except Exception:
        return None
    if not raw:
        return 0.0
    white_count = sum(1 for b in raw if b >= 240)
    return white_count / len(raw)


def validate_figure_rendering(output_dir: Path) -> Tuple[bool, List[str], Dict[str, Any]]:
    """
    Visual sanity check on extracted figure/table PNGs referenced by
    extraction_index.json. Catches:
      (a) file missing on disk despite being indexed
      (b) width × height below a usable minimum
      (c) image is essentially a blank page (>98% white pixels)
      (d) crop_class in diagnostics disagrees with measured crop_width_ratio

    These are the failure modes the v5 extractor rewrite was designed to
    eliminate, so validating them here catches regressions early.

    Returns (passed, errors, stats). Passed when errors list is empty.
    """
    errors: List[str] = []
    stats: Dict[str, Any] = {
        "index_present": False,
        "figures_total": 0,
        "figures_checked": 0,
        "figures_blank": 0,
        "figures_mismatched_class": 0,
        "figures_missing_file": 0,
        "figures_too_small": 0,
    }

    index_path = output_dir / "extraction_index.json"
    if not index_path.exists():
        # Skip: extraction_index.json is optional for the overall validator.
        return True, errors, stats
    stats["index_present"] = True

    try:
        index = json.loads(index_path.read_text(encoding="utf-8"))
    except Exception as exc:
        errors.append(f"extraction_index.json is not valid JSON: {exc}")
        return False, errors, stats

    figures = index.get("figures") or []
    stats["figures_total"] = len(figures)

    for fig in figures:
        rel = fig.get("file")
        label = fig.get("paper_label") or rel or "unknown"
        if not rel:
            continue
        fpath = output_dir / rel
        if not fpath.exists():
            errors.append(f"{label}: listed in extraction_index.json but file not found at {rel}")
            stats["figures_missing_file"] += 1
            continue

        stats["figures_checked"] += 1

        width_px = fig.get("width_px")
        height_px = fig.get("height_px")
        if isinstance(width_px, int) and isinstance(height_px, int):
            if width_px < _MIN_FIG_PIXELS_WIDTH or height_px < _MIN_FIG_PIXELS_HEIGHT:
                errors.append(
                    f"{label}: rendered at {width_px}x{height_px}px, below "
                    f"minimum {_MIN_FIG_PIXELS_WIDTH}x{_MIN_FIG_PIXELS_HEIGHT}. "
                    f"Crop likely missed the figure content."
                )
                stats["figures_too_small"] += 1

        white_ratio = _image_white_ratio(fpath)
        if white_ratio is not None and white_ratio >= _MAX_WHITE_PIXEL_RATIO:
            errors.append(
                f"{label}: image is {white_ratio:.1%} blank/white pixels. "
                f"Crop landed on whitespace — caption anchoring likely picked "
                f"the wrong anchor."
            )
            stats["figures_blank"] += 1

        diagnostics = fig.get("diagnostics") or {}
        crop_class = diagnostics.get("crop_class")
        crop_ratio = diagnostics.get("crop_width_ratio")
        if crop_class in _CROP_CLASS_RATIO_WINDOW and isinstance(crop_ratio, (int, float)):
            lo, hi = _CROP_CLASS_RATIO_WINDOW[crop_class]
            if not (lo <= crop_ratio <= hi):
                errors.append(
                    f"{label}: crop_class='{crop_class}' but crop_width_ratio="
                    f"{crop_ratio:.2f} falls outside expected window [{lo}, {hi}]. "
                    f"Either class label or crop geometry is wrong."
                )
                stats["figures_mismatched_class"] += 1

        # A caption centered on the page midline (±5pt) almost always sits
        # over a full-width figure. A half-width crop with a centered caption
        # was the exact failure mode behind the Figure 2 bug — guard against
        # its return.
        offset = diagnostics.get("caption_offset_from_mid_pt")
        if (isinstance(offset, (int, float))
                and abs(offset) < 5.0
                and crop_class in ("half_width_left", "half_width_right")):
            errors.append(
                f"{label}: caption is centered on the page (offset={offset:+.1f}pt) "
                f"but crop_class='{crop_class}'. A centered caption typically "
                f"implies a full-width figure — verify the crop didn't clip "
                f"half the figure."
            )
            stats["figures_mismatched_class"] += 1

    return len(errors) == 0, errors, stats


def validate_chapter_reviews(shared_memory: Dict[str, Any]) -> Tuple[bool, List[str]]:
    """
    Validate that all chapters were reviewed and approved by Editor-in-Chief.

    Key checks:
    1. Each chapter must have review_score >= 4.0
    2. Each chapter must have status "approved"
    3. reviewer must be "editor_in_chief"
    """
    errors: List[str] = []

    chapter_summaries = shared_memory.get("chapter_summaries", [])

    if not chapter_summaries:
        errors.append("shared_memory.chapter_summaries is empty")
        return False, errors

    for chapter in chapter_summaries:
        chapter_id = chapter.get("chapter_id", "unknown")
        chapter_title = chapter.get("title", "unknown")

        # Check review status
        status = chapter.get("status")
        if status != "approved":
            errors.append(
                f"Chapter '{chapter_id}' ({chapter_title}) status is '{status}', not 'approved'"
            )

        # Check review score (None means not yet reviewed → fail)
        review_score = chapter.get("review_score")
        if review_score is None or review_score < 4.0:
            errors.append(
                f"Chapter '{chapter_id}' ({chapter_title}) review_score is {review_score}, "
                f"must be >= 4.0"
            )

        # Check reviewer
        reviewer = chapter.get("reviewer")
        if reviewer != "editor_in_chief":
            errors.append(
                f"Chapter '{chapter_id}' ({chapter_title}) reviewer is '{reviewer}', "
                f"must be 'editor_in_chief'"
            )

    return len(errors) == 0, errors


def validate_required_files(output_dir: Path) -> Tuple[bool, List[str]]:
    """Validate that all required output files exist."""
    errors: List[str] = []

    required_files = [
        "paper_explanation.md",
        "paper_metadata.json",
        "shared_memory.json",
    ]

    for file_name in required_files:
        file_path = output_dir / file_name
        if not file_path.exists():
            errors.append(f"Required file '{file_name}' does not exist")

    return len(errors) == 0, errors


def validate_schema_alignment(
    metadata: Dict[str, Any],
    shared_memory: Dict[str, Any],
) -> Tuple[bool, List[str]]:
    """
    Validate chapter schema consistency across metadata and shared memory.
    """
    errors: List[str] = []

    metadata_chapters = metadata.get("chapters", [])
    shared_chapters = shared_memory.get("chapter_summaries", [])

    if len(metadata_chapters) != len(shared_chapters):
        errors.append(
            "Chapter count mismatch: "
            f"paper_metadata has {len(metadata_chapters)}, "
            f"shared_memory has {len(shared_chapters)}"
        )

    metadata_ids = {c.get("id") for c in metadata_chapters if c.get("id")}
    shared_ids = {c.get("chapter_id") for c in shared_chapters if c.get("chapter_id")}

    if metadata_ids != shared_ids:
        missing_in_shared = sorted(metadata_ids - shared_ids)
        missing_in_metadata = sorted(shared_ids - metadata_ids)
        if missing_in_shared:
            errors.append(
                f"Chapter ids missing in shared_memory.chapter_summaries: {missing_in_shared}"
            )
        if missing_in_metadata:
            errors.append(
                f"Chapter ids missing in paper_metadata.chapters: {missing_in_metadata}"
            )

    return len(errors) == 0, errors


def validate_chapter_outputs(
    output_dir: Path,
    shared_memory: Dict[str, Any],
) -> Tuple[bool, List[str], List[Dict[str, Any]]]:
    """
    Validate chapter output files exist and meet content floor.

    Returns:
        (passed, errors, stats)
    """
    errors: List[str] = []
    stats: List[Dict[str, Any]] = []

    for chapter in shared_memory.get("chapter_summaries", []):
        chapter_id = chapter.get("chapter_id", "unknown")
        chapter_title = chapter.get("title", "unknown")
        target_words = chapter.get("word_count_target")

        chapter_file = chapter_file_from_id(output_dir, chapter_id)
        if chapter_file is None:
            errors.append(
                f"Chapter id '{chapter_id}' is not in expected format 'chN'"
            )
            continue

        if not chapter_file.exists():
            errors.append(
                f"Chapter output file missing for '{chapter_id}' ({chapter_title}): {chapter_file.name}"
            )
            continue

        text = chapter_file.read_text(encoding="utf-8")
        units = estimate_content_units(text)

        expected_min = MIN_CHAPTER_CONTENT_UNITS
        if isinstance(target_words, (int, float)) and target_words > 0:
            expected_min = max(expected_min, int(target_words * MIN_CHAPTER_COVERAGE_RATIO))

        if units < expected_min:
            errors.append(
                f"Chapter '{chapter_id}' ({chapter_file.name}) content too short: "
                f"{units} units < required {expected_min} "
                f"(target={target_words}, ratio={MIN_CHAPTER_COVERAGE_RATIO})"
            )

        # Soft structure check: require at least one H2/H3-level marker.
        if "###" not in text and "##" not in text:
            errors.append(
                f"Chapter '{chapter_id}' ({chapter_file.name}) lacks section structure markers (##/###)"
            )

        stats.append(
            {
                "chapter_id": chapter_id,
                "file": chapter_file.name,
                "target_words": target_words,
                "content_units": units,
                "required_min_units": expected_min,
            }
        )

    return len(errors) == 0, errors, stats


def validate_explanation_content(
    output_dir: Path,
    metadata: Dict[str, Any],
    shared_memory: Dict[str, Any],
) -> Tuple[bool, List[str], Dict[str, Any]]:
    """
    Validate that paper_explanation.md has correct structure.

    Key checks:
    1. Numbered chapter count in final explanation must match approved chapters
    2. Only H2 headings are expected (H1 means merge forgot to demote)

    Figure rendering is validated separately in validate_multimodal_content.
    """
    errors: List[str] = []

    explanation_path = output_dir / "paper_explanation.md"
    if not explanation_path.exists():
        return False, ["paper_explanation.md does not exist"], {}

    explanation_content = explanation_path.read_text(encoding="utf-8")

    # Count H2 numbered chapters (the expected form after merge-time demotion).
    h2_chapter_count = len(re.findall(
        r"^##\s+第[一二三四五六七八九十百]+章",
        explanation_content,
        flags=re.MULTILINE,
    ))
    # Count raw H1 numbered chapters — if > 0 the merge step forgot to demote.
    h1_chapter_count = len(re.findall(
        r"^#\s+第[一二三四五六七八九十百]+章",
        explanation_content,
        flags=re.MULTILINE,
    ))

    if h1_chapter_count > 0:
        errors.append(
            f"Final explanation contains {h1_chapter_count} H1 numbered chapter headings "
            f"(`# 第X章`). Merge step must demote these to H2 (`## 第X章`) so the "
            f"document has a single H1 title."
        )

    expected_chapter_count = len(shared_memory.get("chapter_summaries", []))

    if h2_chapter_count != expected_chapter_count:
        errors.append(
            "Final explanation numbered chapter count mismatch: "
            f"found {h2_chapter_count} H2 numbered chapters, "
            f"expected {expected_chapter_count} "
            "(must match approved chapters in shared_memory)"
        )

    stats = {
        "final_numbered_chapters": h2_chapter_count,
        "h1_numbered_chapters": h1_chapter_count,
        "expected_numbered_chapters": expected_chapter_count,
    }

    return len(errors) == 0, errors, stats


def validate_multimodal_content(
    output_dir: Path,
    metadata: Dict[str, Any],
    shared_memory: Dict[str, Any],
) -> Tuple[bool, List[str], List[str], Dict[str, Any]]:
    """
    Validate that figures are actually rendered via markdown image syntax and
    surrounded by sufficient teaching text.

    Hard checks (all must pass):
    1. Every figure with `belongs_to_chapter == ch_id` must be embedded with
       `![...](figures/<filename>)` in chapter_{XX}_output.md
    2. Every figure in metadata must be embedded with `![...](figures/<filename>)`
       in paper_explanation.md
    3. No image path may use `../figures/`, absolute path, or http(s):// URL in any
       chapter file or the final explanation
    4. Each embedded figure must be followed by ≥150 content units of teaching text
       before the next image, next heading, or 40 lines later
    5. If a figure has `figure_type == "listing"`, the chapter file must contain at
       least one fenced code block (``` ``` ``` ```)

    Returns (passed, errors, warnings, stats).
    """
    errors: List[str] = []
    warnings: List[str] = []
    stats: Dict[str, Any] = {}

    figures = metadata.get("figures", [])
    image_status = metadata.get("image_analysis", {}).get("status", "unknown")

    # When figure analysis was not available, skip hard multimodal checks.
    if image_status != "available":
        stats["skipped_reason"] = (
            f"image_analysis.status is '{image_status}' — multimodal checks skipped"
        )
        return True, [], [], stats

    if not figures:
        stats["skipped_reason"] = "No figures in metadata to validate"
        return True, [], [], stats

    # Build chapter assignment map from belongs_to_chapter field.
    # validate_figure_analysis already hard-fails on missing belongs_to_chapter, so
    # we just skip orphans silently here and let the figure_analysis check report.
    figures_by_chapter: Dict[str, List[Dict[str, Any]]] = {}
    unassigned_figures: List[str] = []
    for fig in figures:
        file_name = fig.get("file", "")
        if not file_name:
            continue
        ch_id = fig.get("belongs_to_chapter")
        if ch_id:
            figures_by_chapter.setdefault(ch_id, []).append(fig)
        else:
            unassigned_figures.append(file_name)

    # === Per-chapter validation ===
    per_chapter_stats: List[Dict[str, Any]] = []
    for chapter in shared_memory.get("chapter_summaries", []):
        ch_id = chapter.get("chapter_id", "")
        ch_file = chapter_file_from_id(output_dir, ch_id)
        if ch_file is None or not ch_file.exists():
            continue

        ch_text = ch_file.read_text(encoding="utf-8")
        ch_label = f"Chapter '{ch_id}' ({ch_file.name})"

        embedded_images = list(iter_markdown_images(ch_text))
        embedded_figure_files: set = set()
        for m, path in embedded_images:
            kind = classify_image_path(path)
            if kind == "parent_relative":
                errors.append(
                    f"{ch_label}: image path uses '../' prefix: {path!r}. "
                    f"Chapter files must use 'figures/<filename>' (the merge step "
                    f"copies chapter bodies into the root, so '../figures/' breaks)."
                )
            elif kind == "absolute":
                errors.append(
                    f"{ch_label}: image path is absolute: {path!r}. "
                    f"Must use 'figures/<filename>'."
                )
            elif kind == "url":
                errors.append(
                    f"{ch_label}: image path is a URL: {path!r}. "
                    f"Must use the local 'figures/<filename>'."
                )
            elif kind == "ok":
                embedded_figure_files.add(path[len("figures/"):])
            elif kind == "bare":
                warnings.append(
                    f"{ch_label}: image path {path!r} is a bare filename. "
                    f"Prefer 'figures/{path}' for clarity."
                )
                embedded_figure_files.add(path)

        # Split expected entries into image figures and listing figures.
        # Listings are validated as fenced code blocks, not markdown images.
        expected = figures_by_chapter.get(ch_id, [])
        expected_image_figures = [
            f for f in expected if f.get("figure_type") != "listing"
        ]
        expected_listing_figures = [
            f for f in expected if f.get("figure_type") == "listing"
        ]

        # 1. Image figures: must be embedded via ![...](figures/<filename>)
        missing_embeds: List[str] = []
        for fig in expected_image_figures:
            fig_file = fig.get("file", "")
            if fig_file and fig_file not in embedded_figure_files:
                missing_embeds.append(fig_file)
                errors.append(
                    f"{ch_label}: figure '{fig_file}' is assigned to this chapter "
                    f"(belongs_to_chapter == {ch_id}) but is NOT embedded via "
                    f"![...](figures/{fig_file}) markdown image syntax. Listing the "
                    f"filename in an index table or mentioning 'Figure N' in prose "
                    f"does NOT count as rendering."
                )

        # Check teaching paragraph length after each embedded image.
        for m, path in embedded_images:
            if classify_image_path(path) != "ok":
                continue
            units = teaching_paragraph_units_after(ch_text, m)
            if units < MIN_FIGURE_TEACHING_UNITS:
                errors.append(
                    f"{ch_label}: teaching paragraph after image '{path}' is too "
                    f"short ({units} content units, need ≥{MIN_FIGURE_TEACHING_UNITS}). "
                    f"Each embedded figure must be followed by a ≥150 char Chinese "
                    f"teaching paragraph covering level2_breakdown."
                )

        # 2. Listing figures: verify the chapter contains a fenced code block
        # for each assigned listing. We count fenced code blocks (opening fences)
        # and require count >= number of assigned listings.
        fenced_block_count = len(re.findall(r"^```[a-zA-Z0-9_-]+", ch_text, re.MULTILINE))
        missing_listings: List[str] = []
        if expected_listing_figures:
            if fenced_block_count < len(expected_listing_figures):
                for lf in expected_listing_figures:
                    lf_file = lf.get("file", "")
                    missing_listings.append(lf_file)
                errors.append(
                    f"{ch_label}: chapter has {len(expected_listing_figures)} "
                    f"listing figure(s) assigned but only {fenced_block_count} "
                    f"fenced code block(s) found. Each listing must be embedded "
                    f"as a ``` ```<lang> ``` ``` fenced code block with a language "
                    f"tag (c/xml/bash/python/...). Expected listings: "
                    f"{[lf.get('file') for lf in expected_listing_figures]}"
                )

        per_chapter_stats.append({
            "chapter_id": ch_id,
            "file": ch_file.name,
            "expected_figures": len(expected_image_figures),
            "embedded_assigned_figures": len(expected_image_figures) - len(missing_embeds),
            "expected_listings": len(expected_listing_figures),
            "fenced_code_blocks": fenced_block_count,
            "total_image_references": len(embedded_images),
            "missing": missing_embeds,
            "missing_listings": missing_listings,
        })

    stats["chapters"] = per_chapter_stats

    # === paper_explanation.md validation ===
    explanation_path = output_dir / "paper_explanation.md"
    if explanation_path.exists():
        exp_text = explanation_path.read_text(encoding="utf-8")
        exp_embedded = list(iter_markdown_images(exp_text))
        exp_embedded_files: set = set()
        for m, path in exp_embedded:
            kind = classify_image_path(path)
            if kind == "parent_relative":
                errors.append(
                    f"paper_explanation.md: image path uses '../' prefix: {path!r}. "
                    f"Merge step must rewrite '../figures/' → 'figures/' when "
                    f"copying chapter bodies into the root document."
                )
            elif kind == "absolute":
                errors.append(
                    f"paper_explanation.md: image path is absolute: {path!r}. "
                    f"Must use 'figures/<filename>'."
                )
            elif kind == "url":
                errors.append(
                    f"paper_explanation.md: image path is a URL: {path!r}. "
                    f"Must use the local 'figures/<filename>'."
                )
            elif kind == "ok":
                exp_embedded_files.add(path[len("figures/"):])
            elif kind == "bare":
                exp_embedded_files.add(path)

        # Non-listing figures must be embedded as markdown images.
        for fig in figures:
            if fig.get("figure_type") == "listing":
                continue
            fig_file = fig.get("file", "")
            if fig_file and fig_file not in exp_embedded_files:
                errors.append(
                    f"paper_explanation.md: figure '{fig_file}' is in metadata but "
                    f"NOT embedded via ![...](figures/{fig_file}) markdown image "
                    f"syntax. Mentioning the filename in an index table is not "
                    f"enough — the figure must be rendered at its point of "
                    f"discussion."
                )

        # Listing figures must each correspond to a fenced code block in the
        # merged explanation. We require the total fenced block count to be
        # at least the number of listing entries in metadata.
        expected_listing_count = sum(
            1 for f in figures if f.get("figure_type") == "listing"
        )
        exp_fenced_count = len(re.findall(r"^```[a-zA-Z0-9_-]+", exp_text, re.MULTILINE))
        if exp_fenced_count < expected_listing_count:
            errors.append(
                f"paper_explanation.md: expected at least "
                f"{expected_listing_count} fenced code blocks (one per listing) "
                f"but found only {exp_fenced_count}. Every listing figure in "
                f"metadata must be embedded as a ``` ```<lang> ``` ``` block."
            )

        stats["explanation_rendered_figures"] = len(exp_embedded_files)
        stats["explanation_total_image_refs"] = len(exp_embedded)
        stats["explanation_fenced_code_blocks"] = exp_fenced_count
        stats["explanation_expected_listings"] = expected_listing_count

    stats["total_figures"] = len(figures)
    stats["assigned_figures"] = sum(len(v) for v in figures_by_chapter.values())
    stats["unassigned_figures"] = len(unassigned_figures)

    return len(errors) == 0, errors, warnings, stats


def validate_concept_first_headings(
    output_dir: Path,
    shared_memory: Dict[str, Any],
) -> Tuple[bool, List[str], Dict[str, Any]]:
    """
    Validate that no chapter uses figure/table/listing names as ###/#### headings.

    This is the concept-first rule: each `####` sub-section must be a proposition
    ("how does X work?", "why does Y fail?"), NOT a figure walkthrough
    ("Figure 3", "Listing 7", "Venn 图"). Figures/tables/listings are supporting
    evidence woven into proposition narratives, not top-level subjects.

    Structural headings (前置知识, 本章核心, 外部资源, ...) are allowed — they are
    part of the Paper Tutor template and do not carry proposition semantics.
    """
    errors: List[str] = []
    offenders_by_chapter: Dict[str, List[Dict[str, str]]] = {}
    total_headings_scanned = 0
    total_offenders = 0

    for chapter in shared_memory.get("chapter_summaries", []):
        ch_id = chapter.get("chapter_id", "")
        ch_file = chapter_file_from_id(output_dir, ch_id)
        if ch_file is None or not ch_file.exists():
            continue
        ch_text = ch_file.read_text(encoding="utf-8")
        offenders: List[Dict[str, str]] = []

        for m in HEADING_LEVEL_3_OR_4_RE.finditer(ch_text):
            total_headings_scanned += 1
            heading_text = m.group(2).strip()
            # Skip structural headings — they are part of the template.
            if any(s in heading_text for s in STRUCTURAL_HEADING_SUBSTRINGS):
                continue
            match = FORBIDDEN_HEADING_TOKENS_RE.search(heading_text)
            if match:
                line_no = ch_text[: m.start()].count("\n") + 1
                offenders.append(
                    {
                        "line": str(line_no),
                        "heading": heading_text,
                        "forbidden_token": match.group(1).strip(),
                    }
                )
                total_offenders += 1

        if offenders:
            offenders_by_chapter[ch_id] = offenders
            for o in offenders:
                errors.append(
                    f"Chapter '{ch_id}' ({ch_file.name}) line {o['line']}: "
                    f"heading '{o['heading']}' violates concept-first rule "
                    f"(contains forbidden token '{o['forbidden_token']}'). "
                    f"Rewrite as a proposition — figures/tables/listings are evidence, "
                    f"not subjects. See references/multimodal-content.md Example 0."
                )

    stats = {
        "headings_scanned": total_headings_scanned,
        "offenders_total": total_offenders,
        "offenders_by_chapter": {k: len(v) for k, v in offenders_by_chapter.items()},
    }
    return len(errors) == 0, errors, stats


def _find_mermaid_id_leaks_in_text(text: str) -> Dict[str, Any]:
    """
    Find Mermaid single-letter node ID leaks in a single text body.

    For each Mermaid code block in the text:
      1. Extract the set of single-uppercase-letter node IDs (e.g. {'A','B','C','D'}).
      2. Scan the next MERMAID_LEAK_WINDOW_LINES lines of prose (cut short by
         the next heading or the next code fence) for standalone occurrences of
         any of those letters.
      3. Each standalone occurrence is recorded as a leak.

    Returns:
        {
            "blocks_scanned": int,
            "leaks": [
                {"line": int, "id": str, "distance": int, "context": str}
            ],
        }
    """
    leaks: List[Dict[str, Any]] = []
    lines = text.splitlines()

    blocks = []
    for m in MERMAID_BLOCK_RE.finditer(text):
        source = m.group(1)
        # Line numbers are 1-indexed; end_line is the line of the closing fence.
        start_line = text[: m.start()].count("\n") + 1
        end_line = text[: m.end()].count("\n") + 1

        ids: set = set()
        for id_match in MERMAID_SINGLE_LETTER_NODE_RE.finditer(source):
            letter = id_match.group(1)
            if letter in MERMAID_KEYWORDS_SINGLE_LETTER:
                continue
            ids.add(letter)

        blocks.append(
            {
                "start_line": start_line,
                "end_line": end_line,
                "ids": ids,
            }
        )

    for block in blocks:
        if not block["ids"]:
            continue
        # Window is the lines AFTER the closing fence. end_line is 1-indexed;
        # convert to 0-indexed start for slicing `lines`.
        window_start_idx = block["end_line"]  # line (end_line+1) in 1-indexed
        window_limit_idx = min(window_start_idx + MERMAID_LEAK_WINDOW_LINES, len(lines))

        for line_idx in range(window_start_idx, window_limit_idx):
            if line_idx >= len(lines):
                break
            line = lines[line_idx]
            stripped = line.strip()
            if not stripped:
                continue
            # Stop the window at the next code fence (prose ends there).
            if stripped.startswith("```"):
                break
            # Stop the window at the next markdown heading.
            if re.match(r"^#{1,6}\s", stripped):
                break
            # Collect all standalone-uppercase matches whose letter is in the
            # block's ID set. We group by letter so we can count DISTINCT IDs.
            matches_by_letter: Dict[str, List[Any]] = {}
            for match in PROSE_STANDALONE_UPPERCASE_RE.finditer(line):
                letter = match.group(1)
                if letter in block["ids"]:
                    matches_by_letter.setdefault(letter, []).append(match)

            # Precision guard: only flag a line when it contains >=2 DISTINCT
            # node IDs from the block's ID set. This is the observed failure
            # signature ("C 与 D 的交界处", "A -> B -> C"), and skipping the
            # single-letter case eliminates the common false positive where a
            # bare "C" on a nearby line refers to the C programming language
            # (e.g. "C 程序", "C 代码") and just happens to collide with a
            # Mermaid node ID. Leaks that genuinely involve only one letter on
            # a line (e.g. "节点 C 是入口") are accepted as missed — the
            # editorial review is expected to catch those.
            if len(matches_by_letter) < 2:
                continue

            for letter, match_list in matches_by_letter.items():
                for match in match_list:
                    context_start = max(0, match.start() - 20)
                    context_end = min(len(line), match.end() + 20)
                    snippet = line[context_start:context_end].strip()
                    leaks.append(
                        {
                            "line": line_idx + 1,
                            "id": letter,
                            "distance": (line_idx + 1) - block["end_line"],
                            "context": snippet,
                            "coincident_ids": sorted(matches_by_letter.keys()),
                        }
                    )

    return {
        "blocks_scanned": len(blocks),
        "leaks": leaks,
    }


def validate_mermaid_node_id_leaks(
    output_dir: Path,
    shared_memory: Dict[str, Any],
) -> Tuple[bool, List[str], Dict[str, Any]]:
    """
    Validate that no chapter's prose references a Mermaid source-level node ID.

    Mermaid code like `A[Static Analysis]` defines a node with ID `A` and label
    "Static Analysis". After rendering, the reader sees only the label text —
    the ID `A` is an internal identifier, invisible in the rendered figure. If
    the chapter's prose then says "A 与 B 的交界处" or "节点 C", the reader has
    no way to find out what A/B/C refer to. This is a silent but severe
    pedagogical bug: the chapter looks coherent to whoever reads the .md source
    but produces orphan single-letter references in the rendered output.

    This check extracts single-uppercase-letter node IDs from every Mermaid
    block in every chapter file, then scans the next 15 lines of prose after
    the block for standalone occurrences of any of those letters. Each match
    is a hard-fail.

    Scope: all `chapters/chapter_XX_output.md` files plus the merged
    `paper_explanation.md`. Longer (>=2 char) node IDs like `Comp1`, `B1`,
    `Start` are intentionally NOT checked — they're far less likely to be
    confused for bare prose references and checking them would inflate the
    false-positive rate.
    """
    errors: List[str] = []
    leaks_by_file: Dict[str, List[Dict[str, Any]]] = {}
    total_blocks = 0
    total_leaks = 0

    files_to_check: List[Tuple[str, Path]] = []
    for chapter in shared_memory.get("chapter_summaries", []):
        ch_id = chapter.get("chapter_id", "")
        ch_file = chapter_file_from_id(output_dir, ch_id)
        if ch_file is not None and ch_file.exists():
            files_to_check.append((ch_id, ch_file))

    explanation_file = output_dir / "paper_explanation.md"
    if explanation_file.exists():
        files_to_check.append(("paper_explanation.md", explanation_file))

    for file_label, file_path in files_to_check:
        text = file_path.read_text(encoding="utf-8")
        result = _find_mermaid_id_leaks_in_text(text)
        total_blocks += result["blocks_scanned"]
        if result["leaks"]:
            leaks_by_file[file_label] = result["leaks"]
            for leak in result["leaks"]:
                total_leaks += 1
                errors.append(
                    f"File '{file_label}' ({file_path.name}) line {leak['line']}: "
                    f"prose references Mermaid node ID '{leak['id']}' "
                    f"(defined {leak['distance']} line(s) above in a Mermaid "
                    f"block). Node IDs are internal source-code identifiers — "
                    f"the rendered image shows only node labels, not IDs, so "
                    f"the reader has no way to see what '{leak['id']}' refers "
                    f"to. Rewrite the prose to use the node's label text "
                    f"(e.g. 'Fuzzing 与 Concolic Execution 的交界处' instead "
                    f"of 'C 与 D 的交界处'). Context: {leak['context']!r}"
                )

    stats = {
        "mermaid_blocks_scanned": total_blocks,
        "leaks_total": total_leaks,
        "leaks_by_file": {k: len(v) for k, v in leaks_by_file.items()},
    }
    return len(errors) == 0, errors, stats


def validate_execution(output_dir: str) -> Tuple[bool, Dict[str, Any]]:
    """
    Main validation function.

    Returns:
        (is_valid, results) where results contains all validation checks
    """
    output_path = Path(output_dir)

    if not output_path.exists():
        return False, {
            "valid": False,
            "error": f"Output directory '{output_dir}' does not exist",
        }

    results: Dict[str, Any] = {
        "valid": True,
        "output_directory": str(output_path.absolute()),
        "validated_at": datetime.now().isoformat(),
        "checks": {},
    }

    # 1. Check required files
    files_valid, files_errors = validate_required_files(output_path)
    results["checks"]["required_files"] = {
        "passed": files_valid,
        "errors": files_errors,
    }
    if not files_valid:
        results["valid"] = False

    # Load metadata and shared memory for further checks
    metadata: Dict[str, Any] = {}
    shared_memory: Dict[str, Any] = {}

    try:
        metadata = load_json(output_path / "paper_metadata.json")
    except Exception as e:
        results["checks"]["figure_analysis"] = {
            "passed": False,
            "errors": [f"Cannot load paper_metadata.json: {e}"],
        }
        results["valid"] = False

    try:
        shared_memory = load_json(output_path / "shared_memory.json")
    except Exception as e:
        results["checks"]["chapter_reviews"] = {
            "passed": False,
            "errors": [f"Cannot load shared_memory.json: {e}"],
        }
        results["valid"] = False

    # 2. Validate figure analysis
    if metadata:
        fig_valid, fig_errors = validate_figure_analysis(metadata)
        results["checks"]["figure_analysis"] = {
            "passed": fig_valid,
            "errors": fig_errors,
            "figures_count": len(metadata.get("figures", [])),
            "image_analysis_status": metadata.get("image_analysis", {}).get("status", "unknown"),
        }
        if not fig_valid:
            results["valid"] = False

    # 2b. Visual sanity of extracted figure files. Independent of Figure
    # Analyst — catches mechanical rendering failures (blank crop, wrong
    # class) without needing a multimodal model.
    render_valid, render_errors, render_stats = validate_figure_rendering(output_path)
    results["checks"]["figure_rendering"] = {
        "passed": render_valid,
        "errors": render_errors,
        **render_stats,
    }
    if not render_valid:
        results["valid"] = False

    # 3. Validate chapter reviews
    if shared_memory:
        review_valid, review_errors = validate_chapter_reviews(shared_memory)
        results["checks"]["chapter_reviews"] = {
            "passed": review_valid,
            "errors": review_errors,
            "chapters_count": len(shared_memory.get("chapter_summaries", [])),
        }
        if not review_valid:
            results["valid"] = False

    # 4. Validate metadata/shared-memory alignment
    if metadata and shared_memory:
        align_valid, align_errors = validate_schema_alignment(metadata, shared_memory)
        results["checks"]["schema_alignment"] = {
            "passed": align_valid,
            "errors": align_errors,
        }
        if not align_valid:
            results["valid"] = False

    # 5. Validate chapter output files and coverage floor
    if shared_memory:
        chapter_valid, chapter_errors, chapter_stats = validate_chapter_outputs(output_path, shared_memory)
        results["checks"]["chapter_outputs"] = {
            "passed": chapter_valid,
            "errors": chapter_errors,
            "chapters": chapter_stats,
        }
        if not chapter_valid:
            results["valid"] = False

    # 6. Validate final explanation content
    if metadata and shared_memory:
        content_valid, content_errors, content_stats = validate_explanation_content(
            output_path, metadata, shared_memory
        )
        results["checks"]["explanation_content"] = {
            "passed": content_valid,
            "errors": content_errors,
            **content_stats,
        }
        if not content_valid:
            results["valid"] = False

    # 7. Validate multimodal content (figure rendering, teaching paragraphs, listings)
    if metadata and shared_memory:
        mm_valid, mm_errors, mm_warnings, mm_stats = validate_multimodal_content(
            output_path, metadata, shared_memory
        )
        results["checks"]["multimodal_content"] = {
            "passed": mm_valid,
            "errors": mm_errors,
            "warnings": mm_warnings,
            **mm_stats,
        }
        if not mm_valid:
            results["valid"] = False

    # 8. Validate concept-first headings (forbids Figure N / Listing N / 图 N sub-sections)
    if shared_memory:
        cf_valid, cf_errors, cf_stats = validate_concept_first_headings(
            output_path, shared_memory
        )
        results["checks"]["concept_first_headings"] = {
            "passed": cf_valid,
            "errors": cf_errors,
            **cf_stats,
        }
        if not cf_valid:
            results["valid"] = False

    # 9. Validate mermaid node ID leaks (forbids prose references to source-level
    # single-letter node IDs like "A 与 B 的交界处" — the rendered figure shows
    # only node labels, so the ID is invisible to the reader).
    if shared_memory:
        mm_id_valid, mm_id_errors, mm_id_stats = validate_mermaid_node_id_leaks(
            output_path, shared_memory
        )
        results["checks"]["mermaid_node_id_leaks"] = {
            "passed": mm_id_valid,
            "errors": mm_id_errors,
            **mm_id_stats,
        }
        if not mm_id_valid:
            results["valid"] = False

    return results["valid"], results


def main() -> None:
    if len(sys.argv) < 2:
        print("Usage: python validate_execution.py <output_directory>")
        print("\nExample:")
        print("  python validate_execution.py paper_tutor_2026-02-24_attention-is-all-you-need/")
        sys.exit(1)

    output_dir = sys.argv[1]
    is_valid, results = validate_execution(output_dir)

    print("=" * 60)
    print("Paper Tutor Execution Validation Report")
    print("=" * 60)
    print(f"\nOutput Directory: {results.get('output_directory', output_dir)}")
    print(f"Validated At: {results.get('validated_at', 'N/A')}")
    print(f"\nOverall Status: {'✅ PASSED' if is_valid else '❌ FAILED'}")
    print("-" * 60)

    checks = results.get("checks", {})

    for check_name, check_result in checks.items():
        status = "✅" if check_result.get("passed") else "❌"
        print(f"\n{status} {check_name.replace('_', ' ').title()}:")

        if check_name == "figure_analysis" and check_result.get("passed"):
            print(f"   - Figures analyzed: {check_result.get('figures_count', 0)}")
            print(f"   - Image analysis status: {check_result.get('image_analysis_status', 'unknown')}")

        if check_name == "chapter_reviews" and check_result.get("passed"):
            print(f"   - Chapters reviewed: {check_result.get('chapters_count', 0)}")

        if check_name == "chapter_outputs" and check_result.get("chapters"):
            print("   - Chapter coverage snapshot:")
            for ch in check_result["chapters"]:
                print(
                    "     * "
                    f"{ch['chapter_id']} ({ch['file']}): "
                    f"{ch['content_units']} units "
                    f"(min {ch['required_min_units']}, target {ch['target_words']})"
                )

        if check_name == "explanation_content":
            found = check_result.get("final_numbered_chapters")
            expected = check_result.get("expected_numbered_chapters")
            h1 = check_result.get("h1_numbered_chapters", 0)
            if found is not None and expected is not None:
                print(f"   - Numbered chapters in final doc: {found} (expected {expected})")
            if h1:
                print(f"   - Raw H1 numbered chapters (should be 0): {h1}")

        if check_name == "concept_first_headings":
            scanned = check_result.get("headings_scanned", 0)
            offenders = check_result.get("offenders_total", 0)
            print(f"   - Headings scanned: {scanned}")
            print(f"   - Concept-first violations: {offenders}")
            by_chapter = check_result.get("offenders_by_chapter", {})
            if by_chapter:
                for ch_id, count in by_chapter.items():
                    print(f"     * {ch_id}: {count} figure-named heading(s)")

        if check_name == "mermaid_node_id_leaks":
            blocks = check_result.get("mermaid_blocks_scanned", 0)
            leaks = check_result.get("leaks_total", 0)
            print(f"   - Mermaid blocks scanned: {blocks}")
            print(f"   - Single-letter ID leaks in prose: {leaks}")
            by_file = check_result.get("leaks_by_file", {})
            if by_file:
                for file_label, count in by_file.items():
                    print(f"     * {file_label}: {count} leak(s)")

        if check_name == "multimodal_content":
            if check_result.get("skipped_reason"):
                print(f"   - {check_result['skipped_reason']}")
            else:
                total = check_result.get("total_figures", 0)
                assigned = check_result.get("assigned_figures", 0)
                unassigned = check_result.get("unassigned_figures", 0)
                print(
                    f"   - Figures: {total} total, {assigned} assigned to chapters, "
                    f"{unassigned} unassigned"
                )
                exp_rendered = check_result.get("explanation_rendered_figures")
                if exp_rendered is not None:
                    print(
                        f"   - paper_explanation.md rendered figures: {exp_rendered} "
                        f"/ {total}"
                    )
                for ch in check_result.get("chapters", []):
                    expected_n = ch.get("expected_figures", 0)
                    embedded_n = ch.get("embedded_assigned_figures", 0)
                    total_refs = ch.get("total_image_references", 0)
                    mark = "✓" if expected_n == embedded_n else "✗"
                    print(
                        f"     {mark} {ch['chapter_id']} ({ch['file']}): "
                        f"{embedded_n}/{expected_n} assigned figures embedded "
                        f"({total_refs} total image refs)"
                    )

        for warning in check_result.get("warnings", []) or []:
            print(f"   ⚠️  {warning}")

        for error in check_result.get("errors", []):
            print(f"   ❌ {error}")

    print("\n" + "=" * 60)

    sys.exit(0 if is_valid else 1)


if __name__ == "__main__":
    main()
