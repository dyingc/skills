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

    return len(errors) == 0, errors


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

        # Check review score
        review_score = chapter.get("review_score", 0)
        if review_score < 4.0:
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
    Validate that paper_explanation.md correctly references figures and chapter structure.

    Key checks:
    1. If figures exist in metadata, they should be referenced in explanation
    2. Numbered chapter count in final explanation must match approved chapters
    """
    errors: List[str] = []

    explanation_path = output_dir / "paper_explanation.md"
    if not explanation_path.exists():
        return False, ["paper_explanation.md does not exist"], {}

    explanation_content = explanation_path.read_text(encoding="utf-8")

    figures = metadata.get("figures", [])

    for fig in figures:
        fig_file = fig.get("file", "")
        if fig_file and fig_file not in explanation_content:
            errors.append(
                f"Figure '{fig_file}' is in metadata but not referenced in explanation"
            )

    chapter_heading_matches = re.findall(
        r"^##\s+第[一二三四五六七八九十百]+章",
        explanation_content,
        flags=re.MULTILINE,
    )
    final_chapter_count = len(chapter_heading_matches)
    expected_chapter_count = len(shared_memory.get("chapter_summaries", []))

    if final_chapter_count != expected_chapter_count:
        errors.append(
            "Final explanation numbered chapter count mismatch: "
            f"found {final_chapter_count}, expected {expected_chapter_count} "
            "(must match approved chapters in shared_memory)"
        )

    stats = {
        "final_numbered_chapters": final_chapter_count,
        "expected_numbered_chapters": expected_chapter_count,
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
            if found is not None and expected is not None:
                print(f"   - Numbered chapters in final doc: {found} (expected {expected})")

        for error in check_result.get("errors", []):
            print(f"   ❌ {error}")

    print("\n" + "=" * 60)

    sys.exit(0 if is_valid else 1)


if __name__ == "__main__":
    main()
