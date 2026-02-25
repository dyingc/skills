#!/usr/bin/env python3
"""
Paper Tutor Execution Validator

Validates that the Paper Tutor workflow was executed correctly by checking:
1. Figure analysis was performed by Figure Analyst (not faked)
2. All chapters were reviewed and approved by Editor-in-Chief
3. Required files exist and have valid content

Usage:
    python validate_execution.py <output_directory>
"""

import json
import os
import sys
from pathlib import Path
from datetime import datetime
from typing import Tuple, List, Dict, Any


def load_json(path: Path) -> Dict[str, Any]:
    """Load JSON file."""
    with open(path, 'r', encoding='utf-8') as f:
        return json.load(f)


def validate_figure_analysis(metadata: Dict) -> Tuple[bool, List[str]]:
    """
    Validate that figure analysis was performed by Figure Analyst.

    Key checks:
    1. If level1_summary exists, analyzed_by must be "figure_analyst_agent"
    2. analyzed_at timestamp must exist
    3. analysis_method must be specified
    """
    errors = []

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
                errors.append(
                    f"Figure '{fig_file}' is missing analyzed_at timestamp"
                )

            if not fig.get("analysis_method"):
                errors.append(
                    f"Figure '{fig_file}' is missing analysis_method"
                )

    return len(errors) == 0, errors


def validate_chapter_reviews(shared_memory: Dict) -> Tuple[bool, List[str]]:
    """
    Validate that all chapters were reviewed and approved by Editor-in-Chief.

    Key checks:
    1. Each chapter must have review_score >= 4.0
    2. Each chapter must have status "approved"
    3. reviewer must be "editor_in_chief"
    """
    errors = []

    chapter_summaries = shared_memory.get("chapter_summaries", [])

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
    errors = []

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


def validate_explanation_content(output_dir: Path, metadata: Dict) -> Tuple[bool, List[str]]:
    """
    Validate that paper_explanation.md correctly references figures.

    Key checks:
    1. If figures exist in metadata, they should be referenced in explanation
    2. Figure references should match the actual figure descriptions
    """
    errors = []

    explanation_path = output_dir / "paper_explanation.md"
    if not explanation_path.exists():
        return False, ["paper_explanation.md does not exist"]

    with open(explanation_path, 'r', encoding='utf-8') as f:
        explanation_content = f.read()

    figures = metadata.get("figures", [])

    for fig in figures:
        fig_file = fig.get("file", "")
        if fig_file and fig_file not in explanation_content:
            errors.append(
                f"Figure '{fig_file}' is in metadata but not referenced in explanation"
            )

    return len(errors) == 0, errors


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
            "error": f"Output directory '{output_dir}' does not exist"
        }

    results = {
        "valid": True,
        "output_directory": str(output_path.absolute()),
        "validated_at": datetime.now().isoformat(),
        "checks": {}
    }

    # 1. Check required files
    files_valid, files_errors = validate_required_files(output_path)
    results["checks"]["required_files"] = {
        "passed": files_valid,
        "errors": files_errors
    }
    if not files_valid:
        results["valid"] = False

    # Load metadata and shared memory for further checks
    metadata = {}
    shared_memory = {}

    try:
        metadata = load_json(output_path / "paper_metadata.json")
    except Exception as e:
        results["checks"]["figure_analysis"] = {
            "passed": False,
            "errors": [f"Cannot load paper_metadata.json: {e}"]
        }
        results["valid"] = False

    try:
        shared_memory = load_json(output_path / "shared_memory.json")
    except Exception as e:
        results["checks"]["chapter_reviews"] = {
            "passed": False,
            "errors": [f"Cannot load shared_memory.json: {e}"]
        }
        results["valid"] = False

    # 2. Validate figure analysis
    if metadata:
        fig_valid, fig_errors = validate_figure_analysis(metadata)
        results["checks"]["figure_analysis"] = {
            "passed": fig_valid,
            "errors": fig_errors,
            "figures_count": len(metadata.get("figures", [])),
            "image_analysis_status": metadata.get("image_analysis", {}).get("status", "unknown")
        }
        if not fig_valid:
            results["valid"] = False

    # 3. Validate chapter reviews
    if shared_memory:
        review_valid, review_errors = validate_chapter_reviews(shared_memory)
        results["checks"]["chapter_reviews"] = {
            "passed": review_valid,
            "errors": review_errors,
            "chapters_count": len(shared_memory.get("chapter_summaries", []))
        }
        if not review_valid:
            results["valid"] = False

    # 4. Validate explanation content
    if metadata:
        content_valid, content_errors = validate_explanation_content(output_path, metadata)
        results["checks"]["explanation_content"] = {
            "passed": content_valid,
            "errors": content_errors
        }
        if not content_valid:
            results["valid"] = False

    return results["valid"], results


def main():
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

        for error in check_result.get("errors", []):
            print(f"   ❌ {error}")

    print("\n" + "=" * 60)

    sys.exit(0 if is_valid else 1)


if __name__ == "__main__":
    main()
