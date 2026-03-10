# Output Format Reference

This reference contains format specifications for all output files in the deep research workflow.

## Source Index Format

### File: `sources/chapter_N/sources_index.md`

```markdown
# Sources for Chapter N: [Chapter Title]

## Summary
- **Total sources:** [N]
- **High credibility:** [N]
- **Medium credibility:** [N]
- **Lower credibility:** [N]

## Source 1: [Title]
- **Type:** [PDF/Webpage/API/Video/Other]
- **URL:** [Original URL if applicable]
- **Saved to:** `source_01_[ext]` or `source_01_pdf/`
- **Date accessed:** [YYYY-MM-DD]
- **Credibility:** [High/Medium/Low] - [Brief justification]
- **Relevance:** [How this source will be used in the chapter]

## Source 2: [Title]
[Same structure]

## Usage Notes
- [Any notes about how sources relate to each other]
- [Which sources provide key evidence for which sections]
```

## Framework Format

### File: `chapters/N_framework_draft.md`

```markdown
# Chapter N: [Chapter Title]

## Research Questions
- [Main research question 1]
- [Main research question 2]

## Sub-Topics to Cover
1. **[Sub-topic 1]** - [Description]
   - Expected depth: [Comprehensive/Overview]
   - Key sources: [Source 1, Source 2]

2. **[Sub-topic 2]** - [Description]
   - Expected depth: [Comprehensive/Overview]
   - Key sources: [Source 3]

## Key Sources
- [Source 1] - [Brief note on why key]
- [Source 2] - [Brief note on why key]

## Proposed Structure

### Section 1: [Title]
- [What this section covers]
- [Key arguments to make]
- [Sources to use]

### Section 2: [Title]
- [What this section covers]
- [Key arguments to make]
- [Sources to use]

## Expected Deliverables
- [What this chapter will deliver]
- [How it connects to overall research goals]

## Boundaries
- **In scope:** [What's covered]
- **Out of scope:** [What's explicitly not covered]
```

### File: `chapters/N_framework_review.md`

```markdown
# Framework Review: Chapter N

## Summary
[Framework approved as-is / Minor revisions suggested / Major revisions needed]

## Modifications Made

### Added Sub-Topics
1. **[New sub-topic]** - **Rationale:** [Why this is critical]
2. **[New sub-topic]** - **Rationale:** [Why this is critical]

### Adjusted Focus
- **Original:** [topic] → **Revised:** [new topic]
  - **Rationale:** [Why this change]

### Source Recommendations
- **Add:** [New source with URL] - **Rationale:** [What it adds]
- **Replace:** [Old source] → [New source] - **Rationale:** [Why]
- **Remove:** [Source] - **Rationale:** [Why not essential]

### Removed Areas
- [Removed topic] - **Rationale:** [Why out of scope or not essential]

## Research Guidance
- [Specific areas needing additional research]
- [Questions to investigate when writing]

## Revised Framework

[Complete, revised framework for chapter agent to use]

## Updated Source Index
[Updated sources_index.md content if new sources were added]
```

## Chapter Format

### File: `chapters/N_chapter_final.md`

```markdown
# Chapter N: [Chapter Title]

## Introduction
[Set context for this chapter - 2-3 paragraphs]
- What this chapter covers
- Why it matters for the overall research
- Connection to previous chapter (if not first)
- Preview of key findings

## [Section 1 Title]

[Opening sentence for the section]

[Deep analysis with evidence]

> **Source:** [[1]](../sources/chapter_N/source_01_content.md)
> **Full source:** `sources/chapter_N/source_01_pdf/`

[Continue analysis with multiple perspectives]
[Include data, examples, case studies]
[Acknowledge limitations where applicable]

[Closing sentence for the section]

## [Section 2 Title]
[Continue with same structure]

...

## Chapter Conclusions
[Synthesize key findings from this chapter - 2-3 paragraphs]
- Answer the research questions
- Summarize most important findings
- Connection to next chapter (if not last)

## References

### Direct Citations
[1] [Author/Organization] - "[Title]" - [Publication/Year]
    `sources/chapter_N/source_01_content.md`

[2] [Author/Organization] - "[Title]" - [Publication/Year]
    `sources/chapter_N/source_02_pdf/`

### Complete Source Index
See: `sources/chapter_N/sources_index.md` for complete list of sources with credibility assessments
```

## Synthesis Output Formats

### File: `synthesis/executive_summary_content.md`

```markdown
# Executive Summary Content

## Overview
[2-3 paragraphs synthesizing the most important findings from all chapters]
- Start with the big picture
- Highlight most significant insights
- Connect findings across chapters

## Key Insights
1. **[Insight title]**
   - [Cross-chapter finding]
   - [Evidence from chapters X, Y]

2. **[Insight title]**
   - [Cross-chapter pattern]
   - [Evidence from chapters A, B]

## Bottom Line
[2-3 sentences capturing the overall conclusion]
- What the research ultimately shows
- Practical implications if applicable
- Most important takeaway
```

### File: `synthesis/conclusions_content.md`

```markdown
# Overall Conclusions

## Integrated Findings
[Synthesize key findings across all chapters]
- How different chapters' findings relate
- What emerges when looking at everything together
- Consensus across chapters vs areas of disagreement

## Cross-Chapter Patterns
[Patterns identified across multiple chapters]
- Recurring themes
- Unexpected connections
- Convergent evidence from different angles

## Recommendations
[Evidence-based recommendations drawing from all chapters]
1. **[Recommendation 1]** - [Supported by: Chapter X, Y]
   - Priority: [High/Medium/Low]
   - Confidence: [High/Medium/Low]

2. **[Recommendation 2]** - [Supported by: Chapter Z]
   - Priority: [High/Medium/Low]
   - Confidence: [High/Medium/Low]

## Implications
- **For the field/topic:** [What these findings mean]
- **Practical implications:** [If applicable]
- **Future research directions:** [Gaps identified]
```

### File: `synthesis/navigation_content.md`

```markdown
# Navigation Guide

## Chapter Overview

| Chapter | Title | File | Key Topics | Reading Time |
|---------|-------|------|------------|--------------|
| 1 | [Title] | `chapters/01_chapter_final.md` | [Topic 1, Topic 2, Topic 3] | ~15 min |
| 2 | [Title] | `chapters/02_chapter_final.md` | [Topic 1, Topic 2] | ~20 min |
| ... | ... | ... | ... | ... |

## Reading Paths

**Quick overview (5-10 min):**
1. Read Executive Summary in `research_report.md`
2. Review Chapter Overview table
3. Scan "Key Findings" for each chapter

**Comprehensive (2-3 hours):**
1. Read all chapters in sequence
2. Follow cross-references between chapters
3. Review source materials for claims of interest

**Targeted research:**
- For [Topic A]: Read Chapters 1, 3
- For [Topic B]: Read Chapters 2, 4
- For [Topic C]: Read Chapter 5

## Chapter Dependencies
- **Prerequisite:** Chapter 1 should be read before Chapters 2, 3
- **Standalone:** Chapters 4, 5 can be read independently
- **Recommended sequence:** [Suggested reading order]

## Key Cross-Chapter Themes

**Theme 1: [Theme name]**
- Discussed in: Chapters 1, 3, 5
- Key insight: [Cross-chapter finding]

**Theme 2: [Theme name]**
- Discussed in: Chapters 2, 4
- Key insight: [Cross-chapter finding]
```

## Source Inventory Format

### File: `sources/complete_sources_inventory.md`

```markdown
# Complete Sources Inventory

## Summary
- **Total sources:** [N]
- **Chapters covered:** [N]
- **Shared sources:** [N]
- **Total file size:** [Approximate]

## Source Quality Distribution
- **High credibility:** [N] sources (official docs, peer-reviewed papers, established standards)
- **Medium credibility:** [N] sources (industry reports, vendor docs, reputable blogs)
- **Lower credibility:** [N] sources (community forums, informal sources - use with caution)

## Source Type Distribution
- **PDFs:** [N]
- **Webpages:** [N]
- **API/Data:** [N]
- **Other:** [N]

## By Chapter

### Chapter 1: [Title]
**Index:** `sources/chapter_01/sources_index.md`
- **Source count:** [N]
- **Types:** [N] PDFs, [N] webpages, [N] other
- **Key sources:**
  - [Source 1 - title/URL]
  - [Source 2 - title/URL]

### Chapter 2: [Title]
[Same structure]

## Shared Sources
Sources used across multiple chapters:

**[Source name/URL]**
- Used in: Chapter 1, Chapter 3
- Relevance to Ch1: [How used]
- Relevance to Ch3: [How used]

## Source Access
- All source materials saved in `sources/` directory
- Each chapter: `sources/chapter_N/sources_index.md`
- Original content: `sources/chapter_N/source_XX_*`
```

## Research Report Format

### File: `research_report.md`

```markdown
# Deep Research Report: [Topic]

**Generated:** [YYYY-MM-DD HH:MM]
**Research Depth:** [Comprehensive/Deep Dive]
**Chapters:** [N]
**Total Research Time:** [X hours]

---

## Executive Summary

[From synthesis/executive_summary_content.md]

## Quick Navigation

[Table from synthesis/navigation_content.md - Chapter Overview section]

---

## How to Use This Report

1. **Start here** - Read this Executive Summary
2. **Choose your path:**
   - Quick scan: Executive Summary only
   - Comprehensive: All chapters in sequence
   - Targeted: Specific chapters
3. **Deep dive** - Individual chapter files
4. **Verify** - `sources/` directory
5. **Navigate** - Cross-references

---

## Methodology

**Research Process:**
- Exploratory Discovery: [Description or N/A]
- Chapter Planning: [N] chapters planned
- Parallel Research: N chapter agents with framework review
- Source Archiving: All materials saved locally
- Synthesis: Chapters edited for coherence
- Quality Assurance: LLM-as-judge evaluation

**Quality Score:** [X]/5.0 ([Interpretation])

---

## Report Chapters

[From synthesis/navigation_content.md - formatted as chapter summaries]

---

## Overall Conclusions

[From synthesis/conclusions_content.md]

---

## Sources

**Complete inventory:** `sources/complete_sources_inventory.md`

**Chapter-specific:**
- Chapter 1: `sources/chapter_01/sources_index.md`
- Chapter 2: `sources/chapter_02/sources_index.md`
- ...

All source materials saved in `sources/` for verification.

---

## Quality Assessment

**Overall:** [X]/5.0

For details: `final_qa/quality_assessment.md`
```

## File Naming Conventions

```
research_output/
├── research_report.md
├── metadata.json
├── planning/
│   └── chapter_plan.md
├── chapters/
│   ├── NN_framework_draft.md      # NN = 01, 02, 03...
│   ├── NN_framework_review.md
│   └── NN_chapter_final.md
├── sources/
│   ├── chapter_NN/
│   │   ├── source_XX_[ext]        # XX = 01, 02, 03...
│   │   └── sources_index.md
│   └── complete_sources_inventory.md
├── synthesis/
│   ├── executive_summary_content.md
│   ├── conclusions_content.md
│   └── navigation_content.md
└── final_qa/
    ├── quality_assessment.md
    └── refinement_log.md
```

**Key conventions:**
- Chapter numbers: Zero-padded to 2 digits (01, 02, 03...)
- Source numbers: Zero-padded to 2 digits (01, 02, 03...)
- File names: snake_case
- Descriptive names: Clear about content
