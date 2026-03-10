# Synthesis: Coherence Editing and Report Integration

This reference contains detailed prompts for the synthesis phase.

## Synthesis Agent Responsibilities

The synthesis agent ensures all chapters work together coherently by:
1. Editing chapter files directly for transitions, contradictions, and overlaps
2. Creating supporting content files (executive summary, conclusions, navigation)
3. Creating a unified source inventory
4. Creating the main research report as entry point

## Synthesis Agent Prompt

```python
synthesis_agent = Task(
    "general-purpose",
    f"""You are the Synthesis Agent. Ensure all chapters work together coherently and create a unified report entry point.

**Step 1: Review All Chapters**

Read all chapter files in sequence:
- `chapters/01_chapter_final.md`
- `chapters/02_chapter_final.md`
- ...
- `chapters/NN_chapter_final.md`

For each chapter, note:
- Main topics covered
- Key findings and claims
- Sources used
- Any references to other chapters

**Step 2: Review Source Materials**

Read all `sources/chapter_*/sources_index.md` files to understand:
- What source materials were collected
- Any shared sources across chapters
- Gaps in source coverage
- Overall source quality distribution

**Step 3: Edit Chapters for Coherence**

For each chapter file, make these edits:

**Add transitions:**
- At chapter start (if not first chapter):
  "Building on Chapter N's discussion of [topic], this chapter explores [current topic]..."

- At chapter end (if not last chapter):
  "This analysis of [topic] sets the foundation for Chapter N+1's examination of [next topic]..."

**Resolve contradictions:**
- Find conflicting claims between chapters
- Investigate which has stronger evidence
- Edit to reflect nuance: "While Chapter X suggests [claim], Chapter Y's evidence indicates [more accurate claim due to [reason]]..."

**Remove/reduce overlaps:**
- Keep content in the chapter where it's primary
- In secondary chapter: "This aspect is covered in detail in Chapter X. Briefly: [2-3 sentence summary]"

**Add cross-references:**
- "See Chapter N for detailed analysis of [related topic]"
- Add these where natural and helpful

**Edit each file directly:** `chapters/*_chapter_final.md`

**Step 4: Create Supporting Files**

**Create `synthesis/executive_summary_content.md`:**
```markdown
# Executive Summary Content

[2-3 paragraphs synthesizing the most important findings from all chapters]

## Key Insights
1. [Insight 1 - synthesizes findings from multiple chapters]
2. [Insight 2 - cross-chapter pattern or conclusion]
3. [Insight 3 - major takeaway]

## Bottom Line
[2-3 sentences capturing the overall conclusion]
```

**Create `synthesis/conclusions_content.md`:**
```markdown
# Overall Conclusions

## Integrated Findings
[Synthesize key findings across all chapters]
[Identify patterns that emerge when looking at all chapters together]

## Cross-Chapter Patterns
[Patterns that emerged across chapters]
[How different chapters' findings relate to each other]

## Recommendations
[Evidence-based recommendations drawing from all chapters]
[Prioritized by strength of evidence]

## Implications
[What these findings mean for the field/topic]
[Practical implications if applicable]
[Future research directions if gaps identified]
```

**Create `synthesis/navigation_content.md`:**
```markdown
# Navigation Guide

## Chapter Overview

| Chapter | Title | File | Key Topics | Status |
|---------|-------|------|------------|--------|
| 1 | [Title] | `chapters/01_chapter_final.md` | [3-5 key topics] | Complete |
| 2 | [Title] | `chapters/02_chapter_final.md` | [3-5 key topics] | Complete |
| ... | ... | ... | ... | ... |

## Reading Paths

**Quick overview (5 min):**
- Read Executive Summary in `research_report.md`
- Review Chapter Overview table above

**Comprehensive (2+ hours):**
- Read all chapters in sequence
- Follow cross-references between chapters

**Specific interest:**
- Jump to relevant chapter(s) based on topic
- Use navigation guide to identify related chapters

## Chapter Dependencies
- [Note any chapters that should be read in sequence]
- [Note any chapters that can be read independently]

## Key Cross-Chapter Themes
- [Theme 1]: Discussed in Chapters X, Y, Z
- [Theme 2]: Discussed in Chapters A, B
```

**Create `sources/complete_sources_inventory.md`:**
```markdown
# Complete Sources Inventory

## Summary
- **Total sources:** [N]
- **Chapters covered:** [N]
- **Shared sources:** [N]

## Source Quality Distribution
- **High credibility:** [N] sources (official docs, peer-reviewed papers)
- **Medium credibility:** [N] sources (established vendors, industry reports)
- **Lower credibility:** [N] sources (blogs, forums - use with caution)

## By Chapter

### Chapter 1: [Title]
**Index:** `sources/chapter_01/sources_index.md`
- [N] sources: [N] PDFs, [N] webpages, [N] other
- **Key sources:**
  - [Source 1 - title/URL]
  - [Source 2 - title/URL]

### Chapter 2: [Title]
[Same structure]

## Shared Sources
Sources used across multiple chapters:
- [Source] - Used in: Chapter 1, Chapter 3
  - **Relevance to each:** [Brief explanation]

## Source Access
- All source materials saved in `sources/` directory
- Each chapter has its own `sources/chapter_N/sources_index.md`
- Original content available in respective `source_XX_*` files
```

**Step 5: Create Unified Report**

Create `research_report.md` as the main entry point for the entire research output.

**Report structure:**
```markdown
# Deep Research Report: [Topic]

**Generated:** [Date and time]
**Research Depth:** [Comprehensive/Deep Dive]
**Chapters:** [N]
**Total Research Time:** [Approximate duration]

---

## Executive Summary

[Content from synthesis/executive_summary_content.md]

## Quick Navigation

| Chapter | File | Key Topics |
|---------|------|------------|
| Chapter 1: [Title] | `chapters/01_chapter_final.md` | [topics] |
| Chapter 2: [Title] | `chapters/02_chapter_final.md` | [topics] |

[Full table from synthesis/navigation_content.md]

---

## How to Use This Report

1. **Start here** - Read this Executive Summary for key findings
2. **Choose your path:**
   - **Quick scan:** Read Executive Summary only (5 min)
   - **Comprehensive:** Read all chapters in sequence (2+ hours)
   - **Targeted:** Jump to specific chapters of interest
3. **Deep dive** - Open individual chapter files for detailed analysis
4. **Verify** - All sources are saved in `sources/` directory
5. **Navigate** - Use cross-references between chapters

---

## Methodology

**Research Process:**
- **Exploratory Discovery:** [Description - if applicable, otherwise note "Specific topic provided"]
- **Chapter Planning:** [N] chapters planned with [brief description of approach]
- **Parallel Research:** N chapter agents with framework review
- **Source Archiving:** All materials saved locally in `sources/` directory
- **Synthesis:** Chapters edited for coherence and cross-references
- **Quality Assurance:** LLM-as-judge evaluation (see `final_qa/quality_assessment.md`)

**Quality Score:** [X]/5.0 - [Interpretation]

---

## Report Chapters

### Chapter 1: [Title]

**📄 Full content:** `chapters/01_chapter_final.md`

**Overview:** [2-3 sentence description from navigation_content.md]

**Key Findings:**
- [Finding 1]
- [Finding 2]

### Chapter 2: [Title]

**📄 Full content:** `chapters/02_chapter_final.md`

**Overview:** [2-3 sentence description]

**Key Findings:**
- [Finding 1]
- [Finding 2]

[Continue for all chapters]

---

## Overall Conclusions

[Content from synthesis/conclusions_content.md]

---

## Sources

**Complete inventory:** `sources/complete_sources_inventory.md`

**Chapter-specific sources:**
- Chapter 1: `sources/chapter_01/sources_index.md`
- Chapter 2: `sources/chapter_02/sources_index.md`
- ...

All source materials are saved in the `sources/` directory for:
- Full traceability of all claims
- Offline access to original materials
- Verification and fact-checking
- Future reference

---

## Quality Assessment

**Overall Quality:** [X]/5.0 - [Excellent/Good/Acceptable/Weak]

For detailed quality breakdown and consumer guidance, see: `final_qa/quality_assessment.md`

**Quality Interpretation:**
- [Guidance on which findings are trustworthy]
- [Guidance on which areas require caution]
- [Recommendations for verification if needed]
```

**Output files:**
- Edit: `chapters/*_chapter_final.md` (for coherence - add transitions, resolve contradictions)
- Create: `synthesis/executive_summary_content.md`
- Create: `synthesis/conclusions_content.md`
- Create: `synthesis/navigation_content.md`
- Create: `sources/complete_sources_inventory.md`
- Create: `research_report.md` (main entry point)

**Quality checklist:**
- Does the narrative flow when reading chapters in sequence?
- Are contradictions resolved or explained?
- Is redundancy minimized without losing important content?
- Are cross-chapter connections clear?
- Is the executive summary comprehensive yet concise?
- Does the research report provide good navigation?""",
    "Synthesis: Coherence and unified report"
)
```

## Editing Guidelines

### Transition Examples

**Good transitions:**
- "Having established [topic from Chapter N], this chapter examines [current topic]..."
- "While Chapter N focused on [aspect], this chapter explores [related aspect]..."
- "The findings from Chapter N regarding [topic] inform our analysis of [current topic]..."

### Contradiction Resolution

**When chapters disagree:**
1. Identify which source is more authoritative
2. Check if disagreement is due to context/timing
3. Edit to reflect nuance
4. Acknowledge uncertainty if resolution unclear

**Example:**
```markdown
> Original (Chapter 2): "X is always true."
> Original (Chapter 5): "X is rarely true in practice."
>
> Synthesized (Chapter 2): "While X is theoretically sound (see Chapter 5 for practical limitations), it forms the foundation for..."
> Synthesized (Chapter 5): "Although Chapter 2 establishes the theoretical basis for X, practical implementations face these limitations..."
```

### Overlap Handling

**Keep content where primary, cross-reference elsewhere:**
- Primary chapter: Full analysis
- Secondary chapters: "This aspect is covered in detail in Chapter X. Key point: [1 sentence summary]"
