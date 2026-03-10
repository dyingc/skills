---
name: deep-research
description: >
  Conduct comprehensive, deep research (1hr+ for complex topics) with multi-chapter report generation.
  Use when users request: "deep research X", "comprehensive investigation of X", "thorough analysis",
  "I need to understand X in depth", "exhaustive research on X".

  Architecture: Chapter-Based Parallel Research with Framework Review.
  - Exploratory discovery clarifies research scope
  - Chapter planning decomposes topic into independent research directions
  - Parallel chapter agents research, draft frameworks, and write complete chapters
  - Framework review agents validate and improve frameworks through their own research
  - Synthesis agent ensures coherence across chapters
  - LLM-as-judge quality evaluation ensures rigor

  All source materials are saved for full traceability and verification.

allowed-tools:
  # MCP Search and Fetch Tools (Required for web research)
  - mcp__brave-search__*
  - mcp__fetch__*
  - mcp__playwright__*

  # Core tools for research workflow
  - AskUserQuestion
  - Task
  - Read
  - Write
  - Edit
  - Glob
  - Grep

  # Context7 for documentation research
  - mcp__context7__*
---

# Deep Research

Conduct comprehensive investigation with chapter-based parallel research, framework review, and full source traceability.

## Core Philosophy

Deep research v2.0 addresses three challenges through a multi-chapter architecture:

1. **Uncertain scope**: Exploratory discovery clarifies what to research
2. **Complex topics**: Chapter-based parallel research enables deep, independent investigation of each aspect
3. **High stakes**: Framework review + LLM-as-judge evaluation ensures rigor

**Key architectural change**: Each chapter is researched and written by an independent agent, with framework review ensuring quality before writing begins. All source materials are saved for full traceability.

**Evidence base**: Built on research from 15+ academic papers (2024-2025), including NeurIPS, ICLR, arXiv findings on deep research agents, Self-Refine methodology, and LLM-as-judge evaluation.

## Workflow Overview

```
Pre-Step: Determine Output Location
  ↓
Step 0: Exploratory Discovery (if query vague)
  ↓
Step 1: Chapter Planning
  ↓
Step 2-4: Chapter Workflow (Parallel)
  ├─ Phase 1: Research + Draft Framework
  ├─ Phase 2: Framework Review (Parallel)
  └─ Phase 3: Write Complete Chapters
  ↓
Step 5: Synthesis (Edit for coherence)
  ↓
Step 6: Final QA (LLM-as-Judge)
  ↓ (if fail)
Step 7: Iterative Refinement (optional)
  ↓
Step 8: Export to PDF with Preserved Links
  ├─ Create summary.md
  ├─ Run stitchmd to merge
  ├─ Convert to PDF with Pandoc
  └─ Generate links_inventory.md
```

**Total time**: 1-2+ hours (varies by chapter count and depth)

---

## Pre-Step: Determine Output Location

**Action**: Before starting research, ask user where to save the final report.

**Intelligent Recommendations**:
1. Analyze the research topic to suggest an appropriate directory name
2. Consider the research purpose (academic, business, technical, personal)
3. Propose a meaningful, timestamped folder name

**Directory Naming Convention**:
- Format: `research_YYYY-MM-DD_[topic-slug]`
- Topic slug: 2-4 words derived from research subject
- Examples:
  - "deep research AI agents 2025" → `research_2026-02-22_ai-agents-2025/`
  - "comprehensive study of microservices patterns" → `research_2026-02-22_microservices-patterns/`
  - "thorough analysis of Rust memory safety" → `research_2026-02-22_rust-memory-safety/`

**Ask User**:
```
Before starting the deep research, I need to know where to save the final report.

Based on your research topic "[topic]", I recommend:
📁 Suggested directory: [recommended_path]/[suggested_folder_name]/

Options:
1. Use recommended location
2. Choose a different directory
3. Specify custom path

Where would you like the research output to be saved?
```

**Default behavior**: If user doesn't specify, use `~/Research/[suggested_folder_name]/`

**Store the output path** for all subsequent file operations.

---

## Step 0: Exploratory Discovery (For Vague Queries)

**When**: User query is open-ended ("tell me about X", "investigate X", "explore X")

**Action**: Launch parallel discovery agents to map domain and generate research questions.

**Agent A - Domain Landscape Mapper**: Identify key themes, debates, gaps, perspectives, recent developments

**Agent B - Research Question Generator**: Generate 5-7 specific, actionable research questions

**Tool Requirements for Discovery Agents:**
- **PREFERRED:** Use `mcp__brave-search__brave_web_search` for web searches
- **PREFERRED:** Use `mcp__fetch__fetch` to fetch webpage content
- **FALLBACK:** Only use `WebSearch` or `mcp__web_reader__webReader` if MCP tools are unavailable

**Output**: Present findings with specific research angles. Ask user to select or proceed with comprehensive research.

---

## Step 1: Chapter Planning

**Action**: Launch chapter planning agent to decompose topic into 3-8 independent chapters.

**Requirements**:
- Each chapter = distinct research direction
- Define scope and boundaries for each
- Ensure chapters can be researched in parallel
- Output to `planning/chapter_plan.md`

**Confirm** chapter structure with user before proceeding.

---

## Step 2-4: Chapter Workflow (Parallel)

**For detailed prompts**, see `references/chapter-workflow.md`

### Phase 1: Research & Framework (Parallel)

Launch N chapter agents simultaneously. Each:
- Conducts deep research (8-15 sources)
- Saves all source materials to `sources/chapter_N/`
- Creates `sources_index.md`
- Drafts chapter framework to `chapters/N_framework_draft.md`

**Wait**: All frameworks complete before Phase 2.

### Phase 2: Framework Review (Parallel)

Launch N framework review agents simultaneously. Each:
- Reads draft framework and saved sources
- Conducts own research to validate
- Evaluates: scope completeness, balance, currency, depth, sources
- Modifies and improves framework
- Outputs to `chapters/N_framework_review.md`

**Key**: Reviewers actively improve frameworks, not just critique.

**Wait**: All reviews complete before Phase 3.

### Phase 3: Write Chapters (Parallel)

Relaunch N chapter agents simultaneously. Each:
- Reads framework review
- Conducts additional research if needed
- Writes complete chapter (2000-3000 words)
- Cites sources with local file references
- Outputs to `chapters/N_chapter_final.md`

---

## Step 5: Synthesis

**For detailed prompts**, see `references/synthesis.md`

**Action**: Launch synthesis agent to:

1. **Edit chapters for coherence**:
   - Add transitions between chapters
   - Resolve contradictions
   - Remove/reduce overlaps
   - Add cross-references

2. **Create supporting files**:
   - `synthesis/executive_summary_content.md`
   - `synthesis/conclusions_content.md`
   - `synthesis/navigation_content.md`
   - `sources/complete_sources_inventory.md`

3. **Create unified report**: `research_report.md` as main entry point

---

## Step 6: Final QA (LLM-as-Judge)

**For detailed methodology**, see `references/quality/qa-methodology.md`

**Action**: Two-stage quality evaluation

**Stage 1 - Consistency Check**: Rate on 5 dimensions (1-5 scale)
- Source Credibility
- Evidence Quality
- Analytical Rigor
- Completeness
- Attribution Accuracy

**Pass threshold**: Average ≥ 4.0/5.0

**Stage 2 - Pattern Analysis**: Check for systematic biases and gaps

**Output**: `final_qa/quality_assessment.md`

---

## Step 7: Iterative Refinement (Optional)

**For detailed methodology**, see `references/quality/self-refine.md`

**Trigger**: QA score < 4.0 OR user requests refinement

**Action**: Address weak dimensions
- Find additional authoritative sources
- Resolve contradictions
- Fill identified gaps
- Improve attribution

**Limit**: Max 2 refinement iterations

---

## Step 8: Export to PDF with Preserved Links

**Purpose**: Merge all Markdown files into a single PDF while preserving internal cross-references between chapters.

**Tool Selection**: After research, **stitchmd + Pandoc** was chosen over merge-markdown because:
- stitchmd specifically rewrites cross-file links like `[Chapter 2](chapter2.md)` to `[Chapter 2](#chapter-2)` based on headings
- More reliable anchor generation for PDF navigation
- Simpler workflow with better link preservation

### Step 8.1: Create Summary File

Create a `summary.md` file in the output directory that lists all chapters in order:

```markdown
# [Research Topic Title]

- [Chapter 1: Title](chapters/01_chapter_final.md)
- [Chapter 2: Title](chapters/02_chapter_final.md)
- [Chapter 3: Title](chapters/03_chapter_final.md)
... (and so on for all chapters)
```

### Step 8.2: Install Tools (if not already installed)

**macOS**:
```bash
# Install stitchmd
brew install abhinav/tap/stitchmd

# Install pandoc (usually pre-installed)
brew install pandoc

# Install MacTeX for PDF generation (includes pdflatex)
# Note: MacTeX is a large package (~4GB), installation takes several minutes
brew install --cask mactex-no-gui

# Or install BasicTeX (smaller, ~100MB)
brew install --cask basictex
# After BasicTeX install, run:
# eval "$(/usr/libexec/path_helper)"
```

**Alternative for Linux**:
```bash
# Install stitchmd via Go
go install go.abhg.dev/stitchmd@latest

# Install pandoc and LaTeX
sudo apt-get install pandoc texlive-full  # Ubuntu/Debian
```

**Quick test**:
```bash
# Check if tools are installed
which stitchmd
which pandoc
which pdflatex
```

### Step 8.3: Merge Markdown Files

```bash
# Navigate to research output directory
cd [output_directory]

# Merge all files using stitchmd
stitchmd summary.md -o merged.md
```

**What stitchmd does**:
- Combines all referenced Markdown files into one
- Rewrites cross-file links to internal anchors: `[Chapter 2](chapters/02_chapter_final.md)` → `[Chapter 2](#chapter-2)`
- Preserves relative image paths
- Generates table of contents

### Step 8.4: Convert to PDF

**Basic PDF conversion**:
```bash
# For English content
pandoc merged.md -o research_report.pdf

# For Chinese content (requires xelatex)
export PATH="/Library/TeX/texbin:$PATH"  # macOS: add TeX to PATH
pandoc merged.md -o research_report.pdf \
  --toc --toc-depth=2 \
  --pdf-engine=xelatex \
  -V geometry:margin=1in \
  -V CJKmainfont="PingFang SC" \
  -V mainfont="PingFang SC"
```

**With better formatting options**:
```bash
# English
pandoc merged.md \
  -o research_report.pdf \
  --pdf-engine=wkhtmltopdf \
  --toc \
  --toc-depth=3 \
  -V mainfont="Helvetica Neue" \
  -V sansfont="Helvetica" \
  -V geometry:margin=1in

# Chinese
pandoc merged.md \
  -o research_report.pdf \
  --toc --toc-depth=2 \
  --pdf-engine=xelatex \
  -V geometry:margin=1in \
  -V CJKmainfont="PingFang SC" \
  -V mainfont="PingFang SC"
```

**Note on clickable table of contents**:
By default, pandoc-generated PDFs may have non-clickable TOC. To enable clickable links, add the `colorlinks` variable:

```bash
# For clickable TOC (Chinese)
pandoc merged.md -o research_report.pdf \
  --toc --toc-depth=2 \
  --pdf-engine=xelatex \
  -V geometry:margin=1in \
  -V CJKmainfont="PingFang SC" \
  -V mainfont="PingFang SC" \
  --variable=colorlinks:true \
  --variable=linkcolor:blue \
  --variable=urlcolor:blue

# For clickable TOC (English)
pandoc merged.md -o research_report.pdf \
  --toc --toc-depth=3 \
  --variable=colorlinks:true
```

**Alternative: HTML version** (fully clickable, no font rendering issues):
```bash
pandoc merged.md -o research_report.html \
  --toc --toc-depth=2 \
  --standalone --self-contained
```

**Note on emoji/special characters**:
Some Unicode characters (✅, ❌, ⚠️) may not render properly in PDF. Consider:
- Replacing with text equivalents ([OK], [X], [WARNING])
- Using HTML version for full compatibility
- Filtering emoji before PDF conversion

### Step 8.5: Generate Links Inventory

Create a separate file documenting all internal links in the final PDF:

**File**: `links_inventory.md`

```markdown
# Links Inventory

This document lists all internal links in the final PDF for reference.

## Chapter Cross-References

| Source | Target | Description |
|--------|--------|-------------|
| [Chapter 1](#chapter-1-title) | Chapter 1 | Link to Chapter 1 |
| [Chapter 2](#chapter-2-title) | Chapter 2 | Link to Chapter 2 |
| ... | ... | ... |

## External Links (from sources)

| URL | Description |
|-----|-------------|
| https://example.com | Source 1 |
| https://another.com | Source 2 |
```

**How to generate**:
1. Extract all links from `merged.md` using grep/awk
2. Categorize into internal (anchors) vs external (http/https)
3. Create the inventory markdown table

### Step 8.6: Verify Links

Test that internal links work correctly in the PDF:
- Open the generated PDF
- Click on each internal link
- Verify they navigate to the correct section

---

## File Structure

All files are created under the user-specified output directory (determined in Pre-Step).

**Full path structure**: `[CATEGORY_DIR]/[TOPIC_DIR]/`

Where:
- `[CATEGORY_DIR]` = User-selected or recommended category directory (e.g., `~/Research/`, `~/Documents/Business/Research/`)
- `[TOPIC_DIR]` = Date-prefixed topic folder (e.g., `research_2026-02-22_ai-agents/`)

```
[CATEGORY_DIR]/                           # e.g., ~/Research/
└── [TOPIC_DIR]/                          # e.g., research_2026-02-22_ai-agents/
    ├── research_report.md                # Main entry point
    ├── research_report.pdf              # PDF export with preserved links
    ├── merged.md                        # Stitched markdown (from stitchmd)
    ├── summary.md                       # Summary file for stitchmd
    ├── links_inventory.md               # All links documentation
    ├── metadata.json                    # Research metadata
├── planning/
│   └── chapter_plan.md                  # Chapter structure
├── chapters/
│   ├── NN_framework_draft.md            # Original framework
│   ├── NN_framework_review.md           # Reviewed framework
│   └── NN_chapter_final.md              # Complete chapter
├── sources/                             # All source materials
│   ├── chapter_NN/
│   │   ├── source_XX_*
│   │   └── sources_index.md
│   └── complete_sources_inventory.md
├── synthesis/
│   ├── executive_summary_content.md
│   ├── conclusions_content.md
│   └── navigation_content.md
└── final_qa/
    ├── quality_assessment.md            # QA scores and findings
    └── refinement_log.md                # If refinement occurred
```

**For detailed format specifications**, see `references/formats.md`

---

## Tool Usage Strategy

**Tool Priority:** PREFERRED MCP tools → FALLBACK to built-in tools if unavailable

### Main Orchestrator
- **AskUserQuestion**: (Pre-Step) Ask for output directory, confirm chapter plan, QA results
- **Task**: Launch all sub-agents
- **Write**: Create initial directory structure at user-specified location
- **Read**: Access all files for coordination

### Chapter Agents (Phase 1 - Research & Framework)
- **PREFERRED:** `mcp__brave-search__brave_web_search` for web searches
- **PREFERRED:** `mcp__fetch__fetch` to extract and save webpage content
- **PREFERRED:** `mcp__playwright__*` for browser automation if needed
- **FALLBACK:** `WebSearch` or `mcp__web_reader__webReader` only if MCP tools unavailable
- **Write**: Save sources, index, framework

### Framework Review Agents
- **PREFERRED:** `mcp__brave-search__brave_web_search` for web searches
- **PREFERRED:** `mcp__fetch__fetch` to read and extract webpage content
- **PREFERRED:** `mcp__playwright__*` for browser automation if needed
- **FALLBACK:** `WebSearch` or `mcp__web_reader__webReader` only if MCP tools unavailable
- **Write/Read/Edit**: Save sources, update index, read framework

### Chapter Agents (Phase 2 - Writing)
- **Read**: Access framework review, saved sources
- **PREFERRED:** `mcp__brave-search__brave_web_search` to fill gaps
- **PREFERRED:** `mcp__fetch__fetch` to extract content if needed
- **FALLBACK:** `WebSearch` or `mcp__web_reader__webReader` only if MCP tools unavailable
- **Write**: Write complete chapter

### Synthesis Agent
- **Read**: All chapters, source indexes
- **Edit**: Edit chapters for coherence
- **Write**: Create supporting files, research_report.md

### QA Agents
- **Read**: All chapters
- **Write**: Create quality assessment

### Sub-Agent Tool Guidance

All sub-agent prompts in `references/chapter-workflow.md` include tool priority guidance:
- **PREFERRED:** `mcp__brave-search__*`, `mcp__fetch__*`, `mcp__playwright__*`, `mcp__context7__*`
- **FALLBACK:** Built-in tools (`WebSearch`, `mcp__web_reader__webReader`) only if MCP tools unavailable

---

## Progressive Disclosure

**Detailed implementation references** (load as needed):

- **Chapter workflow**: `references/chapter-workflow.md` - Phase 1-3 detailed prompts
- **Synthesis**: `references/synthesis.md` - Coherence editing and report integration
- **Quality methodology**: `references/quality/qa-methodology.md` - LLM-as-judge evaluation
- **Refinement**: `references/quality/self-refine.md` - Iterative improvement patterns
- **Output formats**: `references/formats.md` - All file format specifications

---

## Tips

**Output location recommendations:**
- For academic research: `~/Research/` or `~/Documents/Research/`
- For business/competitive analysis: `~/Documents/Business/Research/` or project-specific folder
- For technical learning: `~/Documents/Learning/[topic]/`
- For personal interest: `~/Documents/Research/` or `~/Desktop/`
- Default fallback: `~/Research/`

**Quality indicators:**
- QA score ≥ 4.5/5.0: Excellent, ready for critical decisions
- QA score 4.0-4.5/5.0: Good, sufficient for most purposes
- QA score < 4.0/5.0: Requires refinement

**Source archiving benefits:**
- Full traceability - every claim can be verified
- Offline access - all materials saved locally
- Reusable knowledge base - sources available for future research
- Transparency - readers can access original materials

**Iteration best practices:**
- Max 2 refinement loops
- Each iteration must show measurable improvement
- Stop when user satisfied or quality plateaus
