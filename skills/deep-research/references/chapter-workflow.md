# Chapter Workflow: Research, Framework Review, and Writing

This reference contains detailed prompts for the three-phase chapter workflow.

## Phase 1: Research and Framework Drafting

Each chapter agent conducts deep research and drafts a framework.

### Chapter Agent Prompt (Phase 1)

````python
agent = Task(
    "general-purpose",
    f"""You are Chapter Agent {i} for: {chapter_title}

**Your Chapter:** {chapter_info[i]}

**Phase 1: Research and Framework Drafting**

1. **Conduct deep research** on this chapter's topic
   - Use 5-7 different search queries
   - Find 8-15 high-quality sources
   - Prioritize: official docs, peer-reviewed papers, recent sources (2024-2025)

2. **Save source materials** to `sources/chapter_{i:02d}/`
   For each valuable source:
   - If webpage: Save HTML to `source_XX_webpage.html`
   - If PDF: Download to `source_XX_pdf/`
   - If data/API: Save to `source_XX_data.json`
   - Extract key content to `source_XX_content.md`
   - Save all URLs for citation

3. **Create source index** at `sources/chapter_{i:02d}/sources_index.md`

**Source index format:**
```markdown
# Sources for Chapter {i}

## Source 1: [Title]
- **Type:** [PDF/Webpage/API/Video]
- **URL:** [Original URL]
- **Saved to:** `source_01_*`
- **Date:** [Date accessed]
- **Credibility:** [High/Medium/Low] - [Brief justification]
- **Relevance:** [How this will be used in the chapter]
```

4. **Draft chapter framework** including:
   - Main research questions this chapter will answer
   - Sub-topics to cover (with brief descriptions)
   - Expected depth for each sub-topic
   - Key sources you'll use
   - Proposed chapter structure

**Output framework to:** `chapters/{i:02d}_framework_draft.md`

**Framework format:**
```markdown
# Chapter {i}: {chapter_title}

## Research Questions
- [Main question 1]
- [Main question 2]

## Sub-Topics to Cover
1. [Sub-topic 1] - [Description + expected depth: Comprehensive/Overview]
2. [Sub-topic 2] - [Description + expected depth]

## Key Sources
- [Source 1 - from sources_index]
- [Source 2]

## Proposed Structure
### Section 1: [Title]
- [What this covers, key arguments to make]

### Section 2: [Title]
- [What this covers]

## Expected Deliverables
- [What this chapter will deliver]
```

**Quality requirements for this phase:**
- Find diverse, authoritative sources (not all from same domain)
- Save all source materials locally
- Create comprehensive source index
- Draft clear, well-structured framework
- Ensure framework scope matches chapter boundaries from plan

**After completing this phase, wait for framework review before proceeding to writing.**""",
    f"Chapter {i}: Research and Framework"
)
````


## Phase 2: Framework Review

Each framework review agent evaluates and improves the framework through their own research.

### Framework Review Agent Prompt

````python
reviewer = Task(
    "general-purpose",
    f"""You are the Framework Review Agent for Chapter {i}: {chapter_title}

**Your Task:** Review and improve the chapter framework through your own research.

**Process:**

1. **Read the draft framework:** `chapters/{i:02d}_framework_draft.md`

2. **Review saved sources:** `sources/chapter_{i:02d}/sources_index.md`
   - Read key content files to assess quality
   - Check source recency and authority
   - Identify gaps in source coverage

3. **Conduct your own research:**
   - Search for recent developments (2024-2025)
   - Find aspects the framework missed
   - Check if proposed sources are still current
   - Look for alternative perspectives not included
   - **Save new sources** to `sources/chapter_{i:02d}/source_XX_*`
   - **Update sources_index.md** if new sources added

4. **Evaluate the framework on five dimensions:**

   **Scope completeness:**
   - Are there missing critical aspects?
   - Are the boundaries clear and appropriate?
   - Does it align with the chapter's role in the overall plan?

   **Balance:**
   - Are sub-topics weighted appropriately?
   - Is depth distributed well across topics?
   - Any topics over- or under-emphasized?

   **Currency:**
   - Is coverage up-to-date?
   - Any recent developments missed?
   - Are sources current for fast-moving topics?

   **Depth:**
   - Is proposed depth sufficient for deep research?
   - Any topics too shallow for the stated goals?

   **Sources:**
   - Are sources authoritative and diverse?
   - Enough sources for comprehensive coverage?
   - Any obvious gaps in source types?

5. **Modify the framework** based on findings:
   - Add missing sub-topics with rationale
   - Adjust priorities/focus where needed
   - Suggest better or additional sources
   - Remove outdated or less relevant areas
   - Restructure if needed for clarity

**Output to:** `chapters/{i:02d}_framework_review.md`

**Output format:**
```markdown
# Framework Review: Chapter {i}

## Summary
[Brief overview: Framework approved as-is / Minor revisions suggested / Major revisions needed]

## Modifications Made

### Added Sub-Topics
1. [New sub-topic] - **Rationale:** [Why this is critical for comprehensive coverage]

### Adjusted Focus
- **Original:** [topic description] → **Revised:** [new description]
  - **Rationale:** [Why this change improves the chapter]

### Source Recommendations
- **Add:** [New source] - **Rationale:** [What it adds]
- **Replace:** [Old source] → [New source] - **Rationale:** [Why the change]
- **Remove:** [Source] - **Rationale:** [Why not essential]

### Removed Areas
- [Removed topic] - **Rationale:** [Why not essential or out of scope]

## Research Guidance
[Any specific areas needing additional research when writing]

## Revised Framework

[Complete, revised framework for the chapter agent to use]
Include: research questions, sub-topics, key sources, structure

## Updated Source Index
[Updated sources_index.md content if new sources were added]
```

**Important:** You are not just critiquing - you are actively improving the framework through your own research and expertise. The chapter agent will use your revised framework as the basis for writing. Be constructive and specific.""",
    f"Framework Review: Chapter {i}"
)
````


## Phase 3: Chapter Writing

After framework review, chapter agents write complete chapters.

### Chapter Agent Prompt (Phase 2)

````python
writer = Task(
    "general-purpose",
    f"""You are Chapter Agent {i}. Write the complete chapter based on the reviewed framework.

**Your Chapter:** {chapter_title}

**Process:**

1. **Read the framework review:** `chapters/{i:02d}_framework_review.md`
   - Understand all modifications made by reviewer
   - Read the rationale for each change
   - Use the "Revised Framework" as your guide
   - Note any "Research Guidance" from reviewer

2. **Conduct any additional research** based on review feedback
   - Fill gaps identified by reviewer
   - Find sources recommended by reviewer
   - Investigate areas marked for additional research
   - **Save new sources** and update `sources_index.md`

3. **Write the complete chapter** (2000-3000 words)
   - Use the revised framework structure
   - Incorporate all reviewer feedback
   - Cite sources with local file references
   - Ensure depth and rigor throughout

**Output to:** `chapters/{i:02d}_chapter_final.md`

**Chapter format:**
```markdown
# Chapter {i}: {chapter_title}

## Introduction
[Set context for this chapter]
[Outline what this chapter covers]
[Preview key findings]
[Connect to previous chapter if applicable]

## [Section 1 Title]
[Deep analysis with evidence and citations]
> Source: [[1]](../sources/chapter_{i:02d}/source_01_content.md)
> Full source: `sources/chapter_{i:02d}/source_01_pdf/`

[Include multiple perspectives, data, examples]
[Acknowledge limitations where applicable]

## [Section 2 Title]
[Continue with thorough coverage]
[Ensure each major claim is supported]
[Use local file references for all sources]

...

## Chapter Conclusions
[Synthesize key findings from this chapter]
[Answer the research questions posed in framework]
[Connect to next chapter if applicable]

## References

### Direct Citations
[1] [Author/Organization] - [Title] - [Year]
    `sources/chapter_{i:02d}/source_01_content.md`

[2] [Source details]
    `sources/chapter_{i:02d}/source_02_pdf/`

### Complete Source Index
See: `sources/chapter_{i:02d}/sources_index.md`
```

**Quality requirements:**
- Use 10-15 high-quality sources
- Every major claim must be cited with local reference
- Include multiple perspectives on debated topics
- Acknowledge limitations explicitly
- Balance depth with readability
- Use local file references for all sources (not just URLs)
- Ensure content matches the revised framework
- Address all research guidance from reviewer""",
    f"Chapter {i}: Writing"
)
````


## Workflow Coordination

### Launch Pattern

````python
# Phase 1: Launch all chapter agents in parallel
chapter_agents = []
for i in range(1, num_chapters + 1):
    agent = Task("general-purpose", chapter_agent_prompt_i, f"Chapter {i}: Research and Framework")
    chapter_agents.append(agent)

# Wait for all frameworks to complete
wait_for_all(chapter_agents)

# Phase 2: Launch all framework reviewers in parallel
review_agents = []
for i in range(1, num_chapters + 1):
    reviewer = Task("general-purpose", framework_review_prompt_i, f"Framework Review: Chapter {i}")
    review_agents.append(reviewer)

# Wait for all reviews to complete
wait_for_all(review_agents)

# Phase 3: Launch all chapter writers in parallel
writing_agents = []
for i in range(1, num_chapters + 1):
    writer = Task("general-purpose", chapter_writing_prompt_i, f"Chapter {i}: Writing")
    writing_agents.append(writer)
````

### File Dependencies

Each phase depends on outputs from previous phase:

- **Phase 1 produces:** `chapters/{N}_framework_draft.md`, `sources/chapter_{N}/`
- **Phase 2 reads:** `chapters/{N}_framework_draft.md`, `sources/chapter_{N}/sources_index.md`
- **Phase 2 produces:** `chapters/{N}_framework_review.md`, updated `sources/chapter_{N}/`
- **Phase 3 reads:** `chapters/{N}_framework_review.md`, `sources/chapter_{N}/`
- **Phase 3 produces:** `chapters/{N}_chapter_final.md`
