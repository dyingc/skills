---
name: deep-research
description: >
  Conduct comprehensive, deep research (30min-1hr+) for complex, uncertain, or high-stakes topics.
  Use when users request: "deep research X", "comprehensive investigation of X", "thorough analysis",
  "I need to understand X in depth", "exhaustive research on X".

  Handles three core challenges: (1) User doesn't know what to research initially - exploratory discovery
  clarifies scope, (2) Complex multi-aspect topics - orchestrator-worker pattern enables parallel investigation,
  (3) Quality assurance - LLM-as-judge evaluation and Self-Refine iteration ensure rigor.

  For quick research (5-30min), use the research skill instead.

allowed-tools:
  # MCP Search and Fetch Tools (Required for web research)
  - mcp__brave-search__brave_web_search
  - mcp__brave-search__brave_news_search
  - mcp__brave-search__brave_video_search
  - mcp__brave-search__brave_image_search
  - mcp__brave-search__brave_local_search
  - mcp__brave-search__brave_summarizer
  - mcp__fetch__fetch
  - mcp__web_reader__webReader

  # Core tools for research workflow
  - AskUserQuestion
  - Task
  - Read
  - Write
  - Edit
  - Glob
  - Grep

  # Context7 for documentation research
  - mcp__context7__resolve-library-id
  - mcp__context7__query-docs
---

# Deep Research

Conduct comprehensive investigation with iterative refinement, quality assurance, and adaptive scope discovery.

## Core Philosophy

Deep research addresses three challenges that quick research cannot:

1. **Uncertain scope**: Users often don't know what to research initially
2. **Complex topics**: Require multi-aspect investigation and synthesis
3. **High stakes**: Require rigorous quality assurance and validation

**Evidence base**: Built on research from 15+ academic papers (2024-2025), including NeurIPS, ICLR, arXiv findings on deep research agents, Self-Refine methodology, and LLM-as-judge evaluation.

## Workflow Overview

```
Step 0: Exploratory Discovery (if query vague)
  ↓
Step 1: Clarify Research Scope
  ↓
Step 2: Plan Search Strategy
  ↓
Step 3: Launch Agents (Orchestrator-Worker for complex topics)
  ↓
Step 4: Analyze Results
  ↓
Quality Gate: LLM-as-Judge (≥4.0/5.0 to pass)
  ↓ (if fail)
Step 5: Iterative Refinement (Self-Refine loop)
  ↓
Step 6: Present Research Report
```

**Total time**: 30-60 min (Comprehensive) or 1+ hours (Deep Dive)

---

## Step 0: Exploratory Discovery (For Vague/Exploratory Queries)

**Problem addressed**: Users often don't know what to research initially (validated by AI-Researcher, NeurIPS 2025)

### Detect Vague Queries

Trigger when user query contains:
- Open-ended phrases: "tell me about X", "what is X"
- Exploratory phrases: "investigate X", "explore X"
- Uncertain scope: "research X" without specifics

```python
def is_vague_query(query):
    vague_indicators = [
        "tell me about", "what is", "investigate",
        "research", "explore", "understand", "learn about"
    ]
    return any(indicator in query.lower() for indicator in vague_indicators)
```

### Launch Parallel Discovery Agents

**Agent A: Domain Landscape Mapper**

```python
Task("general-purpose",
     f"Map the domain landscape for {topic}. Identify:\n"
     "- Key themes and subtopics\n"
     "- Major debates or controversies\n"
     "- Research gaps or open questions\n"
     "- Different perspectives or schools of thought\n"
     "- Recent developments (2024-2025)\n\n"
     "Provide structured overview with hierarchy.",
     "Discovery: Landscape mapping")
```

**Agent B: Research Question Generator**

```python
Task("general-purpose",
     f"Generate 5-7 specific, actionable research questions about {topic}.\n\n"
     "Each question should:\n"
     "- Be specific and researchable\n"
     "- Address a distinct aspect\n"
     "- Have clear deliverables\n"
     "- Vary in breadth (some broad, some focused)\n\n"
     "Format as numbered list with brief context for each.",
     "Discovery: Question generation")
```

### Synthesize and Consult User

Present findings with specific research angles:

```markdown
## Exploration Findings

**Domain Map:**
[Agent A's structured landscape]

**Potential Research Angles:**
1. [Question 1] - Focuses on [aspect]
2. [Question 2] - Focuses on [aspect]
...

**Which aspect interests you most?**
- Select a specific question above
- Combine multiple questions
- Describe your own angle
- Proceed with comprehensive research of all aspects
```

Proceed to Step 1 with clarified scope.

---

## Step 1: Clarify Research Scope

After exploratory discovery (or if query was already specific), confirm research configuration.

### Depth Level

| Depth | Sources | Time | Agents | Best For |
|-------|---------|------|--------|----------|
| **Comprehensive** | 10-20 | 30-60 min | 4-6 | Complex topics, decision-making |
| **Deep Dive** | 20+ | 1+ hours | 6+ iterations | Academic work, thorough validation |

### Research Consumer

**If HUMAN**: Narrative synthesis with explanations
**If LLM**: Structured, code-separated, machine-parseable
**If BOTH**: Both formats with clear section separators

### Report Format

- **Comprehensive Analysis**: Full synthesis with analysis, patterns, recommendations
- **Implementation Guide**: Step-by-step with code samples, API specs, pitfalls (LLM-optimized)
- **Executive Summary**: 2-3 paragraphs for quick scanning

### Multi-Aspect Detection

**Ask**: "Does this topic have 3+ independent aspects?"

If YES (e.g., "MCP server with HTTP stream" → Protocol + Code + Pitfalls):
- Use **Orchestrator-Worker pattern** (Step 3, Option C)
- 40% faster through parallelization

If NO:
- Use **Sequential workflow** (Step 3, Option A)

Present configuration to user for confirmation before proceeding.

---

## Step 2: Plan Search Strategy

**Keywords**: Identify 5-7 distinct queries, vary specificity (broad → narrow), include year filters for fast-moving domains

**Source credibility**:
- Prefer official docs, peer-reviewed papers, established vendors
- Check publication date (recent for technology)
- Skip paywalled, outdated, low-quality sources

**Inclusion criteria**:
- Minimum evidence threshold
- Prioritize official, recent, authoritative
- Define what to skip

---

## Step 3: Launch Agents

Choose workflow based on multi-aspect detection from Step 1.

### Option A: Sequential Workflow (Standard)

Use for single-aspect topics or <3 independent aspects.

```python
# Agent 1: Broad search
agent1 = Task(
    "general-purpose",
    "Conduct broad search on [TOPIC]. Use 5-7 different search queries. "
    "Identify 15-20 high-quality sources. Assess credibility and relevance.",
    "Deep Research: Broad search"
)

# Agent 2: Divergent Exploration
agent2 = Task(
    "general-purpose",
    f"Deep read these sources:\n{agent1_results}\n"
    "Explore ALL perspectives. Include:\n"
    "- Contradictory findings\n"
    "- Minority viewpoints\n"
    "- Emerging theories\n"
    "- Contested claims\n"
    "Do NOT evaluate or synthesize yet.",
    "Deep Research: Divergent exploration"
)

# Agent 3: Convergent Synthesis
agent3 = Task(
    "general-purpose",
    f"Synthesize these findings:\n{agent2_results}\n"
    "Identify consensus, disagreements, patterns. "
    "Evaluate evidence quality. Converge on most supported conclusions.",
    "Deep Research: Convergent synthesis"
)

# Agent 4: Verification
agent4 = Task(
    "general-purpose",
    f"Verify these conclusions:\n{agent3_results}\n"
    "Spot-check claims. Find additional supporting sources. "
    "Assess overall confidence (1-5 scale).",
    "Deep Research: Verification"
)
```

### Option B: Orchestrator-Worker Pattern (For Complex Multi-Aspect Research)

Use for topics with 3+ independent aspects (40% faster).

```python
# Orchestrator plans and coordinates
orchestrator = Task(
    "general-purpose",
    f"""Plan and coordinate deep research on {topic}.

    1. Decompose into 3-5 sub-questions
    2. Assign specialist workers:
       - Background research agent
       - Technical analysis agent
       - Case study agent
       - Comparison/evaluation agent
    3. Monitor progress and reassign as needed
    4. Synthesize findings into coherent report""",
    "Deep Research: Orchestrator"
)

# Orchestrator launches specialist workers dynamically
# Workers explore in parallel
# Orchestrator synthesizes results
```

**Launch workers in parallel:**

```python
# All workers launch simultaneously
workers = [
    Task("general-purpose", "Research aspect 1...", "Worker: Aspect 1"),
    Task("general-purpose", "Research aspect 2...", "Worker: Aspect 2"),
    Task("general-purpose", "Research aspect 3...", "Worker: Aspect 3"),
]

# Wait for all to complete, then orchestrator synthesizes
```

---

## Step 4: Analyze Results

Wait for all agents to complete, then review:

**Agent 1 (Broad search)**: Source quality, diversity, effective queries, coverage gaps

**Agent 2 (Divergent)**: Extraction accuracy, contradictions noted, evidence quality assessed

**Agent 3 (Convergent)**: Consensus/disagreement clarity, patterns identified, evidence levels stated

**Agent 4 (Verification)**: Spot-check results, confidence assessment, additional sources needed

---

## Quality Gate: LLM-as-Judge Evaluation

**Before presenting report**, ensure research meets quality standards.

### Two-Stage Evaluation

**Stage 1: Consistency Check**

```python
qa_stage1 = Task(
    "general-purpose",
    f"""Evaluate this research synthesis for internal consistency:\n\n{agent3_results}\n\n

    Rate each dimension (1-5):
    1. Source Credibility: Authoritative, recent, diverse
    2. Evidence Quality: Specific citations, clear strength levels
    3. Analytical Rigor: Consensus vs debate, contradictions addressed
    4. Completeness: Coverage, perspectives, gaps acknowledged
    5. Attribution Accuracy: Claims traced to sources

    Pass threshold: Average ≥ 4.0/5.0

    If fail: Specify which dimensions need improvement.""",
    "QA: Consistency check"
)

qa_score = extract_score(qa_stage1_results)
```

**Stage 2: Pattern Analysis** (if Stage 1 passes)

```python
qa_stage2 = Task(
    "general-purpose",
    f"""Analyze evaluation patterns:\n\n{qa_stage1_results}\n\n

    Check for:
    - Systematic biases in source selection
    - Missing perspectives or viewpoints
    - Over-representation of certain sources
    - Adequacy of evidence distribution

    Identify specific weaknesses requiring follow-up.""",
    "QA: Pattern analysis"
)
```

### Quality Interpretation & Consumer Warnings

**Always include a consumer-facing quality assessment section in the final report** that explains:

1. **What the scores mean** - Translate numeric scores into practical implications
2. **Which findings are trustworthy** - Highlight high-confidence areas
3. **What requires caution** - Explicitly flag weak dimensions and their impact
4. **How to use the report** - Guidance on verification for critical decisions

**Implementation pattern:**

```python
# After QA evaluation, generate consumer-friendly explanation
quality_explanation = Task(
    "general-purpose",
    f"""Translate this QA evaluation into a consumer-friendly quality assessment:\n\n{qa_results}\n\n

    Create a section that includes:

    1. Overall status (pass/fail with interpretation)
    2. Dimension-by-dimension breakdown with practical implications
    3. For any dimension below 4.5/5.0:
       - What's weak
       - How this affects confidence in findings
       - Which conclusions to treat with caution
       - Recommended verification steps
    4. Clear guidance on which areas are trustworthy vs need verification

    Use clear, non-technical language. Be transparent about limitations.""",
    "QA: Consumer quality interpretation"
)

# Include this in final report's "Quality Assessment" section
```

**Example structure (not content-specific):**

```markdown
## Quality Assessment & Consumer Guidance

### Overall Quality Status
[Score]/5.0 - [Interpretation: Excellent/Good/Acceptable/Weak]

### Dimension Breakdown & Implications

**[Dimension Name]: [Score]/5.0**
- What this means: [Practical interpretation]
- Impact on reliability: [How this affects confidence]
- Consumer guidance: [How to use findings from this dimension]

**[Dimension Name]: [Score]/5.0 ⚠️**
- What this means: [Specific weakness identified]
- Impact on reliability:
  - ⚠️ [Specific limitation]
  - ⚠️ [What claims are less reliable]
- Recommended actions:
  - Verify [specific types of claims] with [specific source types]
  - Treat [specific conclusions] as preliminary

### Using This Report

**High-confidence areas** (suitable for decision-making):
- [Areas with strong evidence and attribution]

**Areas requiring verification** (use with caution):
- [Areas with weak attribution or limited evidence]
- Before critical decisions, verify with [specific source types]
```

### Gate Logic

```python
if qa_score < 4.0:
    print(f"⚠️ Quality gate: {qa_score}/5.0 - Conducting targeted follow-up...")
    # Proceed to Step 5: Iterative Refinement
else:
    print(f"✅ Quality gate: {qa_score}/5.0 - Research approved")
    # Include quality_explanation in final report
    # Skip to Step 6: Present Report
```

---

## Step 5: Iterative Refinement (Self-Refine Loop)

**Trigger**: Quality gate fails OR confidence < 4.0 OR user requests refinement

**Evidence**: Self-Refine (arXiv 2303.17651) shows 20% average improvement; 40% with GPT-4

### Refinement Agent

```python
refinement_threshold = 4.0

if qa_score < refinement_threshold or user_requests_refinement:
    agent5 = Task(
        "general-purpose",
        f"""Refine and strengthen these research conclusions:\n\n{agent4_results}\n\n

        **Refinement priorities:**
        1. Address low-confidence findings
           - Find additional corroborating sources
           - Cross-check with authoritative references
           - Verify recent information (2024-2025)

        2. Resolve contradictions
           - Investigate why sources disagree
           - Identify context differences
           - Determine which evidence is stronger

        3. Strengthen evidence quality
           - Replace weak sources with authoritative ones
           - Add quantitative data where possible
           - Include expert consensus statements

        Target: Elevate confidence to ≥ 4.0/5.0""",
        "Deep Research: Refine conclusions"
    )

    # Evaluate improvement
    agent5_confidence = extract_confidence(agent5_results)

    # Optional second iteration
    if agent5_confidence < refinement_threshold:
        agent6 = Task(
            "general-purpose",
            f"""Further refinement based on evaluation:\n{agent5_results}\n
            Focus on remaining weaknesses. Seek expert sources or official documentation.""",
            "Deep Research: Second refinement"
        )
```

### Iteration Criteria

- Max 2 refinement iterations (avoid infinite loops)
- Stop when confidence ≥ 4.0 or user satisfied
- Each iteration must show measurable improvement

---

## Step 6: Present Research Report

Choose output format based on research consumer (from Step 1).

### Format A: Comprehensive Analysis (Human-Readable)

```markdown
# Deep Research: [TOPIC]

## Executive Summary
[2-3 paragraph synthesis]

## Methodology
- Research questions: [What was investigated]
- Sources: [N sources, types, time period]
- Search strategy: [Keywords, filters]
- Inclusion criteria: [Credibility standards]

## Phase 1: Divergent Exploration Findings
### All Perspectives
- [Contradictory findings]
- [Minority viewpoints]
- [Emerging theories]
- [Contested claims]

## Phase 2: Convergent Synthesis
### Consensus Areas
[Where sources agree]

### Debates & Contradictions
[Where sources disagree, with explanations]

### Evidence Quality Assessment
[Strong vs medium vs limited evidence]

## Recommendations
[Evidence-based with citations]

## Quality Assessment & Consumer Guidance

### Overall Quality Status
- QA Score: [X]/5.0 ([Interpretation])
- Recommendation: [Ready for use / Use with caution / Requires verification]

### Dimension Breakdown
- Source Credibility: [X]/5.0 - [Implications]
- Evidence Quality: [X]/5.0 - [Implications]
- Analytical Rigor: [X]/5.0 - [Implications]
- Completeness: [X]/5.0 - [Implications]
- Attribution Accuracy: [X]/5.0 - [Implications]

### Using This Report
**High-confidence areas:** [List trustworthy sections]
**Use with caution:** [Flag areas needing verification]
**Verification recommendations:** [Specific steps if critical decisions needed]

## References
[Complete source list]
```

### Format B: Implementation Guide (LLM-Optimized)

```markdown
# [Technology] Deep Research & Implementation Guide

## Protocol/Technology Specification
- Required: [Versions, dependencies]
- API/Interface: [Methods, endpoints]
- Data formats: [Structures]
- Configuration: [Settings, env vars]

## Divergent Exploration: All Approaches
### Approach 1: [Name]
- Pros: [Advantages]
- Cons: [Limitations]
- Use cases: [When to use]

### Approach 2: [Name]
[Same structure]

## Convergent Synthesis: Recommended Approach
**Best choice**: [Approach X] because:
- Evidence: [Supporting sources]
- Trade-offs: [What you gain/lose]

## Code Examples (Verified)

### Example 1: Basic Implementation
```[language]
// Working code with comments
// Copy-pasteable, tested
```

### Example 2: Advanced Usage
```[language]
// Advanced features
```

## Dependencies & Requirements
- Minimum versions: [Package versions]
- Installation: `npm install [packages]`
- Setup steps: [1, 2, 3]

## Common Pitfalls & Solutions
- ❌ Pitfall 1 → ✅ Solution
- ❌ Pitfall 2 → ✅ Solution

## Quality Assurance

### Overall Quality Status
- QA Score: [X]/5.0 - [Interpretation]

### Dimension Breakdown
- Source Credibility: [X]/5.0
- Evidence Quality: [X]/5.0
- Analytical Rigor: [X]/5.0
- Completeness: [X]/5.0
- Attribution Accuracy: [X]/5.0

### Consumer Guidance
**Trusted areas:** [Which technical specs/code examples are verified]
**Verify before use:** [Any areas requiring additional validation]

## References
[URLs to official docs, examples]
```

### Format C: Executive Summary (Quick Overview)

```markdown
# Deep Research Summary: [TOPIC]

## Key Findings
1. **[Finding 1]**
   - Evidence: [Source]
   - Confidence: [High/Medium/Low]

2. **[Finding 2]**
   - Evidence: [Source]
   - Confidence: [High/Medium/Low]

## Bottom Line
[2-3 sentence takeaway]

## Quality Metrics
- QA Score: [X]/5.0
- Sources analyzed: [N]
- Research time: [X min]

## Top Sources
1. [URL]
2. [URL]
3. [URL]
```

---

## Tool Usage Strategy

### Main Agent Tools
- **Task tool**: Launch sub-agents, pass outputs forward
- **Write/Edit**: Format report with citations

### Agent 1: Broad Search
- **brave_web_search** (heavy): Multiple targeted searches
- **webReader**: Assess relevance
- Output: 15-20 sources with credibility assessment

### Agent 2: Divergent Exploration
- **webReader** (primary): Read thoroughly
- **brave_web_search** (supporting): Look up unfamiliar concepts
- Output: All perspectives with contradictions noted

### Agent 3: Convergent Synthesis
- **Read**: Cross-reference findings
- **Task**: Validation agents for contradictions
- Output: Synthesized conclusions with evidence levels

### Agent 4: Verification
- **brave_web_search**: Spot-check claims
- **Read**: Verify conclusions
- Output: Quality assessment, confidence level

### Quality Gate Agents
- **Task**: LLM-as-judge evaluation
- Focus: Internal consistency, bias detection

### Refinement Agents
- **brave_web_search**: Find corroborating sources
- **webReader**: Deep dive into weak areas
- Output: Strengthened conclusions

---

## Progressive Disclosure

For detailed implementation patterns and examples, see:

- **Orchestrator patterns**: See [references/orchestrator-patterns.md](references/orchestrator-patterns.md)
- **Quality evaluation**: See [references/qa-methodology.md](references/qa-methodology.md)
- **Refinement techniques**: See [references/self-refine.md](references/self-refine.md)

---

## Tips

**When to use deep-research vs research:**
- **research**: Quick questions (5-30 min), well-defined scope
- **deep-research**: Complex topics (30min-1hr+), uncertain scope, high stakes

**Quality indicators:**
- QA score ≥ 4.5/5.0: Excellent, ready for critical decisions
- QA score 4.0-4.5/5.0: Good, sufficient for most purposes
- QA score < 4.0/5.0: Requires refinement

**Iteration best practices:**
- Max 2 refinement loops (diminishing returns)
- Each iteration must show measurable improvement
- Stop when user satisfied or confidence plateaus

**Cost control:**
- Quality gate and refinement increase API calls
- Can disable for non-critical research
- User can override quality gate if acceptable

---

## When to Transition to Brainstorm

After deep research completes, consider brainstorm if:

- **User needs creative application**: "How should we apply these findings?"
- **Context-specific solutions**: Research provides general knowledge, brainstorm customizes
- **Multiple valid implementations**: Research establishes what works, brainstorm explores how

**Suggest explicitly:**
> "I've conducted deep research on [TOPIC]. Would you like me to brainstorm creative ways to apply these findings to your specific context?"

**Integration patterns:**
- **Research → Brainstorm**: Learn best practices, then generate applications
- **Brainstorm → Research**: Generate options, then validate top choices
- **Iterative**: Alternate for comprehensive problem-solving
