---
name: research
description: >
  Conduct systematic research and comprehensive knowledge synthesis on any topic. Use when users request
  investigation, literature review, evidence gathering, or authoritative information synthesis. Follows
  methodical search strategies with source validation, cross-referencing, and proper attribution.

  Trigger when users say: "research this", "what does the literature say", "find authoritative sources",
  "investigate", "comprehensive overview", "systematic review", "what's the evidence for", "deep dive into",
  "what are best practices for", "how does X work", "compare X vs Y", "teach me about".

  Prioritizes depth, accuracy, source quality, and rigorous synthesis over creative exploration.
  For idea generation and diverse perspective exploration, use the brainstorm skill instead.

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

# Research

Conduct systematic investigation and synthesize verified knowledge from authoritative sources.

## Workflow

### 1. Clarify Research Scope

**Ask user these questions to determine research approach:**

---

#### A. Research Type (Auto-Detect or Confirm)

**Detection cues:**

| User Request Pattern | Research Type |
|---------------------|---------------|
| "how to implement/build/code/write" | **Coding/Technical** |
| "how does X work internally" | **Coding/Technical** |
| "best practices for X technology" | **Coding/Technical** |
| "compare X vs Y technologies" | **Coding/Technical** |
| "implement X protocol" | **Coding/Technical** |
| "what does research say about X" | **General/Geopolitical** |
| "compare countries/policies" | **General/Geopolitical** |
| "investigate [topic]" | **Context-dependent** |

**If Coding/Technical research:**
- Source priorities: Official docs, GitHub repos, API specs, Stack Overflow
- Verification method: Test code examples, verify against docs
- Output format: Implementation guide, code samples, API specs
- Currency critical: Last updated date matters more than publication date

**If General/Geopolitical research:**
- Source priorities: Government reports, think tanks, academic papers, reputable news
- Verification method: Cross-check multiple sources
- Output format: Narrative synthesis with citations
- Credibility criteria: Institutional authority, peer review

---

#### B. Research Consumer

**"Who will consume this research?"**

**If HUMAN reader:**
- Output format: Narrative, contextual, readable
- Emphasis: Synthesis, trade-offs, explanations, background
- Structure: Executive summary → Key findings → Analysis → Recommendations
- References: Embedded in narrative with URLs

**If LLM (for coding plans, implementation, etc.):**
- Output format: Structured, code-separated, minimal narrative
- Emphasis: Working code examples, API specs, implementation steps
- Structure: Protocol spec → Code samples → Dependencies → Pitfalls → Examples
- No fluff: Actionable information only, machine-parseable

**If BOTH:**
- Provide both human-readable summary AND LLM-consumable technical details
- Use clear section separators for parsing

---

#### C. Depth Level & Time Investment

**"请选择研究深度：" / "Select research depth:"**

| Depth | Sources | Time | Agents | Best For |
|-------|---------|------|--------|----------|
| **快速概览 / Quick** | 2-3 | 5-10 min | 2 | Simple questions, tight deadlines |
| **标准研究 / Standard** | 5-10 | 15-30 min | 3 | Typical research, decision-making |
| **全面深入 / Comprehensive** | 10-20 | 30-60 min | 4 | High-stakes, complex topics |
| **深度探索 / Deep Dive** | 20+ | 1+ hours | 4+ iterations | Academic work, thorough validation |

**Time breakdown:**
- Quick: Agent 1 (broad search, 3 min) + Agent 2 (synthesis, 5 min) = 8 min
- Standard: Agent 1 (5 min) + Agent 2 (deep read, 10 min) + Agent 3 (synthesis, 8 min) = 23 min
- Comprehensive: All 4 agents, ~45 min total

**Progress updates:**
- After Agent 1: "✅ Found X sources → Starting deep analysis..."
- After Agent 2: "✅ Analyzed X sources → Starting synthesis..."
- After Agent 3: "✅ Synthesis complete → Starting verification..."
- After Agent 4: "✅ Verification complete → Generating report..."

---

#### D. Research Language

**"研究语言 / Research language:"**

- **English only**: Search English sources, English report
- **Chinese only**: 搜索中文来源, 中文报告
- **Both (Recommended for comparisons)**: Search both languages, report in user's preferred language

**For China-US comparisons or cross-cultural topics:** Recommend "Both"

---

#### E. Report Format

**"报告格式 / Report format:"**

| Format | Description | Best For |
|--------|-------------|----------|
| **执行摘要 / Executive Summary** | 2-3 paragraphs, key findings only | Quick updates, status checks |
| **标准报告 / Standard** ← Default | Summary + Key findings + References | Most use cases |
| **全面报告 / Comprehensive** | Full synthesis with analysis, patterns, recommendations | Decision-making, thorough understanding |
| **代码指南 / Implementation Guide** (Coding only) | Step-by-step with code samples, API specs, pitfalls | LLM consumption, coding tasks |
| **简报幻灯片 / Slides** | Bullet points, structured sections | Presentations, quick scanning |

---

#### F. Multi-Aspect Detection (For Parallel Workflow)

**Ask: "Does this topic have multiple independent aspects?"**

**Examples of multi-aspect topics:**
- Coding: "MCP server with HTTP stream" → Protocol spec + Code examples + Pitfalls (3 aspects)
- Technology: "Compare PostgreSQL vs MongoDB" → Performance + Features + Use cases (3 aspects)
- Implementation: "Deploy microservices on AWS" → Architecture + Security + Cost (3 aspects)

**If YES and 3+ aspects:**
- Use **parallel workflow** (40% faster)
- Phase 1: Launch 3 agents simultaneously (one per aspect)
- Phase 2: Launch 3 verification agents simultaneously
- Phase 3: 1 synthesis agent combines results
- Total time: ~18-20 min vs 30 min sequential

**If NO or <3 aspects:**
- Use **sequential workflow** (standard)

---

#### G. Confirm Before Proceeding

**Present configuration to user:**

```
Research Configuration:
- Type: [Coding/General]
- Consumer: [Human/LLM]
- Depth: [Quick/Standard/Comprehensive]
- Language: [EN/CN/Both]
- Format: [Summary/Standard/Comprehensive/Code Guide]
- Workflow: [Sequential/Parallel]
- Estimated time: [X min]

Proceed? (Adjust any settings if needed)
```

Proceed to Step 2 with user confirmation.

### 2. Plan Search Strategy

Define your approach before launching agents:

**Keywords and queries:**
- Identify 3-5 distinct search queries
- Vary specificity (broad → narrow)
- Include year filters for fast-moving domains (e.g., "2024 OR 2025")

**Source credibility criteria:**
- Prefer official documentation over tutorials
- Prefer peer-reviewed papers over blog posts
- Prefer established vendors/organizations over unknown sources
- Check publication date (prefer recent sources, especially for technology)

**Inclusion/exclusion criteria:**
- What sources to skip (paywalled, outdated, low quality)
- What sources to prioritize (official, recent, authoritative)
- Minimum evidence threshold

### 3. Launch Agents

**Choose workflow based on multi-aspect detection from Step 1:**

---

#### Option A: Sequential Workflow (Standard)

**Use for:** Single-aspect topics, general research, or <3 independent aspects

**Launch agents sequentially, passing outputs forward:**

```python
# Agent 1: Broad search
agent1 = Task(
    "general-purpose",
    "Conduct broad search on [TOPIC]. Use 3-5 different search queries. "
    "Identify 10-15 high-quality sources. Assess credibility and relevance.",
    "Research: Broad search"
)

# Agent 2: Deep analysis (can see agent1's output)
agent2 = Task(
    "general-purpose",
    f"Deep read these sources:\n{agent1_results}\n"
    "Extract key findings, evidence, quotes. Note contradictions. "
    "Assess evidence quality.",
    "Research: Deep analysis"
)

# Agent 3: Synthesis (can see agent2's output)
agent3 = Task(
    "general-purpose",
    f"Synthesize these findings:\n{agent2_results}\n"
    "Identify consensus, disagreements, patterns. Assess evidence quality.",
    "Research: Synthesis"
)

# Agent 4: Verification (optional, can see agent3's output)
agent4 = Task(
    "general-purpose",
    f"Verify these conclusions:\n{agent3_results}\n"
    "Spot-check claims. Find additional supporting sources. "
    "Assess overall confidence.",
    "Research: Verification"
)
```

**Important:**
- Each agent builds on previous agent's work
- Launch sequentially (wait for each to complete before next)
- Use clear, focused descriptions for each agent
- Adjust agent count based on depth level (2-4 agents)

---

#### Option B: Parallel Workflow (For Multi-Aspect Coding/Technical Research)

**Use for:** Topics with 3+ independent aspects (e.g., protocol spec + code examples + pitfalls)

**Launch parallel agents in phases, 40% faster overall:**

**Phase 1: Parallel Aspect-Specific Research (simultaneous launch)**

```python
# All three launch at the same time
agent1a = Task(
    "general-purpose",
    "Research [ASPECT 1] of [TOPIC]. "
    "Focus on: [specific aspect focus]. "
    "Find authoritative sources, extract key information.",
    "Research: [Aspect 1]"
)

agent1b = Task(
    "general-purpose",
    "Research [ASPECT 2] of [TOPIC]. "
    "Focus on: [specific aspect focus]. "
    "Find authoritative sources, extract key information.",
    "Research: [Aspect 2]"
)

agent1c = Task(
    "general-purpose",
    "Research [ASPECT 3] of [TOPIC]. "
    "Focus on: [specific aspect focus]. "
    "Find authoritative sources, extract key information.",
    "Research: [Aspect 3]"
)

# Wait for all three to complete, then proceed to Phase 2
```

**Phase 2: Parallel Verification (simultaneous launch)**

```python
# All three launch at the same time, each verifying one aspect
agent2a = Task(
    "general-purpose",
    f"Verify [ASPECT 1] findings:\n{agent1a_results}\n"
    "Cross-check with additional sources. Test code if applicable. "
    "Confirm accuracy and completeness.",
    "Research: Verify [Aspect 1]"
)

agent2b = Task(
    "general-purpose",
    f"Verify [ASPECT 2] findings:\n{agent1b_results}\n"
    "Cross-check with additional sources. Test code if applicable. "
    "Confirm accuracy and completeness.",
    "Research: Verify [Aspect 2]"
)

agent2c = Task(
    "general-purpose",
    f"Verify [ASPECT 3] findings:\n{agent1c_results}\n"
    "Cross-check with additional sources. Test code if applicable. "
    "Confirm accuracy and completeness.",
    "Research: Verify [Aspect 3]"
)

# Wait for all three to complete, then proceed to Phase 3
```

**Phase 3: Synthesis (single agent)**

```python
agent3 = Task(
    "general-purpose",
    f"Combine all verified findings:\n\n"
    f"Aspect 1: {agent2a_results}\n\n"
    f"Aspect 2: {agent2b_results}\n\n"
    f"Aspect 3: {agent2c_results}\n\n"
    "Create integrated implementation guide with all aspects.",
    "Research: Synthesize all aspects"
)
```

**Example: MCP Server with HTTP Stream**

**Phase 1 (Parallel):**
- Agent 1A: Protocol specification (SSE format, headers, handshake)
- Agent 1B: Working code examples (GitHub repos, tutorials, samples)
- Agent 1C: Common pitfalls (Stack Overflow, GitHub issues, errors)

**Phase 2 (Parallel):**
- Agent 2A: Verify spec against official docs
- Agent 2B: Test code samples, verify they work
- Agent 2C: Cross-check pitfalls against multiple sources

**Phase 3:**
- Agent 3: Combine into step-by-step implementation guide

**Total time:** ~18-20 min (vs 30 min sequential)

**Parallel workflow advantages:**
- 40% faster for multi-aspect topics
- Each agent specializes in one aspect
- No redundancy in source searching
- Verification is aspect-specific

**When to use parallel:**
- Coding research with 3+ technical aspects
- Technology comparisons (performance + features + cost)
- Implementation guides (architecture + security + deployment)

**When to use sequential:**
- General/geopolitical research
- Single-aspect deep dives
- Topics requiring cumulative understanding

### 4. Analyze Results

Wait for all agents to complete, then review:

**Agent 1 (Broad search):**
- Review source list for quality and diversity
- Check if search queries were effective
- Identify gaps in coverage

**Agent 2 (Deep analysis):**
- Verify findings were extracted accurately
- Check that contradictions were noted
- Ensure evidence quality was assessed

**Agent 3 (Synthesis):**
- Confirm consensus/disagreement is clear
- Check that patterns were identified
- Verify evidence levels are stated

**Agent 4 (Verification) - if used:**
- Review spot-check results
- Consider confidence assessment
- Decide if additional sources are needed

### 5. Present Research Report

**Choose output format based on:**
- Research consumer (Human vs LLM)
- Research type (Coding vs General)
- Report format selection from Step 1

---

#### Format A: Standard Research Report (Human-Readable, General Research)

```markdown
# Research: [TOPIC]

## Executive Summary
[2-3 paragraph synthesis of key findings]

## Methodology
- **Research questions**: [What was investigated]
- **Sources consulted**: [N sources from X type]
- **Search strategy**: [Keywords, queries, filters]
- **Time period**: [e.g., "Sources from 2024-2025"]
- **Inclusion criteria**: [What qualified as credible]

## Key Findings

### Finding 1: [Claim]
- **Evidence**: [Specific sources with links]
- **Strength**: [Strong/Medium/Limited]
- **Context**: [Caveats, limitations, scope]
- **Consensus**: [Widely accepted / Debated / Emerging]

### Finding 2: [Claim]
[Follow same structure]

## Synthesis & Analysis

### Consensus Areas
- [Points where sources agree]

### Debates & Contradictions
- [Points where sources disagree, with explanations]

### Knowledge Gaps
- [What wasn't addressed or needs more research]

### Patterns Across Sources
- [Recurring themes, approaches, recommendations]

## Recommendations
[Evidence-based suggestions with source citations]

## References
[Complete source list with URLs]
```

---

#### Format B: Implementation Guide (LLM-Optimized, Coding Research)

```markdown
# [Technology/Protocol] Implementation Guide

## Protocol/Technology Specification
- **Required**: [Version requirements, dependencies]
- **API/Interface**: [Method signatures, endpoints]
- **Data formats**: [Request/response structures]
- **Configuration**: [Required settings, environment variables]

## Code Examples (Verified Working)

### Example 1: Basic Setup
```[language]
// [Working code with comments]
// [Copy-pasteable, tested]
```

### Example 2: Advanced Usage
```[language]
// [Working code showing advanced features]
```

## Dependencies & Requirements
- **Minimum versions**: [Package versions, language requirements]
- **Installation**: `npm install [packages]` or equivalent
- **Setup steps**:
  1. [Step 1]
  2. [Step 2]
  3. [Step 3]

## Common Pitfalls & Solutions
- ❌ **Pitfall 1**: [What goes wrong]
  - ✅ **Solution**: [How to fix/prevent]
- ❌ **Pitfall 2**: [What goes wrong]
  - ✅ **Solution**: [How to fix/prevent]

## Verified Working Examples
- **Source 1**: [URL to working repo/example]
  - Status: ✅ Tested / ⚠️ Partially tested
  - Notes: [Any issues or workarounds]
- **Source 2**: [URL to working repo/example]
  - Status: ✅ Tested
  - Notes: [Clean implementation]

## API Reference
- **Method**: `[METHOD_NAME]`
  - Parameters: [Type and description]
  - Returns: [Type and description]
  - Errors: [Common error codes and meanings]

## Troubleshooting
| Error/Symptom | Cause | Solution |
|---------------|-------|----------|
| [Error message] | [Root cause] | [Fix steps] |
| [Symptom] | [Root cause] | [Fix steps] |

## References & Further Reading
- **Official docs**: [URL]
- **Best practices**: [URL]
- **Community resources**: [URLs]
```

---

#### Format C: Executive Summary (Quick Overview)

```markdown
# Research Summary: [TOPIC]

## Key Findings
1. **[Finding 1]**: [1-2 sentence summary]
   - Evidence: [Source]
   - Confidence: [High/Medium/Low]

2. **[Finding 2]**: [1-2 sentence summary]
   - Evidence: [Source]
   - Confidence: [High/Medium/Low]

3. **[Finding 3]**: [1-2 sentence summary]
   - Evidence: [Source]
   - Confidence: [High/Medium/Low]

## Bottom Line
[2-3 sentence takeaway or recommendation]

## Top Sources
1. [Source 1 with URL]
2. [Source 2 with URL]
3. [Source 3 with URL]
```

---

#### Format D: Slides / Bullet Points (Presentation Format)

```markdown
# [TOPIC]: Research Findings

## Overview
• [Key point 1]
• [Key point 2]
• [Key point 3]

## Key Findings

### Finding 1: [Title]
• **Evidence**: [Source]
• **Impact**: [Why it matters]
• **Confidence**: [High/Medium/Low]

### Finding 2: [Title]
• **Evidence**: [Source]
• **Impact**: [Why it matters]
• **Confidence**: [High/Medium/Low]

## Recommendations
1. [Recommendation 1]
   - Rationale: [Why]
   - Priority: [High/Medium/Low]

2. [Recommendation 2]
   - Rationale: [Why]
   - Priority: [High/Medium/Low]

## Next Steps
• [Action 1]
• [Action 2]
• [Action 3]
```

---

#### Format E: Comprehensive Analysis (Deep Dive)

[Use Format A structure plus:]

```markdown
## Detailed Analysis

### Comparative Analysis
| Aspect | Option A | Option B | Recommendation |
|--------|----------|----------|----------------|
| [Criteria 1] | [Details] | [Details] | [Which & why] |
| [Criteria 2] | [Details] | [Details] | [Which & why] |

### Timeline Analysis
- **Past**: [Historical context]
- **Present**: [Current state]
- **Near-term (1-2 yrs)**: [Projected developments]
- **Long-term (3-5 yrs)**: [Projected developments]

### Stakeholder Perspectives
- **Perspective A**: [Viewpoint with supporting sources]
- **Perspective B**: [Viewpoint with supporting sources]
- **Areas of agreement**: [Where they align]
- **Areas of disagreement**: [Where they differ]

### Risk Assessment
| Risk | Probability | Impact | Mitigation |
|------|-------------|--------|------------|
| [Risk 1] | [High/Med/Low] | [High/Med/Low] | [Strategy] |
| [Risk 2] | [High/Med/Low] | [High/Med/Low] | [Strategy] |
```

---

**Format selection guide:**

| Consumer | Research Type | Recommended Format |
|----------|--------------|-------------------|
| Human | General | Standard or Comprehensive |
| Human | Coding | Implementation Guide |
| LLM | General | Standard (structured) or Slides |
| LLM | Coding | Implementation Guide (LLM-optimized) |
| Both | Any | Standard + Implementation sections |
| Quick update | Any | Executive Summary |

**Bilingual reporting:**
If language = "Both", present sections in user's preferred language with key terms in original language when relevant.

## Tool Usage Strategy

### Main Agent Tools
- **Task tool** (primary): Launch sequential sub-agents, passing outputs forward
- **Write/Edit**: Format research report with proper citations

### Agent 1: Broad Search Tools
- **mcp__brave-search__brave_web_search** (heavy): Multiple targeted searches with different keywords
- **mcp__web_reader__webReader**: Fetch full articles to assess relevance
- **Goal**: Identify 10-15 high-quality sources
- **Output**: Source list with URLs, credibility assessment, brief descriptions

**Example queries:**
```
- "[TOPIC] best practices 2025"
- "[TOPIC] vs [ALTERNATIVE] comparison"
- "[TOPIC] case studies benchmarks"
- "[TOPIC] official documentation"
```

### Agent 2: Deep Analysis Tools
- **mcp__web_reader__webReader** (primary): Read full sources thoroughly
- **Read**: Analyze documentation or reference materials
- **mcp__brave-search__brave_web_search** (supporting): Look up unfamiliar concepts, find related sources
- **Goal**: Extract key findings, evidence, contradictions
- **Output**: Detailed findings with quotes, evidence quality assessment

**Reading strategy:**
- Extract main claims and supporting evidence
- Note publication date and author credibility
- Identify limitations and caveats
- Mark contradictions between sources

### Agent 3: Synthesis Tools
- **Read** (moderate): Cross-reference findings across sources
- **Task** (optional): Launch validation agents for contradictory claims
- **Goal**: Identify consensus, disagreements, patterns
- **Output**: Synthesized conclusions with evidence levels

**Synthesis approach:**
- Group findings by theme
- Identify where sources agree (consensus)
- Note where sources disagree (debates)
- Assess evidence quality for each claim
- Flag areas needing more research

### Agent 4: Verification Tools (Optional)
- **mcp__brave-search__brave_web_search**: Spot-check claims, find additional supporting sources
- **Read**: Verify accuracy of synthesized conclusions
- **Goal**: Validate claims, triangulate sources
- **Output**: Quality assessment, confidence levels

**Verification checks:**
- Spot-check 2-3 key claims
- Find corroborating sources
- Verify recent information (especially for fast-moving topics)
- Assess overall confidence level

### Tool Emphasis
- **Depth over diversity**: Thorough investigation of fewer sources
- **Rigor over speed**: Systematic, methodical approach
- **Sources over examples**: Authoritative documentation over blog posts
- **Attribution over creativity**: Every claim traced to sources
- **Sequential building**: Each agent extends previous agent's work

## Tips

**Research depth vs speed:**
- **Quick overview**: 2 agents (broad search + synthesis), 5-10 minutes
- **Standard research**: 3 agents (search + analysis + synthesis), 15-30 minutes
- **Comprehensive**: 4 agents (all phases), 30-60 minutes
- **Deep dive**: 4 agents + iterative follow-up searches

**Source quality assessment:**
- **Official sources**: Documentation, RFCs, specifications (high credibility)
- **Academic**: Peer-reviewed papers, arXiv preprints (high credibility)
- **Industry**: Vendor blogs, case studies (medium-high credibility)
- **Community**: Stack Overflow, Reddit (low-medium credibility, use sparingly)

**When to use verification agent:**
- High-stakes decisions (security, architecture, technology selection)
- Contradictory findings across sources
- Fast-moving domains (AI, web frameworks)
- User requests additional validation

**Effective search strategies:**
- Start broad, then narrow down
- Use year filters for technology topics (e.g., "2024 OR 2025")
- Include "vs" comparisons for technology selection
- Add "case study" or "benchmark" for real-world data
- Use "best practices" or "tutorial" for implementation guidance

**Synthesis quality:**
- Always distinguish between consensus and debate
- State evidence quality (strong/medium/limited)
- Acknowledge limitations and knowledge gaps
- Provide specific citations, not general references
- Flag outdated or potentially incorrect information

## When to Transition to Brainstorm

After research completes, consider transitioning to brainstorm if:

- **User needs creative application**: "How should we apply these findings?"
- **Context-specific solutions**: Research provides general knowledge, brainstorm customizes it
- **Multiple valid implementations**: Research establishes what works, brainstorm explores how to implement
- **User request shifts**: "Generate ideas for using X", "What are different approaches to Y"

**Suggest brainstorm explicitly:**
> "I've researched best practices for [TOPIC]. Would you like me to brainstorm creative ways to apply these findings to your specific context?"

**Integration patterns:**
- **Research → Brainstorm**: Learn best practices, then generate creative applications
- **Brainstorm → Research**: Generate options, then validate top choices
- **Iterative**: Alternate between both for comprehensive problem-solving
