# Orchestrator-Worker Patterns for Deep Research

This reference provides detailed implementation patterns for the orchestrator-worker workflow used in deep-research for complex, multi-aspect topics.

## Overview

The orchestrator-worker pattern addresses complex research topics with 3+ independent aspects by:
1. Decomposing the topic into sub-questions
2. Assigning specialist workers to explore each aspect in parallel
3. Dynamically coordinating based on findings
4. Synthesizing results into a coherent report

**Performance**: 40% faster than sequential workflow for multi-aspect topics (validated by Anthropic, 2025)

## When to Use Orchestrator-Worker

### Indicators

Use this pattern when ALL of the following apply:
- Topic has 3+ independent aspects
- Aspects can be researched in parallel
- Total research time ≥ 30 minutes
- User wants comprehensive coverage

### Examples

**Good fit:**
- "MCP server with HTTP stream" → Protocol + Code examples + Pitfalls
- "Compare PostgreSQL vs MongoDB" → Performance + Features + Use cases
- "Deploy microservices on AWS" → Architecture + Security + Cost

**Poor fit:**
- Single-aspect deep dive
- Sequential dependency (aspect B requires aspect A)
- Quick research (<15 min)

## Implementation Pattern

### Phase 1: Orchestrator Planning

```python
orchestrator = Task(
    "general-purpose",
    f"""Plan and coordinate deep research on {topic}.

    **Your role:**
    1. Analyze the topic and decompose into 3-5 independent sub-questions
    2. For each sub-question, define:
       - Specific research objective
       - Required expertise type
       - Expected deliverables
    3. Assign specialist workers with clear task descriptions
    4. Set coordination checkpoints

    **Output format:**
    ## Research Plan
    ### Sub-question 1: [Title]
    - Objective: [What this worker will find]
    - Expertise: [Background/Technical/Case study/Comparison]
    - Deliverables: [Specific outputs]

    ### Sub-question 2: [Title]
    [Same structure]

    ## Coordination Strategy
    - Checkpoints: [When to review progress]
    - Dependencies: [Any sequential requirements]
    - Synthesis approach: [How to combine results]""",
    "Deep Research: Orchestrator planning"
)
```

### Phase 2: Parallel Worker Launch

**Launch all workers simultaneously:**

```python
workers = []

# Worker 1: Background research
workers.append(Task(
    "general-purpose",
    f"Research background context for {aspect_1}. Focus on:\n"
    "- Historical development\n"
    "- Current state (2024-2025)\n"
    "- Key concepts and terminology\n"
    "- Major stakeholders or communities",
    "Worker: Background research"
))

# Worker 2: Technical analysis
workers.append(Task(
    "general-purpose",
    f"Conduct technical analysis of {aspect_2}. Focus on:\n"
    "- Technical specifications\n"
    "- Implementation details\n"
    "- Performance characteristics\n"
    "- Technical trade-offs",
    "Worker: Technical analysis"
))

# Worker 3: Case studies
workers.append(Task(
    "general-purpose",
    f"Find and analyze case studies for {aspect_3}. Focus on:\n"
    "- Real-world implementations\n"
    "- Success stories and failures\n"
    "- Lessons learned\n"
    "- Best practices",
    "Worker: Case studies"
))

# Worker 4: Comparison/evaluation (if applicable)
workers.append(Task(
    "general-purpose",
    f"Compare and evaluate options for {aspect_4}. Focus on:\n"
    "- Comparative analysis\n"
    "- Pros and cons of each approach\n"
    "- Decision criteria\n"
    "- Recommendations with evidence",
    "Worker: Comparison"
))

# Wait for all workers to complete
worker_results = await_all(workers)
```

### Phase 3: Orchestrator Synthesis

```python
synthesizer = Task(
    "general-purpose",
    f"""Synthesize these parallel research findings into a coherent report:\n\n
    **Worker 1 (Background):** {worker_results[0]}\n\n
    **Worker 2 (Technical):** {worker_results[1]}\n\n
    **Worker 3 (Case Studies):** {worker_results[2]}\n\n
    **Worker 4 (Comparison):** {worker_results[3]}\n\n

    **Synthesis tasks:**
    1. Identify connections and patterns across aspects
    2. Resolve any contradictions between workers
    3. Create unified narrative
    4. Highlight key insights from each aspect
    5. Provide integrated recommendations

    **Output structure:**
    - Executive Summary (integrating all aspects)
    - Detailed Findings by Aspect
    - Cross-Aspect Patterns and Insights
    - Integrated Recommendations
    - Quality Assessment""",
    "Deep Research: Orchestrator synthesis"
)
```

## Worker Specialization Patterns

### Background Research Worker

**Focus**: Context, history, definitions, stakeholders

**Search queries**:
- "[topic] history development"
- "[topic] overview 2024 2025"
- "[topic] key concepts terminology"
- "[topic] major players companies"

**Deliverables**:
- Timeline of development
- Key concepts with definitions
- Current state overview
- Stakeholder landscape

### Technical Analysis Worker

**Focus**: Specifications, implementation, performance

**Search queries**:
- "[topic] technical specifications"
- "[topic] implementation guide"
- "[topic] performance benchmarks"
- "[topic] architecture patterns"

**Deliverables**:
- Technical specifications
- Implementation approaches
- Performance data
- Technical trade-offs

### Case Study Worker

**Focus**: Real-world examples, lessons learned

**Search queries**:
- "[topic] case studies"
- "[topic] success stories"
- "[topic] implementation examples"
- "[topic] lessons learned"

**Deliverables**:
- Curated case studies
- Success factors
- Common pitfalls
- Best practices

### Comparison Worker

**Focus**: Comparative analysis, recommendations

**Search queries**:
- "[option A] vs [option B] comparison"
- "[topic] comparison criteria"
- "[topic] pros and cons"
- "[topic] decision framework"

**Deliverables**:
- Comparison matrix
- Evaluation criteria
- Pros/cons analysis
- Recommendations with evidence

## Coordination Checkpoints

### Checkpoint 1: Initial Review (After planning)

**Questions:**
- Are sub-questions truly independent?
- Is coverage comprehensive?
- Are deliverables well-defined?

**Action**: Adjust worker assignments if needed

### Checkpoint 2: Mid-Research (Optional, for long-running tasks)

**Questions:**
- Are workers making progress?
- Any gaps or overlaps emerging?
- Need to redirect any workers?

**Action**: Reassign or refine worker tasks

### Checkpoint 3: Pre-Synthesis (After workers complete)

**Questions:**
- Are all worker outputs high quality?
- Any contradictions to resolve?
- Missing information?

**Action**: Launch targeted follow-up if needed

## Dynamic Reassignment

### When to Reassign

- Worker finding conflicts with another worker's findings
- Worker discovers aspect needs different expertise
- Worker completes early and can help elsewhere

### Reassignment Pattern

```python
# If Worker 2 discovers technical aspect needs more background
additional_task = Task(
    "general-purpose",
    f"Worker 2 found this technical gap: {gap_description}\n"
    f"Conduct targeted background research to fill this gap.",
    "Worker: Supplemental background"
)
```

## Quality Assurance for Orchestrator-Worker

### Pre-Synthesis Quality Check

```python
qa_check = Task(
    "general-purpose",
    f"""Review these worker outputs for quality:\n\n{worker_results}\n\n

    **Check for each worker:**
    1. Completeness: Addressed assigned objective?
    2. Accuracy: Claims supported by sources?
    3. Credibility: Sources authoritative and recent?
    4. Clarity: Findings clearly communicated?

    **Check across workers:**
    1. Consistency: Any contradictions?
    2. Coverage: All aspects adequately covered?
    3. Integration: How do findings relate?

    **Output:** Pass/Fail for each worker + overall synthesis readiness""",
    "QA: Worker output quality"
)
```

## Common Pitfalls

### Pitfall 1: Over-Decomposition

**Problem**: Too many sub-questions (6+), creates coordination overhead

**Solution**: Limit to 3-5 sub-questions, group related aspects

### Pitfall 2: False Parallelism

**Problem**: Aspects marked independent but actually have dependencies

**Solution**: Verify true independence before parallel launch

### Pitfall 3: Uneven Worker Outputs

**Problem**: Some workers produce comprehensive findings, others minimal

**Solution**: Clear task descriptions with specific deliverables

### Pitfall 4: Synthesis Challenges

**Problem**: Difficulty integrating disparate worker outputs

**Solution**: Orchestrator defines synthesis approach upfront

## Example: Complete Orchestrator-Worker Flow

**Topic**: "Implementing MCP servers with HTTP streaming"

### Orchestrator Planning Output

```markdown
## Research Plan

### Sub-question 1: SSE Protocol Specification
- Objective: Understand Server-Sent Events protocol for HTTP streaming
- Expertise: Technical analysis
- Deliverables: Protocol spec, headers, handshake format

### Sub-question 2: Code Examples and Patterns
- Objective: Find working MCP server implementations with HTTP streaming
- Expertise: Case studies + Technical
- Deliverables: Curated code examples, repository links

### Sub-question 3: Common Pitfalls and Solutions
- Objective: Identify implementation challenges and their solutions
- Expertise: Community knowledge (Stack Overflow, issues)
- Deliverables: Pitfall list with solutions

## Coordination Strategy
- Checkpoints: Pre-synthesis quality review
- Dependencies: None (truly parallel)
- Synthesis: Create implementation guide integrating spec + examples + pitfalls
```

### Worker Outputs (Simulated)

**Worker 1 (Protocol)**: SSE format, headers, event types, reconnection strategies

**Worker 2 (Code)**: 5 GitHub repos with MCP + SSE implementations

**Worker 3 (Pitfalls)**: CORS issues, buffering, connection drops, browser compatibility

### Synthesis Output

```markdown
# MCP Server with HTTP Streaming: Implementation Guide

## Executive Summary
[Protocol specs] + [Working code patterns] + [Pitfall avoidance]

## Protocol Specification
[From Worker 1]

## Code Examples (Verified)
[From Worker 2, with protocol context from Worker 1]

## Common Pitfalls and Solutions
[From Worker 3, with technical explanations from Worker 1]
```

## Performance Metrics

**Expected improvement vs sequential:**
- Time savings: 40% (parallelization)
- Quality: Same or better (specialized workers)
- Coverage: More comprehensive (dedicated workers per aspect)

**When sequential is better:**
- <3 aspects
- Strong dependencies between aspects
- Total time <15 minutes

## References

1. Anthropic Multi-Agent Research System (official blog, 2025)
2. Multi-Agent Collaboration via Evolving Orchestration (arXiv 2505.19591)
3. Agentic AI Frameworks (arXiv 2508.10146)
