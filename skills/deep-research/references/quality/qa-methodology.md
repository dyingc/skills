# LLM-as-Judge Quality Assurance Methodology

This reference provides detailed implementation guidance for the two-stage quality evaluation used in deep-research.

## Overview

LLM-as-Judge evaluation uses a language model to assess research quality before presentation. This approach achieves 85% agreement with human evaluators (Agent-as-a-Judge, arXiv 2508.02994).

### Two-Stage Process

1. **Stage 1: Consistency Check** - Internal quality assessment (5 dimensions, 1-5 scale)
2. **Stage 2: Pattern Analysis** - Bias detection and systematic issues

**Pass threshold**: Average ≥ 4.0/5.0 across all dimensions

## Stage 1: Consistency Check

### Evaluation Dimensions

#### 1. Source Credibility (1-5 scale)

**5 (Excellent)**:
- All sources from authoritative venues (official docs, peer-reviewed papers, established vendors)
- Recent sources for fast-moving topics (2024-2025)
- Diverse, independent sources (not all from same author/organization)

**4 (Good)**:
- Mostly authoritative sources with some reputable blogs
- Generally recent with 1-2 older sources
- Adequate diversity

**3 (Acceptable)**:
- Mix of credible and less-credible sources
- Some outdated sources
- Limited diversity

**2 (Weak)**:
- Many blog posts or community sources
- Outdated sources dominate
- Limited source diversity

**1 (Poor)**:
- Predominantly low-credibility sources
- Outdated or irrelevant
- Single source or echo chamber

#### 2. Evidence Quality (1-5 scale)

**5 (Excellent)**:
- Every claim backed by specific citations
- Clear distinction between strong/medium/limited evidence
- Quantitative data included where applicable
- Acknowledges limitations

**4 (Good)**:
- Most claims cited
- Evidence levels mostly clear
- Some quantitative data
- Some limitations acknowledged

**3 (Acceptable)**:
- Many claims cited but some unsupported
- Evidence levels sometimes unclear
- Limited quantitative data
- Few limitations acknowledged

**2 (Weak)**:
- Many uncited claims
- Evidence quality rarely specified
- Little quantitative data
- Limitations not acknowledged

**1 (Poor)**:
- Most claims uncited
- No evidence quality distinction
- Anecdotal only
- No limitations acknowledged

#### 3. Analytical Rigor (1-5 scale)

**5 (Excellent)**:
- Clear distinction between consensus and debate
- Contradictions investigated and explained
- Patterns and trends identified
- Multiple perspectives represented

**4 (Good)**:
- Consensus and debate generally clear
- Contradictions noted
- Some patterns identified
- Multiple perspectives present

**3 (Acceptable)**:
- Consensus vs debate sometimes unclear
- Contradictions noted but not explained
- Few patterns identified
- Limited perspective diversity

**2 (Weak)**:
- Consensus/debate not clearly distinguished
- Contradictions rarely noted
- No pattern identification
- Limited perspectives

**1 (Poor)**:
- No distinction between consensus/debate
- Contradictions ignored
- No synthesis
- Single perspective

#### 4. Completeness (1-5 scale)

**5 (Excellent)**:
- All key aspects covered comprehensively
- Multiple perspectives on each aspect
- Knowledge gaps explicitly acknowledged
- Follow-up research suggested

**4 (Good)**:
- Most key aspects covered
- Multiple perspectives on most aspects
- Some gaps acknowledged
- Limited follow-up suggestions

**3 (Acceptable)**:
- Main aspects covered
- Some perspectives represented
- Gaps rarely acknowledged
- No follow-up suggestions

**2 (Weak)**:
- Key aspects missing
- Limited perspectives
- Gaps not acknowledged
- No follow-up

**1 (Poor)**:
- Major aspects missing
- Single perspective
- No gap acknowledgement
- Incomplete coverage

#### 5. Attribution Accuracy (1-5 scale)

**5 (Excellent)**:
- Every claim traceable to specific source
- Proper citation format throughout
- No unsupported assertions
- Direct quotes attributed

**4 (Good)**:
- Most claims traceable
- Generally proper citations
- Few unsupported assertions
- Quotes mostly attributed

**3 (Acceptable)**:
- Many claims traceable, some not
- Citation format inconsistent
- Some unsupported assertions
- Some quotes unattributed

**2 (Weak)**:
- Few claims traceable
- Citations inconsistent or missing
- Many unsupported assertions
- Quotes rarely attributed

**1 (Poor)**:
- Claims not traceable
- No proper citations
- Frequent unsupported assertions
- No attribution

### Stage 1 Implementation

```python
qa_stage1 = Task(
    "general-purpose",
    f"""Evaluate this research synthesis for quality and readiness:\n\n{research_synthesis}\n\n

    **Rate each dimension (1-5 scale):**

    1. **Source Credibility**
       - 5: All authoritative, recent, diverse
       - 4: Mostly authoritative with some blogs
       - 3: Mix of credible and less-credible
       - 2: Many low-credibility sources
       - 1: Predominantly unreliable

    2. **Evidence Quality**
       - 5: All claims cited, clear evidence levels
       - 4: Most cited, levels mostly clear
       - 3: Many cited, levels sometimes unclear
       - 2: Few claims cited
       - 1: Most claims uncited

    3. **Analytical Rigor**
       - 5: Clear consensus/debate, contradictions explained
       - 4: Generally clear, contradictions noted
       - 3: Sometimes clear, contradictions noted
       - 2: Rarely clear, contradictions ignored
       - 1: No distinction, no synthesis

    4. **Completeness**
       - 5: All aspects, multiple perspectives, gaps acknowledged
       - 4: Most aspects, some gaps acknowledged
       - 3: Main aspects, few gaps
       - 2: Key aspects missing
       - 1: Major gaps, incomplete

    5. **Attribution Accuracy**
       - 5: Every claim traceable, proper format
       - 4: Most traceable, generally proper
       - 3: Many traceable, inconsistent
       - 2: Few traceable
       - 1: Not traceable

    **Pass threshold:** Average ≥ 4.0/5.0

    **If fail:** For each dimension below 4.0, specify:
    - What's missing or weak
    - Specific improvements needed
    - Additional research required""",
    "QA: Consistency check"
)

# Extract scores
scores = parse_scores(qa_stage1_results)
average = sum(scores.values()) / len(scores)

if average < 4.0:
    # Proceed to targeted follow-up
    weak_dimensions = [d for d, s in scores.items() if s < 4.0]
    print(f"Weak dimensions: {weak_dimensions}")
```

## Stage 2: Pattern Analysis

**Trigger**: Stage 1 passes (≥ 4.0/5.0)

**Purpose**: Detect systematic biases and issues not visible in individual dimensions

### Analysis Categories

#### 1. Source Selection Bias

**Checks:**
- Over-representation of certain sources (e.g., all from same vendor)
- Geographic or cultural bias (e.g., all US sources)
- Temporal bias (e.g., all recent, ignoring historical context)
- Language bias (e.g., all English sources)

**Red flags:**
- >50% of sources from same organization
- All sources from same region
- No sources older than 1 year for historical topics
- Missing non-English perspectives for global topics

#### 2. Perspective Coverage

**Checks:**
- Are all major viewpoints represented?
- Are minority views acknowledged?
- Is there balance between technical and non-technical perspectives?
- Are practitioner and academic views both included?

**Red flags:**
- Only one perspective on debated topics
- Missing practitioner voices for practical topics
- Only academic or only industry sources
- No counter-examples or alternative approaches

#### 3. Evidence Distribution

**Checks:**
- Is evidence evenly distributed across claims?
- Are key claims well-supported while minor claims less so?
- Is there over-reliance on single sources?

**Red flags:**
- Many claims supported by same single source
- Key claims with weak evidence
- Uneven evidence distribution

#### 4. Systematic Gaps

**Checks:**
- Missing aspects of the topic
- Under-represented subtopics
- Logical holes in the analysis

**Red flags:**
- Major subtopics unaddressed
- Obvious follow-up questions unanswered
- Incomplete coverage of stated scope

### Stage 2 Implementation

```python
qa_stage2 = Task(
    "general-purpose",
    f"""Analyze this research evaluation for systematic patterns:\n\n{qa_stage1_results}\n\n

    **Check for:**

    1. **Source Selection Bias**
       - Over-representation of certain sources?
       - Geographic/cultural/language bias?
       - Temporal bias?
       - Specific: List any overrepresented sources/perspectives

    2. **Perspective Coverage**
       - All major viewpoints represented?
       - Minority views acknowledged?
       - Balance between technical/non-technical?
       - Academic vs practitioner balance?
       - Specific: List missing perspectives

    3. **Evidence Distribution**
       - Evidence evenly distributed?
       - Over-reliance on single sources?
       - Key claims well-supported?
       - Specific: List claims with weak support

    4. **Systematic Gaps**
       - Missing aspects?
       - Under-represented subtopics?
       - Logical holes?
       - Specific: List gaps requiring follow-up

    **Output:**
    - Overall bias assessment (Minimal/Moderate/Significant)
    - Specific issues found
    - Recommended follow-up research (if any)""",
    "QA: Pattern analysis"
)
```

## Gate Logic and Follow-up

### Decision Flow

```
Stage 1: Consistency Check
  ↓
Average ≥ 4.0?
  ↓ Yes                    ↓ No
Stage 2: Pattern    →  Targeted Follow-up → Re-evaluate
Analysis
  ↓
Biases found?
  ↓ No           ↓ Yes
Approve     →  Targeted Follow-up → Re-evaluate
```

### Targeted Follow-up Pattern

```python
# If Stage 1 fails with specific weaknesses
if average < 4.0:
    weak_dims = identify_weak_dimensions(scores)

    followup_tasks = []
    for dim in weak_dims:
        if dim == "Source Credibility":
            followup_tasks.append(Task(
                "general-purpose",
                f"Replace low-credibility sources with authoritative ones. "
                f"Focus on these weak areas: {specific_gaps}",
                "Follow-up: Improve sources"
            ))
        elif dim == "Evidence Quality":
            followup_tasks.append(Task(
                "general-purpose",
                f"Find supporting evidence for uncited claims. "
                f"Focus on: {list_unsupported_claims}",
                "Follow-up: Add evidence"
            ))
        # ... similar for other dimensions

    # Execute follow-up in parallel
    followup_results = await_all(followup_tasks)

    # Re-evaluate
    qa_recheck = Task(...)
```

## Quality Metrics Tracking

### Metrics to Record

```python
quality_metrics = {
    "qa_score": average,
    "dimension_scores": scores,
    "stage2_bias": bias_level,
    "followup_required": bool(followup_tasks),
    "followup_iterations": len(followup_tasks),
    "final_confidence": final_confidence
}
```

### Quality Categories

- **Excellent (4.5-5.0)**: Ready for critical decisions, publication
- **Good (4.0-4.5)**: Sufficient for most purposes
- **Acceptable (3.5-4.0)**: Usable with caveats
- **Weak (3.0-3.5)**: Requires significant refinement
- **Poor (<3.0)**: Not usable, major rework needed

## Best Practices

### 1. Calibration

Different LLMs may evaluate differently. Calibrate by:
- Running same evaluation through multiple LLMs
- Comparing to human evaluations
- Adjusting prompts to reduce variance

### 2. Context Length

Long research syntheses may exceed context. Strategy:
- Evaluate section by section
- Aggregate scores
- Flag sections needing attention

### 3. Iteration Management

Max refinement iterations: 2-3
- Beyond this, diminishing returns
- User consultation may be needed
- Consider scope adjustment

### 4. User Override

Allow users to:
- Accept lower-quality research if time-constrained
- Skip quality gate for non-critical topics
- Adjust threshold for their needs

## Common Pitfalls

### Pitfall 1: Over-Reliance on QA

**Problem**: Treat QA score as absolute truth

**Solution**: QA is guidance, not gospel. Use human judgment for final decisions.

### Pitfall 2: Ignoring Stage 2

**Problem**: Only run Stage 1, skip pattern analysis

**Solution**: Stage 2 catches systematic issues Stage 1 misses. Always run both.

### Pitfall 3: Infinite Refinement Loops

**Problem**: Keep refining until perfect (never achieves perfection)

**Solution**: Max 2-3 iterations. Stop at "good enough" or consult user.

### Pitfall 4: One-Size-Fits-All Threshold

**Problem**: Use 4.0 threshold for all research

**Solution**: Adjust threshold based on:
- Research stakes (critical vs exploratory)
- Time constraints (quick vs thorough)
- User needs (comprehensive vs overview)

## References

1. A Survey on LLM-as-a-Judge (arXiv 2411.15594)
2. Judge's Verdict Benchmark (arXiv 2510.09738)
3. When AIs Judge AIs (arXiv 2508.02994)
