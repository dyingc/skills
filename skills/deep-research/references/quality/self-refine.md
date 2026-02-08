# Self-Refine Iteration Methodology

This reference provides detailed implementation guidance for the Self-Refine loop used in deep-research for iterative improvement.

## Overview

Self-Refine is an iterative refinement technique where LLMs improve their own outputs through feedback and revision. Research shows 20% average performance improvement across tasks, up to 40% with GPT-4 (arXiv 2303.17651).

### Core Mechanism

```
Initial Output → Self-Evaluation → Feedback → Refinement → [Repeat]
```

### Application to Research

In deep-research, Self-Refine addresses:
- Low-confidence findings
- Contradictions between sources
- Weak evidence quality
- Gaps identified by quality gate

## When to Trigger Self-Refine

### Automatic Triggers

1. **Quality gate fails** (QA score < 4.0/5.0)
2. **Confidence assessment below threshold** (< 4.0/5.0)
3. **Significant contradictions found** (unresolvable conflicts)

### User Triggers

1. **Explicit request**: "Refine this further"
2. **Dissatisfaction**: "This isn't comprehensive enough"
3. **New information**: "I found this additional source"

## Implementation Pattern

### First Refinement Iteration

```python
refinement_threshold = 4.0

if qa_score < refinement_threshold or user_requests_refinement:
    agent5 = Task(
        "general-purpose",
        f"""Refine and strengthen these research conclusions:\n\n{agent4_results}\n\n

        **Context:** Quality assessment scored {qa_score}/5.0.
        Weak dimensions: {weak_dimensions}

        **Refinement priorities:**

        1. **Address low-confidence findings**
           - Identify findings with confidence < 4.0
           - Find additional corroborating sources
           - Cross-check with authoritative references
           - Verify recent information (2024-2025 for fast-moving topics)
           - Replace "Limited" evidence with "Medium" or "Strong"

        2. **Resolve contradictions**
           - List all contradictions found
           - Investigate why sources disagree
           - Identify context differences (e.g., different time periods, conditions)
           - Determine which evidence is stronger
           - Explain resolution clearly

        3. **Strengthen evidence quality**
           - Replace weak sources (blogs, forums) with authoritative ones
           - Add quantitative data where currently qualitative
           - Include expert consensus statements
           - Find peer-reviewed support for claims
           - Add specific citations for currently unsupported claims

        4. **Fill identified gaps**
           - Address gaps from quality assessment
           - Cover missing perspectives
           - Add underrepresented aspects
           - Complete incomplete coverage

        **Target:** Elevate overall confidence to ≥ 4.0/5.0
        **Constraint:** Use web search to find new sources, don't just rephrase existing content

        **Output format:**
        ## Refined Research Conclusions
        [Full revised synthesis]

        ## Refinement Summary
        - Changes made: [List specific improvements]
        - New sources added: [Count and types]
        - Contradictions resolved: [List resolutions]
        - Confidence improvement: [Before → After]""",
        "Deep Research: Refine conclusions (iteration 1)"
    )

    # Evaluate improvement
    agent5_confidence = extract_confidence(agent5_results)
    improvement = agent5_confidence - qa_score

    print(f"Iteration 1: {qa_score} → {agent5_confidence} (Δ{improvement:+.1f})")
```

### Second Refinement Iteration (Conditional)

```python
# Only if first iteration insufficient
if agent5_confidence < refinement_threshold:
    agent6 = Task(
        "general-purpose",
        f"""Further refinement based on evaluation:\n\n{agent5_results}\n\n

        **Context:** Previous refinement achieved {agent5_confidence}/5.0.
        Still below threshold of {refinement_threshold}.

        **Focus areas:**
        1. Remaining weak dimensions from quality assessment
        2. Persisting low-confidence findings
        3. Unresolved contradictions
        4. Remaining evidence gaps

        **Strategy:**
        - Seek expert sources (official docs, academic papers, industry standards)
        - Find corroborating evidence for weak claims
        - Investigate alternative perspectives
        - Add quantitative data

        **Stop conditions:**
        - Achieve confidence ≥ 4.0
        - OR determine maximum achievable quality given available sources
        - OR 2 iterations reached (avoid infinite loops)

        **Output format:**
        ## Further Refined Conclusions
        [Full revised synthesis]

        ## Additional Refinements
        - New sources in this iteration: [List]
        - Additional improvements: [List]
        - Final confidence: [Score]
        - Limitations: [What couldn't be improved]""",
        "Deep Research: Refine conclusions (iteration 2)"
    )

    agent6_confidence = extract_confidence(agent6_results)
    improvement_2 = agent6_confidence - agent5_confidence

    print(f"Iteration 2: {agent5_confidence} → {agent6_confidence} (Δ{improvement_2:+.1f})")
```

## Iteration Management

### Stopping Criteria

```python
MAX_ITERATIONS = 2
TARGET_CONFIDENCE = 4.0

iterations = 0
current_confidence = qa_score

while iterations < MAX_ITERATIONS and current_confidence < TARGET_CONFIDENCE:
    iterations += 1

    # Run refinement
    refined_result, new_confidence = run_refinement_iteration(
        current_result,
        current_confidence,
        iteration=iterations
    )

    # Check for improvement
    improvement = new_confidence - current_confidence

    # Stop if negligible improvement (diminishing returns)
    if improvement < 0.2:
        print(f"Negligible improvement ({improvement:+.1f}). Stopping.")
        break

    current_result = refined_result
    current_confidence = new_confidence

    # User checkpoint after each iteration
    if should_prompt_user():
        user_feedback = AskUserQuestion(
            questions=[{
                "question": f"Confidence: {current_confidence}/5.0. Continue refining?",
                "header": "Iteration Checkpoint",
                "options": [
                    {"label": "Yes, continue", "description": "Run another refinement iteration"},
                    {"label": "No, accept current", "description": "Use current refined results"}
                ],
                "multiSelect": False
            }]
        )
        if user_feedback == "No, accept current":
            break
```

### Improvement Tracking

```python
refinement_log = {
    "initial_confidence": qa_score,
    "iterations": [],
    "final_confidence": None,
    "total_improvement": None
}

for i in range(MAX_ITERATIONS):
    result = run_refinement_iteration(...)
    improvement = result['confidence'] - current_confidence

    refinement_log["iterations"].append({
        "iteration": i + 1,
        "confidence_before": current_confidence,
        "confidence_after": result['confidence'],
        "improvement": improvement,
        "sources_added": result['new_sources'],
        "changes": result['changes_summary']
    })

    current_confidence = result['confidence']

    if current_confidence >= TARGET_CONFIDENCE:
        break

refinement_log["final_confidence"] = current_confidence
refinement_log["total_improvement"] = current_confidence - qa_score
```

## Refinement Strategies by Weakness

### Weak Dimension: Source Credibility

**Strategy**:
1. Identify low-credibility sources (blogs, forums, outdated)
2. For each claim from weak sources, search for:
   - Official documentation
   - Peer-reviewed papers
   - Established vendor resources
   - Recent industry reports
3. Replace weak citations with strong ones

**Example prompt**:
```python
Task("general-purpose",
     "Find authoritative sources for these claims currently supported by weak sources:\n"
     "{claims_list}\n\n"
     "Search for: official docs, peer-reviewed papers, established vendors.\n"
     "Prioritize: recent (2024-2025), specific, quantifiable.",
     "Refinement: Improve source credibility")
```

### Weak Dimension: Evidence Quality

**Strategy**:
1. Identify unsupported or weakly-supported claims
2. For each, find:
   - Specific citations
   - Quantitative data
   - Direct evidence vs hearsay
3. Add evidence strength indicators

**Example prompt**:
```python
Task("general-purpose",
     "Find supporting evidence for these unsupported claims:\n"
     "{unsupported_claims}\n\n"
     "For each claim, find:\n"
     "- Specific sources with direct quotes\n"
     "- Quantitative data (numbers, statistics)\n"
     "- Multiple independent corroborating sources\n"
     "Categorize evidence as Strong/Medium/Limited.",
     "Refinement: Add evidence")
```

### Weak Dimension: Analytical Rigor

**Strategy**:
1. Identify areas where consensus/debate unclear
2. For each debate:
   - Investigate both sides
   - Find sources representing each perspective
   - Explain why disagreement exists
   - Assess evidence strength on each side
3. Identify patterns and trends

**Example prompt**:
```python
Task("general-purpose",
     "Investigate these contradictions in the research:\n"
     "{contradictions}\n\n"
     "For each:\n"
     "- Find sources supporting each side\n"
     "- Explain context differences\n"
     "- Assess evidence quality\n"
     "- Determine which position is stronger\n"
     "- Explain resolution clearly",
     "Refinement: Resolve contradictions")
```

### Weak Dimension: Completeness

**Strategy**:
1. Identify gaps in coverage
2. For each gap:
   - Search for missing perspectives
   - Find sources on underrepresented aspects
   - Add missing subtopics
3. Ensure balanced representation

**Example prompt**:
```python
Task("general-purpose",
     "Fill these gaps in the research:\n"
     "{gaps_list}\n\n"
     "For each gap:\n"
     "- Find sources on missing aspects\n"
     "- Include multiple perspectives\n"
     "- Ensure balanced coverage\n"
     "- Add to appropriate section",
     "Refinement: Fill gaps")
```

### Weak Dimension: Attribution Accuracy

**Strategy**:
1. Identify unsupported assertions
2. For each:
   - Find supporting source
   - Add proper citation
   - If no source found, remove or qualify claim
3. Ensure all claims traceable

**Example prompt**:
```python
Task("general-purpose",
     "Find sources for these unsupported assertions:\n"
     "{unsupported_assertions}\n\n"
     "For each:\n"
     "- Search for supporting evidence\n"
     "- Add proper citation\n"
     "- If no evidence found, remove or qualify as 'speculative'\n"
     "Ensure all claims are traceable.",
     "Refinement: Add attributions")
```

## Quality Assessment After Refinement

```python
# Re-run quality gate after refinement
qa_after_refinement = Task(
    "general-purpose",
    f"""Re-evaluate this refined research:\n\n{refined_results}\n\n

    Use same 5-dimension evaluation (1-5 scale).
    Compare to previous score: {previous_score}.

    Highlight:
    - Dimensions that improved
    - Dimensions still weak
    - Overall improvement""",
    "QA: Post-refinement evaluation"
)

new_qa_score = extract_score(qa_after_refinement_results)

# Report improvement
print(f"Quality improvement: {qa_score} → {new_qa_score}")
print(f"Confidence improvement: {confidence_before} → {confidence_after}")
```

## Best Practices

### 1. Iteration Limit

**Rule**: Max 2-3 iterations

**Rationale**:
- Diminishing returns after 2 iterations
- Risk of over-refinement (making things worse)
- Time cost vs benefit trade-off

**Implementation**: Hard stop at MAX_ITERATIONS

### 2. Measurable Improvement

**Rule**: Each iteration must show ≥ 0.2 improvement

**Rationale**:
- Avoid busy work
- Stop when plateau reached
- User time is valuable

**Implementation**: Check improvement delta, break if too small

### 3. Progress Updates

**Rule**: Report progress after each iteration

**Rationale**:
- User should see improvement
- Transparency builds trust
- Allows user intervention

**Implementation**:
```python
print(f"✅ Iteration {i}: {before} → {after} (Δ{improvement:+.1f})")
print(f"   Sources added: {new_sources}")
print(f"   Changes: {changes_summary}")
```

### 4. Source Quality in Refinement

**Rule**: Refinement must add NEW sources, not rephrase

**Rationale**:
- Rephrasing doesn't improve evidence quality
- New sources strengthen claims
- Avoids echo chamber

**Implementation**: Explicitly require web search in refinement prompt

### 5. F Graceful Degradation

**Rule**: Accept "best achievable" if can't reach threshold

**Rationale**:
- Some topics lack strong sources
- Perfection is enemy of good
- User may not need 5.0 quality

**Implementation**:
```python
if agent6_confidence < TARGET_CONFIDENCE:
    # Explain why couldn't improve further
    limitations = Task(..., "Explain limitations preventing further improvement")
    # Ask user if acceptable
    user_decision = AskUserQuestion(...)
```

## Common Pitfalls

### Pitfall 1: Infinite Refinement Loops

**Problem**: Keep refining forever trying to reach 5.0

**Solution**: Hard limit at 2-3 iterations, accept "good enough"

### Pitfall 2: Cosmetic Refinement

**Problem**: Only rephrase existing content, add no new sources

**Solution**: Require web search and new sources in refinement prompt

### Pitfall 3: Over-Refinement

**Problem**: Make things worse by over-editing

**Solution**: Stop if improvement < 0.2 or confidence decreases

### Pitfall 4: Ignoring User Time

**Problem**: Run multiple iterations without user input

**Solution**: Checkpoint after each iteration, allow user to stop

### Pitfall 5: One-Size-Fits-All Refinement

**Problem**: Same refinement strategy for all weaknesses

**Solution**: Tailor refinement to specific weak dimensions (see above)

## References

1. Self-Refine: Iterative Refinement with Self-Feedback (arXiv 2303.17651)
2. SSR: Socratic Self-Refine (arXiv 2511.10621)
3. Evolving LLMs' Self-Refinement Capability (arXiv 2502.05605)
