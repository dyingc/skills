---
name: patent-extraction
description: >
  Extract patentable inventions from source code, technical documents, or verbal descriptions
  and prepare patent preamble assessment answers. Use when users want to identify patentable
  innovations in their work, prepare patent application materials, answer patent assessment
  questionnaires, or articulate novelty and non-obviousness of an invention. Helps narrow
  down broad technical work into concrete, patentable claims that satisfy requirements like
  novelty and non-obviousness.
---

# Patent Extraction

Extract and articulate patentable inventions for patent preamble assessment.

## Workflow

### Phase 1: Information Gathering

Collect materials from the user. Accept any combination of:
- Source code or codebase references
- Technical documents, design docs, architecture specs
- Verbal descriptions of the invention

Ask clarifying questions to understand:
1. **Core innovation**: What is fundamentally new?
2. **Problem solved**: What specific problem does this address?
3. **Technical approach**: How does it work technically?
4. **Prior art awareness**: What existing solutions does the user know about?
5. **Differentiators**: What makes this different from known approaches?

Continue gathering until confident about:
- The specific technical mechanism of the invention
- Why it's novel (not previously known)
- Why it's non-obvious (not a trivial combination of existing techniques)

### Phase 2: Innovation Analysis

Analyze the collected materials to identify patentable elements:

**Novelty Check** - The invention must be new:
- Identify the specific technical contribution
- Distinguish from similar existing solutions
- Articulate what has never been done before

**Non-Obviousness Check** - Not an obvious combination of prior art:
- Would a skilled practitioner find this solution obvious?
- What unexpected technical effects or advantages exist?
- What problem-solving approach is non-trivial?

**Claim Narrowing** - Focus on the defensible core:
- Identify the minimum novel technical mechanism
- Avoid overly broad claims that overlap with prior art
- Frame in terms of method, system, or apparatus as appropriate

If the innovation appears too broad or obvious, ask the user for more specific technical details that differentiate their approach.

### Phase 3: Domain Classification

Determine the appropriate patent category:
- **Software/Algorithm**: Methods, data processing, computational techniques
- **AI/ML**: Machine learning models, training methods, inference techniques
- **System Architecture**: Distributed systems, hardware-software integration
- **User Interface**: Novel interaction methods, display techniques

This informs how to frame the invention description.

### Phase 4: Assessment Generation

Once sufficient information is gathered, ask the user to choose output format:
- **Markdown document**: Structured file with all answers
- **Interactive review**: Go through each question with user feedback

Generate answers for the patent preamble assessment:

#### 1. Brief Summary
Write 2-3 sentences capturing:
- What the invention is (technical mechanism)
- What it does (function/purpose)
- Why it matters (key benefit)

#### 2. Problem Description
Describe:
- The specific technical problem addressed
- Why existing solutions are inadequate
- The gap in current technology

#### 3. Invention Description
Provide:
- High-level overview of the solution
- How it addresses the stated problem
- Key technical components and their interactions

#### 4. Novel Features
List specific features that are new:
- Each feature should be technically concrete
- Explain why each is novel (not found in prior art)
- Focus on the minimum differentiating elements

#### 5. Advantages
State benefits over known solutions:
- Technical advantages (performance, efficiency, accuracy)
- Practical advantages (cost, ease of implementation)
- Be specific and quantifiable where possible

#### 6. Disadvantages
Acknowledge limitations honestly:
- Technical constraints or tradeoffs
- Scope limitations
- Implementation complexity if applicable

#### 7. Implementation
Confirm implementation status and timeline:
- Current state (concept, development, production)
- Implementation date or expected date
- Check user-provided text for grammar issues

#### 8. Additional Enabling Details
Provide enough detail for reproduction:
- System architecture or algorithm steps
- Key components and their functions
- How components interact
- Sufficient for a skilled practitioner to implement

#### 9. Detectability
Describe how infringement could be detected:
- Observable behaviors or outputs
- Technical signatures or characteristics
- How to identify if a third party uses the invention

#### 10. Competitors or Competing Products
Identify potential beneficiaries:
- Direct competitors who might use this
- Adjacent products that could benefit
- Market context

#### 11. External Disclosure
Document any external communications:
- Prior disclosures to third parties
- Joint development agreements
- Government funding involvement
- Publication or presentation history

## Output Format

### Markdown Document
```markdown
# Patent Preamble Assessment: [Invention Name]

## 1. Brief Summary
[Content]

## 2. Problem Description
[Content]

## 3. Invention Description
[Content]

## 4. Novel Features
[Content]

## 5. Advantages
[Content]

## 6. Disadvantages
[Content]

## 7. Implementation
- **Has the invention been implemented?**: [Yes/No]
- **Implementation details**: [Details and date]

## 8. Additional Enabling Details
[Content]

## 9. Detectability
[Content]

## 10. Competitors or Competing Products
[Content]

## 11. External Disclosure
[Content]
```

## Key Principles

**Be Specific**: Vague claims are weak claims. Always push for concrete technical details.

**Focus on the Mechanism**: Patents protect *how* something works, not just *what* it does.

**Narrow is Strong**: A narrow, defensible claim is better than a broad, vulnerable one.

**Honest Assessment**: If an invention doesn't meet novelty/non-obviousness standards, communicate this clearly rather than forcing a weak patent application.
