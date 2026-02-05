# Reusable Prompt Templates

Templates for paper analysis and explanation tasks.

## Paper Analysis Prompts

### Initial Paper Assessment
```
Analyze this paper and provide:
1. One-sentence summary of the main contribution
2. 3-5 key technical concepts involved
3. Prerequisite knowledge needed, categorized by difficulty:
   - Basic: Undergraduate CS/math
   - Intermediate: Domain-specific (ML, NLP, CV, etc.)
   - Advanced: Specialized techniques

For each prerequisite, note if you need to search for additional information to explain it accurately.
```

### Section Breakdown Prompt
```
Break this paper into teachable sections. For each section provide:
1. Section title/focus
2. Prerequisites specific to THIS section
3. Main ideas to explain (2-4 bullet points)
4. How this connects to previous sections

Group related ideas together. Each section should be digestible in 5-10 minutes of explanation.
```

### Concept Explanation Prompt
```
Explain [CONCEPT NAME] for someone learning [PAPER TITLE]:

Structure your explanation:
1. One-sentence intuitive definition (what problem does it solve?)
2. Simple analogy or example
3. Key technical details (2-3 sentences)
4. How it's used in this specific paper

Keep it under 200 words. Avoid jargon unless defined.
```

### Prerequisite Search Prompt
```
I need to explain [CONCEPT] as a prerequisite for understanding [PAPER].
Search for:
1. Recent survey or tutorial papers on [CONCEPT]
2. The original paper that introduced [CONCEPT]
3. Beginner-friendly explanations

Summarize findings with 2-3 best sources and brief description of each.
```

## Interactive Teaching Prompts

### Start Teaching Session
```
Let's learn [PAPER TITLE] together!

## Paper Overview
[Insert 1-2 sentence summary]

## Learning Plan
We'll cover these sections:
1. [Section 1]
2. [Section 2]
3. [Section 3]
...

## Before We Start
To understand this paper, you should be familiar with:
- [Concept 1]
- [Concept 2]
- [Concept 3]

Are you familiar with these concepts? Should I explain any of them first?
```

### Prerequisite Check
```
Before we dive into [SECTION NAME], let's check prerequisites:

This section requires understanding of:
- [Prerequisite 1]: [Brief 1-sentence description]
- [Prerequisite 2]: [Brief 1-sentence description]
- [Prerequisite 3]: [Brief 1-sentence description]

Are you familiar with these? Would you like me to explain any before we proceed?
```

### Section Explanation
```
## [SECTION NAME]

[Explanation with analogies, examples, equations]

### Key Points
- Point 1
- Point 2
- Point 3

### Connection to Prerequisites
This builds on [previous concept] by...

Does this make sense? Do you have any questions?
```

### Understanding Verification
```
Quick check: Can you explain in your own words what [KEY CONCEPT] does and why it's important for this paper?

Take your time - no rush. I want to make sure you understand before we move on.
```

### Moving Forward
```
Great! You've got [SECTION NAME].

## Next Up: [NEXT SECTION]
This will cover [brief description of what's next].

It builds on what we just learned by [connection].

Ready to continue?
```

## Handling Difficulties

### When User Is Struggling
```
No problem - let me explain [CONCEPT] differently.

[Alternative explanation with different analogy]

Let me break it down further:
- Sub-concept A: [explanation]
- Sub-concept B: [explanation]
- How they connect: [explanation]

Does this help clarify things?
```

### When User Wants More Depth
```
Great question! Let me provide more detail on [CONCEPT].

[Deeper explanation with mathematical details]

Would you like me to search for related papers that cover this in more depth? I can find the original [CONCEPT] paper or recent surveys.
```

### When User Says It's Too Easy
```
Got it! You're already familiar with [CONCEPTS].

Let me focus on what's novel in this paper rather than basics:

[More advanced explanation focusing on nuances and innovations]

Shall I move to the next section?
```

## Progress Tracking

### Save Progress
```
## Learning Progress: [PAPER TITLE]

### Completed
- [x] [Section 1]
- [x] [Section 2]

### Current
- [ ] [Section 3]
  - Last explained: [specific concept]
  - User understands: [yes/no/partially]

### Remaining
- [ ] [Section 4]
- [ ] [Section 5]
```

## Search Queries

### Concept Understanding
```
"[concept name] tutorial"
"[concept name] explained simply"
"[concept name] intuition"
"introduction to [concept name]"
```

### Finding Papers
```
"[concept name] paper arxiv"
"[concept name] original paper"
"[concept name] survey 2024"
"state of the art [concept name]"
```

### Finding Examples
```
"[concept name] example"
"[concept name] code example"
"[concept name] visualization"
```

## Response Patterns

### Acknowledging Confusion
```
That's a great question - [CONCEPT] is definitely tricky.

Many people get stuck here because [common misconception].

Let me clarify: [correction]
```

### Celebrating Understanding
```
Exactly! You've got it.

[CONCEPT] is essentially [user's explanation in refined form].

This understanding will help us with [next section] because...
```

### Transitioning
```
Perfect - now that you understand [CURRENT CONCEPT], we can move to [NEXT CONCEPT].

The connection is: [how current leads to next]

Let's go!
```
