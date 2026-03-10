---
name: codex-discuss
description: "Structured multi-round discussion with Codex for independent second opinions. Use when: (1) making design decisions that benefit from a different model's perspective, (2) reviewing code or architecture with an independent reviewer, (3) validating assumptions before committing to an approach. Trigger phrases: 'discuss with codex', 'get codex opinion', 'codex review', 'second opinion'. Also suggest proactively when facing design trade-offs or when a decision has high blast radius."
---

# Codex Discuss

Bounded multi-round discussion with Codex CLI for design review, code review, or assumption validation. Default 2 rounds, max 3 (tie-breaking only).

## Prerequisites

```bash
export NVM_DIR="$HOME/.nvm" && [ -s "$NVM_DIR/nvm.sh" ] && . "$NVM_DIR/nvm.sh"
codex --version  # must be available
```

## Modes

| Mode | Sandbox | Task framing (prepended to prompt) |
|------|---------|-----------------------------------|
| `design` | `read-only` | "Be practical and concise. Focus on simplicity. Avoid over-engineering. Do not edit files." |
| `review` | `read-only` | "Focus on bugs, security issues, and correctness. Classify each issue as High/Medium/Low. Do not edit files." |
| `validate` | `read-only` | "Challenge assumptions. Point out what could go wrong. Be devil's advocate. Do not edit files." |

All modes use `--sandbox read-only` to prevent Codex from modifying files.

## Workflow

### 1. Create discussion directory

```bash
DISCUSS_DIR=$(mktemp -d /tmp/codex-discuss-XXXXXX)
```

### 2. Prepare Round 1

Write `$DISCUSS_DIR/round-1.md`:

```markdown
# [Topic]

## Context
[Concise background — what exists today, what problem we're solving]

## Proposal
[The specific design/code/decision under review]

## Questions
1. [Specific, answerable question]
2. [Specific, answerable question]
```

Rules:
- Max 5 numbered questions per round
- Every question must be answerable, not open-ended brainstorming
- Use **absolute file paths** so Codex can read source code itself
- Do NOT paste large code blocks — reference files instead
- Do NOT reference files containing secrets or credentials

### 3. Run Codex Round 1

```bash
timeout 180 codex exec \
  --sandbox read-only --skip-git-repo-check \
  -o "$DISCUSS_DIR/response-1.md" \
  "{task_framing} Answer only the numbered questions in $DISCUSS_DIR/round-1.md. Read only that file and directly referenced files. Do not edit files."
```

After execution, verify:
- Exit code is 0
- `response-1.md` exists and is non-empty

If Codex fails or times out, note "Codex did not respond" and skip to step 6 with available information.

### 4. Read response and decide

Read `response-1.md`. One of three outcomes:

| Outcome | Action |
|---------|--------|
| **Converged** — answers are clear, no disagreement | Go to step 6 (conclude) |
| **Needs clarification** — some points unclear | Write `round-2.md`, go to step 5 |
| **Disagreement** — fundamentally different view | Write `round-2.md` stating your position, go to step 5 |

### 5. Round 2 (and optional Round 3)

Write `$DISCUSS_DIR/round-2.md`:

```markdown
# Round 2: [Follow-up topic]

## Codex R1 Summary
[1-3 bullet summary of Codex's R1 position]

## My Assessment
[Where you agree/disagree and why]

## Questions
1. [Focused follow-up]
2. [Focused follow-up]
```

Run Codex with previous context:

```bash
timeout 180 codex exec \
  --sandbox read-only --skip-git-repo-check \
  -o "$DISCUSS_DIR/response-2.md" \
  "{task_framing} Read $DISCUSS_DIR/round-1.md, $DISCUSS_DIR/response-1.md, and $DISCUSS_DIR/round-2.md for full context. Answer only the numbered questions in round-2.md. Do not edit files."
```

**Round 3 rule**: Only if Round 2 has unresolved disagreement. Prompt must frame as tie-breaking:

```bash
timeout 180 codex exec \
  --sandbox read-only --skip-git-repo-check \
  -o "$DISCUSS_DIR/response-3.md" \
  "This is the final round. Read all files in $DISCUSS_DIR/ for context. Pick one option and justify. No new proposals. Do not edit files."
```

### 6. Conclude

Write the discussion result into the **target document** (design doc, code, or AGENTS.md). Do NOT leave conclusions only in the temp directory.

Format:
```markdown
### Codex Discussion Consensus ({date}, {rounds} rounds)
- **Decision**: [what was decided]
- **Reasoning**: [1-2 sentences]
- **Rejected alternatives**: [what was considered and why not]
```

If Codex failed or gave no useful response, note that and proceed with your own judgment.

## Anti-Patterns

- Opening a round without specific numbered questions
- Asking more than 5 questions per round
- Going to Round 3 without genuine disagreement from Round 2
- Leaving conclusions in temp dir without writing to target document
- Using for simple factual lookups (use web search instead)
- Re-running rounds hoping for a different answer
- Referencing files containing secrets or credentials
- Reusing an old discussion directory instead of creating fresh
- Treating timeout/empty output as consensus
- Expanding discussion scope in later rounds beyond the original topic

## When to Suggest This Skill

Proactively suggest when:
- A design decision has multiple valid approaches and high blast radius
- You're about to add significant complexity to a system
- The user asks "what do you think about X" for architectural questions
- A code review would benefit from an independent perspective

Do NOT suggest when:
- The task is straightforward implementation
- The question is factual (use web search)
- The user has already decided and just wants execution
