---
name: codex-discuss
description: "Structured multi-round discussion with Codex for independent second opinions. Use when: (1) making design decisions that benefit from a different model's perspective, (2) reviewing code or architecture with an independent reviewer, (3) validating assumptions before committing to an approach. Trigger phrases: 'discuss with codex', 'get codex opinion', 'codex review', 'second opinion'. Also suggest proactively when facing design trade-offs or when a decision has high blast radius."
---

# Codex Discuss

Bounded multi-round discussion with Codex CLI for design review, code review, or assumption validation. Default 2 rounds, max 4 rounds.

## Core Principle: Discussion, Not Delegation

**This is a DISCUSSION skill, not an "ask Codex and follow" skill.**

You are an active participant, not a passive recipient. Your role:

| DO | DON'T |
|----|-------|
| Form your own hypothesis BEFORE asking Codex | Ask Codex first, then accept without question |
| Do independent research to verify/challenge Codex | Use Codex's search results as final truth |
| Present contradictory evidence you found | Echo Codex's conclusions without verification |
| Question Codex when you disagree | Change your view just because Codex said so |
| Synthesize both perspectives | Treat Codex as the authority |

**If you find yourself just agreeing with Codex, you're doing it wrong.**

## Prerequisites

```bash
export NVM_DIR="$HOME/.nvm" && [ -s "$NVM_DIR/nvm.sh" ] && . "$NVM_DIR/nvm.sh"
codex --version  # must be available
```

## Model and Reasoning Configuration

Use `-m` to select a model and `-c` to tune reasoning effort:

```bash
# Set model (default: whatever is in ~/.codex/config.toml, typically gpt-5.4)
# Available: gpt-5.4-pro | gpt-5.4 | gpt-5.4-mini
codex exec -m gpt-5.4-pro ...

# Set reasoning effort (valid values vary by model):
#   gpt-5.4-pro:  medium | high | xhigh (default xhigh)
#   gpt-5.4:      low | medium | high | xhigh (default none)
#   gpt-5.4-mini: low | medium | high | xhigh (default none)
codex exec -m gpt-5.4-pro -c 'model_reasoning_effort="medium"' ...
```

| Scenario | Recommended flags |
|----------|-------------------|
| Deep design review | `-m gpt-5.4-pro` (default xhigh reasoning) |
| Code review | `-m gpt-5.4-pro -c 'model_reasoning_effort="medium"'` |
| Fast validation | `-m gpt-5.4 -c 'model_reasoning_effort="high"'` |
| Budget-conscious | `-m gpt-5.4-mini` |

If Codex exits non-zero or returns empty output, retry once with lower reasoning effort before giving up.

## Modes

| Mode | Sandbox | Task framing (prepended to prompt) |
|------|---------|-----------------------------------|
| `design` | `read-only` | "Be practical and concise. Focus on simplicity. Avoid over-engineering. Do not edit files." |
| `review` | `read-only` | "Focus on bugs, security issues, and correctness. Classify each issue as High/Medium/Low. Do not edit files." |
| `validate` | `read-only` | "Challenge assumptions. Point out what could go wrong. Be devil's advocate. Do not edit files." |

All modes use `--sandbox read-only` to prevent Codex from modifying files.

## Claude Code Bash Execution Requirement

When using this skill inside Claude Code, every Bash tool call that starts `codex exec` MUST set `run_in_background: true`.

Why this is required:
- Claude Code foreground Bash calls can hit tool-level timeouts before Codex finishes.
- Background execution changes only process supervision; the discussion contract remains file-based via `-o "$DISCUSS_DIR/response-N.md"`.

Rules:
- Do NOT wrap `codex exec` in `timeout`.
- Do NOT set the Bash tool `timeout` field for `codex exec` background calls.
- Do NOT append `&`, or use `nohup`, `tmux`, or `screen`.
- Use the Bash tool's `run_in_background: true` option.
- Use `BashOutput` to wait for the background job and collect completion output.
- Do NOT read `response-N.md` or start the next round until `BashOutput` shows the job completed.
- If the job exits non-zero or `response-N.md` is missing/empty, retry once with lower reasoning effort; otherwise record the failure and continue to conclusion.

Supervision:
- There is intentionally no fixed wall-clock timeout for Codex discussion rounds.
- Keep the returned background shell ID until the round is completed or explicitly abandoned.
- If `BashOutput` returns `running`, keep waiting with `BashOutput`; do not treat "still running" as failure.
- If the user cancels, the discussion is no longer needed, or output shows an unrecoverable setup/authentication error, use `KillBash` on the background shell ID and record "Codex did not respond".
- If background execution is unavailable or no shell ID is returned, do not fall back to foreground `codex exec`; record the failure or ask the user to enable Claude Code background tasks.

## Pre-Discussion Requirements

Before writing Round 1, you MUST:

1. **Form your own hypothesis** - What do YOU think the answer is?
2. **Do initial research** - Search the web, read docs, gather evidence
3. **Document your findings** - Write them in `round-1.md` under "My Initial Research"
4. **Identify contradictions** - Note any conflicting evidence you found

Example `round-1.md` structure:
```markdown
# [Topic]

## My Initial Research
[What I found BEFORE asking Codex - sources, evidence, my hypothesis]

## Conflicting Evidence
[Sources that disagree with each other - this is where discussion is valuable]

## Questions for Codex
1. [Specific question]
2. [Specific question]
```

## Workflow

### 1. Create discussion directory

```bash
DISCUSS_DIR=$(mktemp -d /tmp/codex-discuss-XXXXXX)
```

### 2. Prepare Round 1 (with your research)

Write `$DISCUSS_DIR/round-1.md`:

```markdown
# [Topic]

## Context
[Concise background — what exists today, what problem we're solving]

## My Initial Research
[What YOU found before asking - include sources]

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
- **MUST include your own research/hypothesis before asking**

### 3. Run Codex Round 1

Use the Bash tool with `run_in_background: true`:

```text
command: |
  codex exec \
    -m gpt-5.4-pro \
    --sandbox read-only --skip-git-repo-check \
    -o "$DISCUSS_DIR/response-1.md" \
    "{task_framing} Answer only the numbered questions in $DISCUSS_DIR/round-1.md. Read only that file and directly referenced files. Do not edit files."
run_in_background: true
```

If this exits non-zero or produces empty output, retry with reduced reasoning effort:

```text
command: |
  codex exec \
    -m gpt-5.4-pro -c 'model_reasoning_effort="medium"' \
    --sandbox read-only --skip-git-repo-check \
    -o "$DISCUSS_DIR/response-1.md" \
    "{task_framing} Answer only the numbered questions in $DISCUSS_DIR/round-1.md. Read only that file and directly referenced files. Do not edit files."
run_in_background: true
```

After `BashOutput` reports completion, verify:
- Background job exit code is 0
- `response-1.md` exists and non-empty

If Codex fails or produces no useful response, note "Codex did not respond" and skip to step 6 with available information.

### 4. Read response and INDEPENDENTLY evaluate

**CRITICAL: Do NOT just accept Codex's answer.**

Read `response-1.md` and ask yourself:

1. **Does this match my research?** - If not, who's wrong?
2. **Are there contradictions?** - Did Codex miss evidence I found?
3. **Do I disagree?** - If yes, document WHY with evidence
4. **What did Codex miss?** - Perspectives, edge cases, alternatives

Then decide:

| Outcome | Action |
|---------|--------|
| **Converged** — both agree, evidence supports it | Go to step 6 (conclude) |
| **Needs clarification** — some points unclear | Write `round-2.md`, go to step 5 |
| **Disagreement** — I have evidence contradicting Codex | Write `round-2.md` with MY position and evidence, go to step 5 |
| **Codex missed something** — I found evidence Codex didn't | Write `round-2.md` presenting MY evidence, go to step 5 |

### 5. Round 2 (and optional Round 3/4)

Write `$DISCUSS_DIR/round-2.md`:

```markdown
# Round 2: [Follow-up topic]

## Codex R1 Summary
[1-3 bullet summary of Codex's R1 position]

## My Assessment (CRITICAL - show your independent thinking)
[Where you agree/disagree and WHY]
[Evidence YOU found that supports or contradicts Codex]

## Questions / Challenges
1. [Focused follow-up or challenge]
2. [Present contradictory evidence if any]
```

Run Codex with previous context:

Use the Bash tool with `run_in_background: true`:

```text
command: |
  codex exec \
    --sandbox read-only --skip-git-repo-check \
    -o "$DISCUSS_DIR/response-2.md" \
    "{task_framing} Read $DISCUSS_DIR/round-1.md, $DISCUSS_DIR/response-1.md, and $DISCUSS_DIR/round-2.md for full context. Answer only the numbered questions in round-2.md. Do not edit files."
run_in_background: true
```

#### When to use Round 3 or 4

**Default: Stop at Round 2.** Only continue if:

| Scenario | Why more rounds needed |
|----------|------------------------|
| **Conflicting authoritative sources** | E.g., official docs say X, but release notes imply Y - need to dig deeper |
| **Codex found evidence I missed** | I need to verify Codex's sources independently |
| **Both parties found valid but contradictory evidence** | Need to determine which source is more authoritative |
| **High-stakes decision with no clear answer** | When the decision has significant blast radius and evidence is ambiguous |
| **Technical constraint discovery mid-discussion** | E.g., "API is Pro-only" contradicts "download page says it's included" |

**Round 3/4 rule**: Must have genuine unresolved tension. Frame as resolution:

Use the Bash tool with `run_in_background: true`:

```text
command: |
  codex exec \
    --sandbox read-only --skip-git-repo-check \
    -o "$DISCUSS_DIR/response-3.md" \
    "This is round 3 of 4 max. Read all files in $DISCUSS_DIR/ for context. Address the specific contradiction: [describe]. Do not edit files."
run_in_background: true
```

Round 4 is the absolute maximum. If no resolution, document the impasse.

### 6. Conclude

Write the discussion result into the **target document** (design doc, code, or AGENTS.md). Do NOT leave conclusions only in the temp directory.

Format:
```markdown
### Codex Discussion Consensus ({date}, {rounds} rounds)
- **Decision**: [what was decided]
- **My position**: [what I initially thought]
- **Codex's position**: [what Codex initially thought]
- **Resolution**: [how we converged OR why we disagreed]
- **Reasoning**: [1-2 sentences]
- **Rejected alternatives**: [what was considered and why not]
- **Key evidence**: [links/sources that were decisive]
```

If Codex failed or gave no useful response, note that and proceed with your own judgment.

## Challenge Protocol

You MUST challenge Codex when:

1. **Codex's answer contradicts your research** - Present your evidence
2. **Codex cites sources you can't verify** - Ask for specifics or verify yourself
3. **Codex's logic has gaps** - Point them out
4. **You have domain knowledge Codex lacks** - Share it

You should ACCEPT Codex's answer when:

1. **Codex found evidence you missed** - But verify it independently
2. **Codex's logic is sound AND you have no contradictory evidence**
3. **Both your research and Codex's converge** - Good sign

## Anti-Patterns

### Discussion Anti-Patterns (CRITICAL)
- **Echo-chamber**: Writing "My Assessment" that just restates Codex's position
- **Passive acceptance**: "Codex said X, so I'll update the plan" without verification
- **Selective research**: Only searching for evidence that supports Codex's view
- **Skipping your own research**: Going straight to Codex without forming a hypothesis

### Process Anti-Patterns
- Opening a round without specific numbered questions
- Asking more than 5 questions per round
- Going to Round 3/4 without genuine unresolved tension
- Leaving conclusions in temp dir without writing to target document
- Using for simple factual lookups (use web search instead)
- Re-running rounds hoping for a different answer
- Referencing files containing secrets or credentials
- Reusing an old discussion directory instead of creating fresh
- Treating a still-running job, timeout, or empty output as consensus
- Running `codex exec` in foreground Bash inside Claude Code
- Setting a fixed Bash timeout that recreates the foreground timeout problem
- Abandoning a still-running Codex job without `KillBash`
- Expanding discussion scope in later rounds beyond the original topic

## When to Suggest This Skill

Proactively suggest when:
- A design decision has multiple valid approaches and high blast radius
- You're about to add significant complexity to a system
- The user asks "what do you think about X" for architectural questions
- A code review would benefit from an independent perspective
- You've done research but found conflicting evidence

Do NOT suggest when:
- The task is straightforward implementation
- The question is factual (use web search)
- The user has already decided and just wants execution
- You haven't done any independent research yet
