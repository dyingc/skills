---
name: code-review
description: "Use when user asks to review code, compare branches, or review a diff/PR for merge readiness. Focus on the to-be-merged update and prioritize business logic correctness, logic errors, and security risks introduced by the update."
---

# Code Review

## Core Workflow

### Stage 0: Sync and Lock Latest Commit Scope (Must Execute First!)

Before reading code, lock review scope to the **latest commit tips** of both branches:

1. Identify source (merge) branch and target branch.
2. Fetch latest remote refs for both branches.
3. Resolve exact commit IDs (SHA) for both latest tips.
4. Use these SHAs as immutable review scope for the entire review.
5. In the report header, explicitly show:
   - `Target branch + commit SHA`
   - `Source branch + commit SHA`
   - `Compared range: <target_sha>..<source_sha>`

Recommended commands:

```bash
# Fetch latest heads
git fetch origin <target-branch> <source-branch>

# Lock exact SHAs
git rev-parse origin/<target-branch>
git rev-parse origin/<source-branch>
```

If user explicitly asks to review local-unpushed commits, state that scope override clearly.

### Stage 1: Define Update Scope

Before deep analysis, lock the review target to the to-be-merged update:

1. Generate exact diff and changed-file list from locked SHAs.
2. Treat this diff as the primary review scope.
3. Do not expand into unrelated full-repo audits unless user explicitly asks.

### Stage 2: Get Diff

Use the locked commit SHAs to avoid branch drift during review:

```bash
# Compare full diff
git diff <target_sha>..<source_sha>

# Show file stats
git diff --stat <target_sha>..<source_sha>

# List changed files
git diff --name-only <target_sha>..<source_sha>

# Inspect one file
git diff <target_sha>..<source_sha> -- path/to/file
```

### Stage 2.5: Source-of-Truth Discipline (Must Follow for Entire Review)

After SHAs are locked, treat the compared commits as the **only source of truth** for review findings.

1. Use only these sources when forming findings:
   - `git diff <target_sha>..<source_sha> ...`
   - `git show <source_sha>:path/to/file`
   - `git show <target_sha>:path/to/file`
2. Do **not** use current working tree file contents as evidence for findings unless the user explicitly asks to review local workspace state.
3. If working tree contents differ from locked SHAs, ignore the working tree and continue using the locked SHAs.
4. When citing line numbers or snippets, ensure they come from the locked commit content, not from an edited local file.

Recommended commands:

```bash
# Read source-branch file content at locked SHA
git show <source_sha>:path/to/file

# Read target-branch file content at locked SHA
git show <target_sha>:path/to/file
```

### Stage 3: Load Just-Enough Context (Support Only)

Load only context needed to understand changed behavior:

1. Read changed hunks first.
2. Read directly related call sites, interfaces, schemas, and tests when required.
3. Read docs/config only when necessary to interpret update behavior.

Do not perform broad architecture exploration unless the update cannot be evaluated otherwise.

### Stage 4: Priority-Based Review (Update-Centric)

Before evaluating issues, align on assumptions:

- Assume update is runnable (developer has done E2E validation)
- Do not spend review time on build/test-pass checks unless user explicitly asks

#### 🔴 Highest Priority: Business Logic / Implementation Approach

**Questions to evaluate:**
- Is the implementation approach reasonable for the stated change?
- Does the update preserve or correctly modify business process behavior?
- Are update-side data flow and state transitions correct?
- Does the update create regressions in directly affected workflows?
- Is requirement interpretation in the update accurate?

**Important**: If business correctness cannot be judged (missing business context, unclear requirements), explicitly state:

> "由于缺乏 [specific business background], 我无法判断这个实现思路是否正确。建议与产品经理确认。"

#### 🔴 High Priority: Logic Errors

- Conditional logic errors introduced in changed paths
- Null/undefined handling issues in changed paths
- Loop condition errors in modified logic
- State management issues caused by the update
- Race conditions introduced or exposed by the update
- Edge cases missing in changed behavior

#### 🔴 High Priority: Security Vulnerabilities

- Injection attacks introduced by changed inputs/queries
- Authentication/authorization regressions in changed flows
- Sensitive data leakage added by the update
- Cryptographic misuse in changed code
- Path traversal or unsafe file handling in changed code

#### 🟡 Other Issues

Performance and code quality issues relevant to changed code.

### Stage 5: Report Findings with Strict Scope Labels and Context

Report findings primarily for changed code. For **each finding**, include:

1. Severity
2. File and line reference
3. **Code context snippet with line numbers** (small, focused snippet)
4. **Background** (why this code exists in flow/business context; 1-3 sentences)
5. Why it is a problem
6. Suggested fix

If issue is outside diff but found while tracing impact, label explicitly:

- `Out-of-scope (context-only)`: not merge-blocking unless it directly affects this update

If user challenges line numbers, re-check against locked SHAs and re-print code context.

### Stage 5.5: Pre-Report Consistency Check

Before sending findings, verify:

1. Every cited snippet and line reference came from locked SHA content.
2. No finding relies on current working tree state unless scope was explicitly overridden.
3. If local files were read for convenience, re-confirm each merge-blocking finding against `git show <sha>:...` before reporting it.

## Risk Assessment

Provide a clear assessment at the end:

- **Business Logic Risk (Update)**: Low / Medium / High / Unable to Judge [needs business confirmation]
- **Logic Risk (Update)**: Low / Medium / High
- **Security Risk (Update)**: Low / Medium / High
- **Overall**: [Can Merge / Needs Modification / Needs Discussion / Needs Business Confirmation]

## Recommendations

Provide actionable items:

1. [Specific issue] → [Recommended action]
2. [Another issue] → [Recommended action]

## Important Principles

1. **Latest Commit First**: Always review latest tips of both branches unless user overrides scope
2. **Honest Assessment**: If business logic cannot be judged, state it clearly with reason
3. **Update Scope First**: Keep review centered on to-be-merged diff
4. **Context as Support**: Use repository context only to understand update impact
5. **Business Logic First**: Evaluate implementation approach before style details
6. **Evidence-Backed Findings**: Every key finding should include line-numbered code context + short background
7. **Be Constructive**: Frame suggestions as improvements
8. **Prioritize**: Focus on important issues over minor nits
9. **Call Out Scope Changes**: If user asks for full-repo audit, acknowledge scope expansion
10. **Skip Compile Verification by Default**: Treat build/run checks as out of scope unless explicitly requested
11. **Locked SHA Is Authoritative**: For branch reviews, never let current working tree contents override the locked commit scope

## Tools Used

- Read - Read files
- Glob - Find files
- Grep - Search patterns
- Bash - Run git diff / git fetch / git rev-parse
