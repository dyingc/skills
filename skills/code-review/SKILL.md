---
name: code-review
description: "Conducts deep code review focused on the to-be-merged update (diff/PR), prioritizing business logic correctness, logic errors, and security vulnerabilities introduced by the update. Use when: (1) User asks to review code, code review, or review branch; (2) User requests branch comparison or reviews diff; (3) User mentions 审查代码, 对比分支, or 审查 diff; (4) User provides two branch names for comparison. Use repository context only as supporting information to understand the update, not as a full codebase audit."
---

# Code Review

## Core Workflow

### Stage 1: Define Update Scope (Must Execute First!)

Before deep analysis, lock the review target to the to-be-merged update:

1. Identify source and target branches (or PR base/head)
2. Generate the exact diff and changed-file list
3. Treat this diff as the primary review scope
4. Do not expand into unrelated full-repo audits unless the user explicitly asks

### Stage 2: Get Diff

Run `git diff` to get the differences between two branches:

```bash
# Compare two branches
git diff main..feature-branch

# Show files changed
git diff main..feature-branch --stat

# Compare specific files
git diff main..feature-branch -- path/to/file

# If user provides branch names, use them directly
git diff branch1..branch2

# List changed files quickly
git diff branch1..branch2 --name-only
```

If user only provides one branch, assume comparison with main/master.

### Stage 3: Load Just-Enough Context (Support Only)

Load only the context needed to understand changed code behavior:

1. Read changed files/hunks first
2. Read directly related call sites, interfaces, schemas, and tests when required
3. Read repository docs/config only when they are necessary to interpret update behavior

Do not perform broad architecture exploration unless the update cannot be evaluated otherwise.

### Stage 4: Priority-Based Review (Update-Centric)

#### 🔴 Highest Priority: Business Logic / Implementation Approach

**Questions to evaluate:**
- Is the update implementation approach reasonable for the stated change?
- Does the update preserve or correctly modify business process behavior?
- Are update-side data flow and state transitions correct?
- Does the update create regressions in directly affected workflows?
- Is requirement interpretation in the update accurate?

**Important**: If you cannot determine whether business logic is correct (e.g., lack of business background, incomplete requirements, uncertain business goals), explicitly state:

> "由于缺乏 [specific business background], 我无法判断这个实现思路是否正确。建议与产品经理确认。"

**How to evaluate business logic:**
- Does changed logic match the requirement?
- Are changed boundary conditions handled correctly?
- Are changed data flow and state changes correct?
- Are there obvious logic flaws introduced by the update?

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

### Stage 5: Report Findings with Strict Scope Labels

Report findings primarily for changed code. For each finding, include:

1. Severity
2. File and line reference
3. Why it is a problem
4. Suggested fix

If an issue is outside the diff but discovered while tracing impact, label it explicitly:

- `Out-of-scope (context-only)`: not part of merge blocking unless it affects this update directly

## Risk Assessment

Provide a clear assessment at the end of the review:

- **Business Logic Risk (Update)**: Low / Medium / High / Unable to Judge [needs business confirmation]
- **Logic Risk (Update)**: Low / Medium / High
- **Security Risk (Update)**: Low / Medium / High
- **Overall**: [Can Merge / Needs Modification / Needs Discussion / Needs Business Confirmation]

## Recommendations

Provide actionable items:

1. [Specific issue] → [Recommended action]
2. [Another issue] → [Recommended action]

## Important Principles

1. **Honest Assessment**: If you cannot judge business logic, state it clearly with reasons
2. **Update Scope First**: Keep the review centered on the to-be-merged diff
3. **Context as Support**: Use repository context only to understand update impact
4. **Business Logic First**: Evaluate whether the update implementation approach is reasonable first
5. **Focus on Approach Over Details**: Care about "whether this is correct" rather than just "whether code is well-written"
6. **Be Specific**: Reference specific files, functions, and line numbers
7. **Be Constructive**: Frame suggestions as improvements
8. **Prioritize**: Don't get overwhelmed by small issues; focus on important problems
9. **Call Out Scope Changes**: If user asks for full-repo audit, explicitly acknowledge scope expansion

## Tools Used

- Read - Read files
- Glob - Find files
- Grep - Search patterns
- Bash - Run git diff
