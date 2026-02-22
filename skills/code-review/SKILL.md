---
name: code-review
description: "Conducts deep code review focusing on business logic correctness, logic errors, and security vulnerabilities. Use when: (1) User asks to review code, code review, or review branch; (2) User requests branch comparison or reviews diff; (3) User mentions 审查代码, 对比分支, or 审查 diff; (4) User provides two branch names for comparison. First understands repository context, then analyzes branch differences, explicitly assesses implementation approach reasonableness, and clearly states when business logic judgment cannot be made due to lack of context."
---

# Code Review

## Core Workflow

### Stage 1: Understand Repository Context (Must Execute First!)

Before viewing any diff, you MUST understand the repository:

1. **Repository Purpose** - What does the project do? What is the core business?
2. **Architecture Overview** - What are the key components?
3. **Tech Stack** - What frameworks, languages, and patterns are used?
4. **Business Logic** - What are the core business processes?

**How to gather context:**
- Read README.md and key documentation files
- Explore project structure with Glob
- Check package.json, Cargo.toml, requirements.txt, or similar dependency files
- Look for architecture or design documents
- Use Grep to find key business logic files

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
```

If user only provides one branch, assume comparison with main/master.

### Stage 3: Priority-Based Review

#### 🔴 Highest Priority: Business Logic / Implementation Approach

**Questions to evaluate:**
- Is the implementation approach reasonable?
- Is the business process correct?
- Is the architecture appropriate?
- Is there a better implementation approach?
- Is the requirement understanding accurate?

**Important**: If you cannot determine whether business logic is correct (e.g., lack of business background, incomplete requirements, uncertain business goals), explicitly state:

> "由于缺乏 [specific business background], 我无法判断这个实现思路是否正确。建议与产品经理确认。"

**How to evaluate business logic:**
- Does the code logic match the requirements?
- Are boundary conditions handled correctly?
- Is data flow reasonable?
- Are state changes correct?
- Are there obvious logic flaws?

#### 🔴 High Priority: Logic Errors

- Conditional logic errors
- Null/undefined handling issues
- Loop condition errors
- State management issues
- Race conditions
- Edge cases not handled

#### 🔴 High Priority: Security Vulnerabilities

- Injection attacks (SQL, XSS, command injection)
- Authentication/authorization issues
- Sensitive data leakage
- Cryptographic weaknesses
- Path traversal

#### 🟡 Other Issues

Performance and code quality issues

## Risk Assessment

Provide a clear assessment at the end of the review:

- **Business Logic Risk**: Low / Medium / High / Unable to Judge [needs business confirmation]
- **Logic Risk**: Low / Medium / High
- **Security Risk**: Low / Medium / High
- **Overall**: [Can Merge / Needs Modification / Needs Discussion / Needs Business Confirmation]

## Recommendations

Provide actionable items:

1. [Specific issue] → [Recommended action]
2. [Another issue] → [Recommended action]

## Important Principles

1. **Honest Assessment**: If you cannot judge business logic, state it clearly with reasons
2. **Business Logic First**: Evaluate whether the implementation approach is reasonable first
3. **Context First**: Understand codebase and business background before reviewing
4. **Focus on Approach Over Details**: Care about "whether this is correct" rather than just "whether code is well-written"
5. **Be Specific**: Reference specific files, functions, and line numbers
6. **Be Constructive**: Frame suggestions as improvements
7. **Prioritize**: Don't get淹没 by small issues, focus on important problems

## Tools Used

- Read - Read files
- Glob - Find files
- Grep - Search patterns
- Bash - Run git diff
