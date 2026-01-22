---
name: git-commit-message
description: Generate clean git commit messages from staged files. Use this skill when the user asks to create a git commit message, wants to commit changes, or needs help summarizing staged changes. The skill analyzes staged files to generate concise commit messages in English (or other specified language), and commits if the user approves. Does NOT include co-authorship tags or AI attribution.
---

# Git Commit Message Generator

## Overview

Generate clean git commit messages by analyzing staged changes and commit the changes if the user approves.

## Process

1. **Check staged changes**: Run `git status` and `git diff --staged` to understand what will be committed

2. **Analyze changes**: Review the diff to understand:
   - What files changed
   - What the changes accomplish
   - The nature of the changes (bug fix, new feature, refactoring, etc.)

3. **Determine language**: Use English by default. Switch to another language only if the user explicitly requests it or if the majority of the codebase/file changes are in that language.

4. **Generate commit message**: Create a message following the 50/72 rule:
   - **Subject line** (first line): Max 50 characters, imperative mood ("add" not "added" or "adds"), summarize WHAT and WHY
   - **Body** (optional): For non-trivial changes, add a blank line followed by detailed explanation, wrapped at 72 characters per line
   - **When to add a body**:
     - Multiple files changed with different purposes
     - Bug fixes (explain the bug and solution)
     - Refactoring (explain the motivation)
     - Performance changes (include before/after context)
     - anything that isn't immediately obvious from the diff
   - **Simple changes**: Subject line only is fine (e.g., typo fixes, straightforward refactorings)

5. **Present to user**: Show the proposed commit message and ask for approval. Keep it simple - just show the message, don't explain the format choices.

6. **Commit if approved**: If user approves, run `git commit -m "message"` with the approved message

## Important Rules

- **NEVER** add co-authorship tags like "Co-Authored-By: Claude Sonnet <noreply@anthropic.com>"
- **NEVER** add AI attribution of any kind
- Keep messages clean and professional
- Only commit staged files - do not stage additional files unless explicitly asked
