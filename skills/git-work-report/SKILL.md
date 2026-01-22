---
name: git-work-report
description: Generate concise work reports from git commit history and uncommitted changes. Use when the user requests work summaries, daily reports, weekly reports, or asks "what did I work on" within a git repository. Analyzes actual code changes across all branches to provide accurate work highlights.
---

# Git Work Report

Generate concise work reports by analyzing actual code changes, diffs, and modifications within a specified time period.

## Workflow

1. Verify the current directory is a git repository
2. Query git log for commits within the user-specified time period (all branches)
3. For each commit, examine the actual diff/changes to understand what was done
4. Check for uncommitted work (staged and unstaged changes)
5. Analyze changes to identify major work items
6. Summarize into highlights (default 3 for daily reports)

## Time Periods

Parse user requests for time periods:
- "today" / "today's report" → `--since="midnight"`
- "yesterday" → `--since="yesterday midnight" --until="midnight"`
- "this week" / "weekly report" → `--since="1 week ago"`
- "last week" → `--since="2 weeks ago" --until="1 week ago"`
- Custom ranges → Use appropriate git date format (e.g., `--since="2026-01-20" --until="2026-01-22"`)

## Git Commands

Check if current directory is a git repository:
```bash
git rev-parse --is-inside-work-tree
```

Get commits from all branches within time period:
```bash
git log --all --since="<start>" --until="<end>" --pretty=format:"%H" --author="$GIT_AUTHOR_NAME"
```

Or if no author specified (all commits):
```bash
git log --all --since="<start>" --until="<end>" --pretty=format:"%H"
```

Get detailed diff for a specific commit:
```bash
git show <commit-hash> --stat
git show <commit-hash> --format="" --no-patch
```

Get list of changed files in a commit:
```bash
git show <commit-hash> --name-status --format=""
```

Get uncommitted changes (unstaged):
```bash
git status --short
git diff --name-status
```

Get uncommitted changes (staged):
```bash
git diff --staged --name-status
```

Get untracked files:
```bash
git ls-files --others --exclude-standard
```

## Analysis Guidelines

### Understanding Changes

Look beyond commit messages. Analyze:

1. **Files changed**: Which files were modified/added/deleted?
2. **Code structure**: New functions, classes, or modules?
3. **File types**: What kind of work (e.g., `.py` = Python code, `.md` = docs, `.test.js` = tests)?
4. **Impact**: What functionality was added or modified?

### Grouping Work

Group related changes together:
- Multiple commits to the same feature/module → One highlight
- Test additions alongside code changes → Include in the same highlight
- Documentation updates for a feature → Part of feature work

### Writing Highlights

- Use present tense: "Fixes authentication bug in login flow"
- Be specific: "Add user profile page with avatar upload" not "Update UI"
- Focus on functional changes: Bug fixes, new features, refactoring
- One concise sentence per highlight
- Default to 3 highlights for daily reports

### Handling Uncommitted Work

Check for:
- Modified files: What's being worked on right now?
- Staged changes: What's ready to commit?
- New files: What's being created?

Include as a separate note: "Currently working on: X, Y, Z"

### Priority

When summarizing many changes, prioritize:
1. New features or major functionality
2. Bug fixes
3. Refactoring or code improvements
4. Documentation updates
5. Minor tweaks or formatting
