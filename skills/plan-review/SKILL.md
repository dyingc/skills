---
name: plan-review
description: Audit AI-oriented development plans for implementation correctness, logic completeness, and test coverage adequacy. Use when reviewing a New Project or New Feature plan before coding to detect logic holes, missing failure paths, inconsistent state transitions, hidden assumptions, and weak risk-driven tests.
---

# Plan Review

## Overview

Audit development plans that AI agents will execute.
Prioritize implementation correctness, logic completeness, and risk-driven test coverage.
Ignore schedule estimation and release/operations concerns unless explicitly requested.

## Select Review Mode

Select exactly one mode before review:

1. `New Project`
- Check system boundaries, core architecture feasibility, and high-risk assumption validation.
- Require a minimal end-to-end slice (MVP/PoC) for risky design decisions.

2. `New Feature`
- Check impact scope, compatibility with existing behavior, and regression risk.
- Require explicit list of changed behavior and affected existing paths.

## Normalize Plan Shape

Convert the plan into atomic steps. Each step must include:

- `step_id`
- `goal`
- `preconditions`
- `actions`
- `expected_output`
- `failure_handling`
- `tests`

Flag missing fields as blocking gaps.

## Audit Workflow

1. Determine review mode.
2. Build `Requirement -> Implementation Step` mapping.
3. Build `Implementation Step -> Test` mapping.
4. Check main flow closure from input to output.
5. Check branch completeness:
- success path
- failure path
- boundary path
- invalid/empty input path
- timeout/retry/dependency failure path
6. Check state and data consistency:
- legal state transitions
- idempotency where needed
- race and duplicate execution risks
7. Check assumptions and dependencies:
- external services
- data contracts
- permission and security boundaries
- fallback/degrade behavior
8. Check AI executability:
- explicit and unambiguous actions
- concrete step input/output
- verifiable done criteria
9. Score and return verdict.

## Scoring

Use a 100-point scale:

1. Requirement traceability: `20`
2. Logic completeness: `25`
3. Technical correctness: `20`
4. State/dependency safety: `15`
5. Test quality and risk coverage: `20`

Interpret score:

- `PASS`: 90-100
- `REVISE`: 75-89
- `FAIL`: below 75

## Hard Fail Criteria

Return `FAIL` immediately if any condition is true:

1. Critical path has no failure handling.
2. Critical state transition has no test.
3. High-risk dependency failure is untested.
4. Steps are not AI-executable (missing preconditions/outputs/done criteria).
5. New Feature plan lacks regression coverage for affected existing behavior.

## Test Coverage Requirements

Require tests for each high-risk step in applicable categories:

1. Functional success case
2. Expected failure case
3. Boundary/extreme input case
4. Invalid/empty input case
5. Dependency failure/timeout case
6. Concurrency/retry/idempotency case

Apply risk levels:

- `P0`: security, data integrity, irreversible state changes
- `P1`: core business flow, cross-module integration
- `P2`: non-critical logic

Minimum expectations:

- `P0`: all applicable categories
- `P1`: success + failure + boundary
- `P2`: success + one negative case

## Mode-Specific Checks

### New Project

1. Check whether system boundaries are explicit.
2. Check whether architecture choices match constraints.
3. Check whether highest-risk assumptions are validated early.
4. Check whether minimal end-to-end slice exists.
5. Check whether security/data consistency is integrated into core flow.

### New Feature

1. Check whether impact scope is explicit (modules/APIs/data models).
2. Check whether backward compatibility strategy is explicit.
3. Check whether behavior-change points are enumerated.
4. Check whether regression scope covers affected old behavior.
5. Check whether rollback or feature-flag safety is handled in logic.

## Output Format

Return exactly this structure:

```text
Verdict: PASS | REVISE | FAIL
Mode: New Project | New Feature
Score: <0-100>

Critical Gaps:
1) ...
2) ...

Logic Holes:
1) ...
2) ...

Test Gaps:
1) ...
2) ...

Required Fixes (ordered):
1) ...
2) ...

Re-check Criteria:
1) ...
2) ...
```

## Review Principles

1. Cite exact step IDs for every finding.
2. Prefer concrete fixes over general advice.
3. Reject hidden assumptions.
4. Optimize for safe AI execution, not human intuition.
