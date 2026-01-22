---
name: gdb-dynamic-analysis
description: Performs dynamic binary analysis using GDB MCP server. Use when static analysis assumptions need runtime verification, when tracing execution flow, inspecting memory at specific points, observing program behavior at runtime, validating control flow predictions, or debugging binary behavior. Essential for understanding runtime constraints, observing actual program state, and bridging the gap between static analysis and dynamic execution.
license: MIT License
compatibility: Requires GDB MCP server with access to binary files
allowed-tools: create_session close_session get_session get_all_sessions start_debugging stop_debugging get_registers get_register_names get_local_variables get_stack_frames read_memory set_breakpoint delete_breakpoint get_breakpoints continue_execution next_execution step_execution
---

# GDB Dynamic Binary Analysis

## When to Use This Skill

Invoke this skill when:
- Static analysis reveals a path that needs runtime verification
- You need to trace actual execution flow vs theoretical paths
- Memory contents need inspection at specific program points
- Register states need verification
- Input processing needs observation
- Control flow decisions need validation
- Function call sequences need confirmation
- Buffer contents after input processing need inspection
- Runtime constraints need investigation

## Session Lifecycle

### Starting a Session
1. Use `create_session` with `gdb_path` and `working_dir`
2. Load the program using the session ID
3. Start debugging with `starti` or `start`
4. Calculate base address if needed (use `info files` or `info proc mappings`)

### Managing Breakpoints
- Set breakpoints: `set_breakpoint` or via `gdb_command` with `break <address>`
- View breakpoints: `get_breakpoints`
- Delete breakpoints: `delete_breakpoint`

### Execution Control
- Continue: `continue_execution`
- Step over: `next_execution`
- Step into: `step_execution`
- Arbitrary commands: `gdb_command` for any GDB command

### Inspection
- Registers: `get_registers`, `get_register_names`
- Memory: `read_memory` or `x` command via `gdb_command`
- Stack: `get_stack_frames`
- Local variables: `get_local_variables`
- Print expressions: `gdb_print` (if available) or via `gdb_command`

### Cleanup
Always close sessions with `close_session` when done.

## Common Workflows

### 1. Basic Verification Workflow
Use to verify static analysis assumptions:

1. Start session and load binary
2. Set breakpoint at target address (calculate: base + offset)
3. Run to breakpoint with input if needed
4. Inspect registers/memory to verify assumptions
5. Continue execution or inspect further
6. Close session

### 2. Input Observation Workflow
Use to see how input is processed:

1. Create input file (shell command or script)
2. Set breakpoint after input is read/stored
3. Run with input redirected
4. Examine memory at buffer location
5. Trace subsequent processing

### 3. Trace Execution Workflow
Use to follow control flow:

1. Set breakpoints at multiple control flow points
2. Step through or continue to each breakpoint
3. Record which paths are taken
4. Compare with static analysis predictions

### 4. Automated GDB Script Workflow
For complex multi-step scenarios, see detailed references:
- **Script development workflow**: [references/scripting-workflow.md](references/scripting-workflow.md)
- **Deadlock prevention**: [references/deadlock-prevention.md](references/deadlock-prevention.md)

## Important Considerations

### GDB Extensions (GEF, Pwndbg, etc.)
**Important**: Always disable GDB extensions to maintain consistent environment.

**Rationale**:
- Extensions may change output formats, breaking script parsing
- Extensions add custom commands that may conflict with standard GDB
- Reduces complexity and environment variability

**Environment Setup Commands**:
```gdb
set pagination off
set confirm off
```

**Verification**:
- GEF: Check for `gef-*` commands
- Pwndbg: Check for custom prompts or enhanced register displays

### ASLR (Address Space Layout Randomization)
- Programs load at different addresses each run
- Always calculate: `actual_address = base_address + relative_offset`
- Get base address from `info files` or `info proc mappings` after `starti`
  - **Using `info files`**: Look for "Entry point" which gives absolute address; subtract static offset to get base
  - **Using `info proc mappings`**: Look for the first mapped memory region belonging to the binary (the read-executable segment)
- Example: If main is at offset 0x12f0 and base is 0x555555554000, set breakpoint at 0x5555555552f0

### Input Handling
- For programs reading stdin, create input file and redirect: `run < input_file`
- Use `gdb_command` with shell commands to create inputs
- Buffer contents can be inspected after they're written

### Memory Inspection Patterns
- Use `x/Nbx <address>` for byte display
- Use `x/s <address>` for string display
- Use `x/NI <address>` for disassembly

### Register Access
- Use `$rip`, `$rsp`, `$rbp`, etc. in expressions
- Full register list: `info registers`
- Specific registers: `info registers <reg1> <reg2>`

## Best Practices

### Core Best Practices

1. **Always clean up**: Close sessions when complete
2. **Verify addresses**: Calculate breakpoints correctly considering ASLR
3. **Start small**: Verify basic workflow before complex analysis
4. **Use breakpoints strategically**: Don't step through every instruction
5. **Document findings**: Record what was verified vs what wasn't

### GDB Scripting
For complex multi-step scenarios, see detailed references:
- **Script development workflow**: [references/scripting-workflow.md](references/scripting-workflow.md)
- **Deadlock prevention**: [references/deadlock-prevention.md](references/deadlock-prevention.md)

**When to use scripts**: After interactive verification is complete, for repeatable workflows.

## Example Use Cases

### Verifying String Length Check
After static analysis finds a length check at offset:

```python
# 1. Start session
session_id = create_session(gdb_path="gdb", working_dir="/path/to/binary")

# 2. Load and start
# (via gdb commands)

# 3. Calculate and set breakpoint
# If check is at 0x1a10 relative
# Base from info files: 0x555555554000
# Breakpoint: 0x555555555a10

# 4. Run with test input
# Run with input that exceeds expected length

# 5. Inspect at breakpoint
# Check register values (length in rbx, buffer in r12)
# Verify check logic

# 6. Continue or close
```

### Tracing Complex Input Handling
When analyzing programs with complex input processing (e.g., C++ std::cin, scanf, custom parsers):

```python
# 1. Create GDB script to trace input handling behavior
# 2. Set breakpoints before and after input operations
# 3. Run with various test inputs
# 4. Observe actual execution paths taken
# 5. Verify buffer handling and edge cases
```

### Validating Static Analysis Predictions
Compare static analysis results with dynamic execution:

1. Use static analysis tools (Ghidra, radare2, etc.) to predict execution path
2. Use GDB to trace actual execution with sample inputs
3. Compare: branches taken, memory states, function calls, return values
4. Identify discrepancies for further investigation

## Troubleshooting

### Breakpoint Not Hit
- Verify address calculation (base + offset)
- Check if code path is actually reached
- Ensure input triggers the target code

### Session Issues
- Close and recreate session
- Verify binary path is correct
- Check permissions

### Memory Read Failures
- Address may be inaccessible (not mapped)
- Use `info proc mappings` to check memory layout
- Verify the program state at inspection point

## Integration with Other Tools

This skill works well with:
- **Ghidra MCP**: Get static analysis, addresses, function offsets for target locations
- **radare2**: Additional static analysis context and binary information
- **angr**: Validate symbolic execution assumptions (when applicable)
- **Any static analysis tool**: Use static results to guide where to set breakpoints and what to inspect

## Notes

- This skill is for **runtime verification**, not primary analysis
- Always perform static analysis first to know where to look
- Document both expected and actual behaviors
- Use findings to refine static analysis or symbolic execution models
