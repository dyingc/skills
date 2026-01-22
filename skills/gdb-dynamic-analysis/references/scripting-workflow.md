# GDB Scripting Workflow

## Table of Contents
- [When to Use Scripts](#when-to-use-scripts)
- [Script Development Workflow](#script-development-workflow)
- [Handling Script Failures](#handling-script-failures)
- [Example Script Structure](#example-script-structure)

## When to Use Scripts

**When to use scripts**:
- After interactive command-by-command verification is complete
- For repeatable analysis workflows
- When commands are sequential and predictable

**When NOT to use scripts**:
- During initial exploration/debugging phase
- When commands depend on runtime decision-making
- When execution paths are uncertain

## Script Development Workflow

### 1. Command Verification Phase
- Run each GDB command separately via `gdb_command`
- Verify output is as expected
- Note the execution time for each command
- Do NOT proceed until all commands work individually

### 2. Sequential Verification Phase
- Run the full command sequence one-by-one via MCP tool
- Still separate `gdb_command` calls, check each result
- Ensure commands work in the intended order

### 3. Script Creation Phase
- Convert verified commands to a .gdb script file
- Add comments explaining each step
- Add logging: `set logging file <path>; set logging on`
- Add environment setup: `set pagination off; set confirm off`

### 4. Script Testing Phase
- Run the script via `gdb_command "source <script_path>"`
- Wait for completion
- Check the log file for errors
- Verify output matches expectations

## Handling Script Failures

If a script fails or hangs:
1. Terminate the GDB session immediately (MCP: `gdb_terminate` tool)
2. Start a fresh session (do NOT reuse the corrupted session)
3. Revert to interactive exploration mode
4. Be more cautious in the second attempt - test each command thoroughly
5. Consider simplifying the script

## Example Script Structure

```gdb
# Environment setup
set pagination off
set confirm off
set logging file /tmp/gdb_analysis.log
set logging on

# Breakpoints
break *0x5555555512f0
break *0x5555555513a0

# Execution
run < input.txt

# Inspection at first breakpoint
echo [+] At first breakpoint\n
x/s $rdi
info registers rax rbx

# Continue to next breakpoint
continue

# Inspection at second breakpoint
echo [+] At second breakpoint\n
x/32bx $rsp
info registers

# Cleanup
set logging off
echo [+] Script completed\n
quit
```
