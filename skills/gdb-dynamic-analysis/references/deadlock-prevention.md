# Deadlock Prevention in GDB Scripts

## Table of Contents
- [Common Deadlock Scenarios](#common-deadlock-scenarios)
- [Command Failure Cascade](#command-failure-cascade)
- [Script Design Guidelines](#script-design-guidelines)
- [Testing Checklist](#testing-checklist)
- [Recovery from Deadlocks](#recovery-from-deadlocks)

## Common Deadlock Scenarios

**Important**: GDB scripts run non-interactively. Deadlocks are particularly problematic because:
- No interactive recovery possible
- Script may hang indefinitely
- Session state becomes unpredictable

### 1. `until` with unreachable address

```gdb
until 0x12345678  # HANGS if address never reached!
```

- **Prevention**: Verify address is on execution path first
- **Alternative**: Use `break <addr>; continue` instead

### 2. `finish` in problematic functions

```gdb
finish  # HANGS in main() or functions calling exit()!
```

- **High-risk**: `main()`, functions calling `exit()`/`_exit()`, signal handlers
- **Prevention**: Use `continue` to next breakpoint instead
- **Test**: Always test `finish` interactively before scripting

### 3. `continue` without reachable breakpoints

```gdb
continue  # Runs forever if no breakpoint or infinite loop!
```

- **Prevention**: Always ensure at least one reachable breakpoint exists
- **Verification**: List breakpoints before `continue` with `info breakpoints`

### 4. Conditional breakpoints that never trigger

```gdb
break *0x12345678 if $rax == 999999  # May never trigger!
continue
```

- **Prevention**: Test conditions interactively first
- **Alternative**: Use unconditional breakpoint + manual condition check

### 5. Commands that require input

```gdb
run  # HANGS waiting for stdin input
```

- **Prevention**: Always provide input via file: `run < input.txt` or `set args < input.txt`

## Command Failure Cascade

```gdb
# RISKY: If program exits after continue, rest is skipped
continue
x/s $rdi  # Never executes if program exited

# SAFER: Check if still running after continue
continue
if $_inferior == 0
  echo [!] Program exited unexpectedly\n
else
  echo [+] Still running\n
  x/s $rdi
end
```

Use `$_inferior` convenience variable:
- `0`: No inferior (program exited or not started)
- Non-zero: Inferior running

## Script Design Guidelines

### 1. Always set breakpoints before execution

```gdb
# GOOD: Set breakpoints first
break *0x12345678
run < input.txt
continue
```

### 2. Avoid `until` in scripts

```gdb
# AVOID
until 0x12345678

# PREFER
break *0x12345678
continue
```

### 3. Avoid `finish` in scripts

```gdb
# AVOID
finish

# PREFER
break *0x12345678  # Set breakpoint after return
continue
```

## Testing Checklist

Before finalizing a script:
- [ ] Each command tested interactively
- [ ] Full sequence tested interactively (via separate MCP calls)
- [ ] Verify no `until` commands in script
- [ ] Verify no `finish` commands in script (unless tested)
- [ ] Verify all breakpoints set before execution
- [ ] Verify input provided for programs that read stdin

## Recovery from Deadlocks

If a script hangs:
1. Terminate entire GDB session (MCP: `gdb_terminate`)
2. Start a completely fresh session
3. Analyze what caused the deadlock (check log file if available)
4. Fix the issue in the script
5. Start over from command-by-command verification
