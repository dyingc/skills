---
name: angr-binary-analysis
description: Automated binary analysis and symbolic execution using angr framework. Use this skill when the user asks to: (1) Solve CTF challenges or find correct inputs automatically, (2) Generate symbolic execution scripts for binaries, (3) Perform automated constraint solving or path finding, (4) Analyze taint analysis on controlled data, (5) Hook functions and simulate library calls, (6) Create automated solutions for binary exploitation challenges. This skill integrates static analysis tools with angr to automatically understand binary structure and generate solving strategies.
---

# angr Binary Analysis

This skill provides automated binary analysis capabilities using the angr symbolic execution framework. It integrates static analysis tools to understand binary structure and automatically generate appropriate solving strategies.

## Quick Start

For automated binary analysis and script generation:

```python
# Use the provided analysis script
python scripts/analyze_binary.py <binary_path> --output solution.py
```

This will:
1. Analyze binary architecture and properties
2. Identify functions, imports, and strings
3. Determine appropriate angr technique
4. Generate a working solution script

## Core Workflow

### Step 1: Analyze Binary Structure

Use available tools to understand the binary:

**Preferred: Ghidra MCP (if available)**
```python
# Use Ghidra for comprehensive analysis
mcp__ghidra__list_functions()
mcp__ghidra__decompile_function("main")
mcp__ghidra__get_xrefs_to(address)
```

**Alternative: objdump/radare2**
```bash
objdump -d binary | less
r2 -A binary -c pdf @main
strings binary | grep -i "good\|job\|try again"
```

### Step 2: Determine Technique

Match binary characteristics to angr technique:

| Binary Characteristics | Technique |
|------------------------|-----------|
| Standard input/output | Basic symbolic execution |
| Uses scanf/scanf-like | scanf hooking |
| Statically linked | Libc function hooks |
| Shared library (.so) | Base address + call_state |
| Arbitrary memory read/write | Taint analysis |
| Control flow hijack | Unconstrained state handling |

### Step 3: Choose Solution Pattern

Select appropriate pattern from [reference documentation](references/):
- **[core_patterns.md](references/core_patterns.md)**: Basic setup, symbolic variables, input injection, exploration
- **[advanced_techniques.md](references/advanced_techniques.md)**: Hooks, SimProcedures, taint analysis, static binaries

### Step 4: Generate angr Script

Use the appropriate template for the identified technique. Key components:

1. **Project Setup**: Load binary with appropriate options
2. **State Creation**: Create entry_state, blank_state, or call_state
3. **Symbolic Input**: Create and inject symbolic variables
4. **Exploration**: Explore to success condition while avoiding failure
5. **Solution Extraction**: Extract and print the solution

## Common Scenarios

### Basic Path Finding (Challenges 00-02)

**When to use**: Binary reads from stdin and checks input against a condition.

**Key patterns**:
- Use `project.factory.entry_state()`
- Explore with output-based lambdas: `find=lambda s: b'Good Job.' in s.posix.dumps(1)`
- Extract from stdin: `solution_state.posix.dumps(0)`

See [core_patterns.md](references/core_patterns.md) for complete template.

### Symbolic Registers/Stack (Challenges 03-04)

**When to use**: Binary expects input in registers or on stack instead of stdin.

**Key patterns**:
```python
# Register injection
initial_state.regs.eax = symbolic_var
initial_state.regs.ebx = symbolic_var2

# Stack injection
initial_state.memory.store(stack_addr + offset, symbolic_var)
```

### Symbolic Memory (Challenge 05)

**When to use**: Input is stored at a specific global memory address.

**Critical**: Always specify `endness=state.arch.memory_endness` for multi-byte operations.

### scanf Hooking (Challenge 11)

**When to use**: Binary uses scanf/scanf-like functions for input.

**Key patterns**:
```python
class ScanfHook(angr.SimProcedure):
    def run(self, format_str, *args):
        scanf_inputs = []
        for i, arg in enumerate(args):
            scanf_input = claripy.BVS(f'scanf_{i}', size)
            self.state.memory.store(arg, scanf_input)
            scanf_inputs.append(scanf_input)

        self.state.globals['scanf_inputs'] = scanf_inputs
        return claripy.BVV(len(args), 32)

project.hook_symbol('__isoc99_scanf', ScanfHook())
```

### Static Binary (Challenge 13)

**When to use**: Binary is statically linked (no libc dependencies).

**Key patterns**:
```python
from angr import SIM_PROCEDURES
libc = SIM_PROCEDURES['libc']

# Hook commonly-used functions
project.hook(strcmp_addr, libc['strcmp']())
project.hook(printf_addr, libc['printf']())
project.hook(scanf_addr, libc['scanf']())
```

### Arbitrary Memory Operations (Challenges 15-17)

**When to use**: Binary performs arbitrary reads/writes or jumps based on user input.

**Key patterns**:
- Use `is_controlled_by_user()` to check if values are tainted
- Process unconstrained states to catch control flow hijacks
- Constrain symbolic addresses/values to targets

See [advanced_techniques.md](references/advanced_techniques.md) for taint analysis patterns.

### Shared Library (Challenge 14)

**When to use**: Analyzing a shared library (.so file).

**Key patterns**:
```python
# Set base address for PIC
project = angr.Project(library_path, load_options={
    'main_opts': {'base_addr': 0x10000}
})

# Start at function offset
state = project.factory.call_state(base_addr + function_offset, param1, param2)

# Constrain return value
solution_state.add_constraints(solution_state.regs.eax == 0)
```

## Integration with Static Analysis Tools

### Ghidra MCP (Preferred)

For comprehensive binary analysis:

```python
# List all functions
mcp__ghidra__list_functions()

# Decompile specific function
mcp__ghidra__decompile_function("main")

# Find cross-references
mcp__ghidra__get_xrefs_to(address)

# Rename function for clarity
mcp__ghidra__rename_function("old_name", "descriptive_name")

# Set comments
mcp__ghidra__set_decompiler_comment(address, "Suspicious input handling")
```

### objdump

For quick disassembly:

```bash
# Disassemble main function
objdump -d binary | grep -A 50 "<main>"

# Find strings
objdump -s -j .rodata binary

# Find imports
objdump -T binary
```

### radare2

For interactive analysis:

```bash
# Analyze binary
r2 -A binary

# Disassemble function
pdf @main

# Find strings
iz

# Find calls to specific function
afl | grep scanf
```

## Critical Best Practices

### 1. Always Specify Endianness

```python
# WRONG - will fail on multi-byte values
state.memory.store(addr, value)

# CORRECT
state.memory.store(addr, value, endness=state.arch.memory_endness)
```

### 2. Use Output-Based Exploration with Veritesting

```python
# If veritesting is enabled
simgr = project.factory.simgr(initial_state, veritesting=True)

# DON'T use address-based exploration (unreliable with veritesting)
# simgr.explore(find=0x400123)  # May miss the solution!

# DO use output-based exploration
simgr.explore(find=lambda s: b'Good Job.' in s.posix.dumps(1))
```

### 3. Check Satisfiability

```python
# Before constraining or solving
if state.solver.satisfiable():
    solution = state.solver.eval(symbolic_var)
else:
    print("Unsatisfiable constraints!")
```

### 4. Use state.globals for Cross-Hook Data

```python
# In hook
self.state.globals['user_input'] = symbolic_input

# In solution extraction
symbolic_var = solution_state.globals['user_input']
solution = solution_state.solver.eval(symbolic_var, cast_to=bytes)
```

### 5. Handle Unconstrained States for Exploitation

```python
# For challenges with arbitrary jumps
while (simgr.active or simgr.unconstrained) and not simgr.found:
    if simgr.unconstrained:
        for state in list(simgr.unconstrained):
            # Try to constrain EIP/RIP to target
            state.add_constraints(state.regs.eip == target_addr)
            if state.solver.satisfiable():
                simgr.move(from_stash='unconstrained', to_stash='found',
                          filter_func=lambda s: s == state)
    simgr.step()
```

## Troubleshooting

### No Solution Found

1. **Check simulation manager state**:
   ```python
   print(f"Active: {len(simgr.active)}, Found: {len(simgr.found)}")
   ```

2. **Verify success condition**:
   ```python
   # Make sure you're checking the right output
   state.posix.dumps(1)  # stdout
   state.posix.dumps(2)  # stderr
   ```

3. **Increase exploration limits**:
   ```python
   simgr.explore(find=target, step_limit=100000)
   ```

### Performance Issues

1. **Enable Unicorn engine** for concrete execution speedup
2. **Use Veritesting** to merge similar states
3. **Add step limits** to prevent infinite exploration

### Memory Errors

1. **Disable auto_load_libs**: `auto_load_libs=False`
2. **Add memory limit**: `export ANGR_MAX_MEMORY=2G`
3. **Useunicorn option**: `add_options={angr.options.unicorn}`

## Reference Documentation

- **[core_patterns.md](references/core_patterns.md)**: Essential angr patterns for all tasks
- **[advanced_techniques.md](references/advanced_techniques.md)**: Specialized techniques (hooks, SimProcedures, taint analysis, static binaries)
- **[analyze_binary.py](scripts/analyze_binary.py)**: Automated binary analysis script

## Development Notes

This skill is based on the angr_ctf framework covering:
- Basic symbolic execution (00-02)
- Symbolic registers/stack/memory (03-05)
- Dynamic memory and file I/O (06-07)
- Constraints and hooks (08-09)
- SimProcedures and veritesting (10-12)
- Static binaries and libraries (13-14)
- Arbitrary memory operations (15-17)
