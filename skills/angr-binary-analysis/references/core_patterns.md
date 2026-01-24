# Core angr Patterns

This document contains the essential angr patterns used across all binary analysis tasks.

## 1. Project Initialization

### Basic Project Setup
```python
import angr
import claripy
import sys

# Standard setup for most binaries
project = angr.Project(binary_path, auto_load_libs=False)

# For shared libraries with specific base address
project = angr.Project(library_path, load_options={
    'main_opts': {'base_addr': 0x10000}
})

# For static binaries that need libc functions hooked
project = angr.Project(static_binary_path, auto_load_libs=False)
```

## 2. State Creation Patterns

### Entry State (Most Common)
Start from the binary's entry point with symbolic input.

```python
initial_state = project.factory.entry_state(add_options={
    angr.options.SYMBOL_FILL_UNCONSTRAINED_MEMORY,
    angr.options.SYMBOL_FILL_UNCONSTRAINED_REGISTRIES
})
```

### Blank State
Start execution at a specific address with clean state.

```python
initial_state = project.factory.blank_state(addr=start_address)
```

### Call State
Simulate a function call with parameters.

```python
initial_state = project.factory.call_state(
    function_address,
    param1,
    param2,
    add_options={...}
)
```

### Full Init State
For complex initialization scenarios with custom stdin.

```python
from angr.storage.file import SimPackets
simpackets = SimPackets(name='stdin', write_mode=False, content=[...])
initial_state = project.factory.full_init_state(stdin=simpackets)
```

## 3. Symbolic Variable Creation

### Basic Symbolic Variables
```python
# Single symbolic value (32-bit)
password = claripy.BVS('password', 32)

# Byte-oriented symbolic input (N bytes)
input_buffer = claripy.BVS('input', 8 * size)

# Multiple related variables
password0 = claripy.BVS('password0', 32)
password1 = claripy.BVS('password1', 32)
password2 = claripy.BVS('password2', 32)
```

### Concrete Values
```python
# Concrete bitvector value
claripy.BVV(0x41414141, 32)  # 'AAAA' in hex
```

### Concatenation
```python
# Combine multiple symbolic variables
full_input = claripy.Concat(part0, part1, part2)
```

## 4. Input Injection Methods

### Register Injection
Used when the binary reads input from registers instead of stdin.

```python
# Direct register assignment
initial_state.regs.eax = symbolic_var
initial_state.regs.ebx = symbolic_var2
initial_state.regs.edx = symbolic_var3

# For x86_64
initial_state.regs.rdi = symbolic_var
initial_state.regs.rsi = symbolic_var2
initial_state.regs.rdx = symbolic_var3
initial_state.regs.rcx = symbolic_var4
initial_state.regs.r8 = symbolic_var5
initial_state.regs.r9 = symbolic_var6
```

### Stack Injection
Used when the binary expects input on the stack.

```python
# Store to stack address
initial_state.memory.store(stack_pointer + offset, symbolic_var,
                          size=var_size, endness=project.arch.memory_endness)
```

### Memory Injection
Used when input should be at a specific global memory address.

```python
# Store to global address
initial_state.memory.store(global_address, symbolic_input,
                          size=input_size, endness=project.arch.memory_endness)
```

### Heap Injection (Challenge 06)
Used when input is dynamically allocated on the heap.

```python
# Allocate heap buffer
heap_buffer = initial_state.heap.allocate(buffer_size)

# Store symbolic data to heap
initial_state.memory.store(heap_buffer, symbolic_var,
                          size=size, endness=project.arch.memory_endness)
```

### File-based Input (Challenge 07)
Used when the binary reads from a file.

```python
from angr.storage.file import SimFile

# Create symbolic file content
symbolic_file = SimFile(name='filename.txt', content=symbolic_var)

# Insert into filesystem
initial_state.fs.insert(symbolic_file.name, symbolic_file)
```

### Stdin with Packets
Used for complex input scenarios with multiple reads.

```python
from angr.storage.file import SimPackets

# Create packetized stdin
simpackets = SimPackets(name='stdin',
                       write_mode=False,
                       content=[(input1, size1), (input2, size2)])

# Use with full_init_state
initial_state = project.factory.full_init_state(stdin=simpackets)
```

## 5. Simulation Manager Setup

### Basic Simulation Manager
```python
simgr = project.factory.simulation_manager(initial_state)
```

### With Veritesting (Challenge 12)
Enables static-dynamic hybrid analysis for faster path exploration.

```python
simgr = project.factory.simgr(initial_state, veritesting=True)

# OR add as a technique
simgr.use_technique(angr.exploration_techniques.Veritesting())
```

## 6. Path Exploration Strategies

### Address-Based Exploration
Used when you know the exact success/failure addresses.

```python
simgr.explore(find=target_address, avoid=avoid_address)
```

**Important**: When veritesting is enabled, address-based exploration may be unreliable. Use output-based instead.

### Output-Based Exploration (Preferred)
More robust, checks actual program output.

```python
simgr.explore(
    find=lambda s: b'Good Job.' in s.posix.dumps(sys.stdout.fileno()),
    avoid=lambda s: b'Try again.' in s.posix.dumps(sys.stdout.fileno())
)
```

### Manual Step Loop
Used for complex scenarios with custom state management.

```python
while (simgr.active or simgr.unconstrained) and not simgr.found:
    simgr.step()

    # Custom logic to move states
    if simgr.unconstrained:
        for state in list(simgr.unconstrained):
            # Process unconstrained states
            if is_solution(state):
                simgr.move(from_stash='unconstrained', to_stash='found',
                          filter_func=lambda s: s == state)
```

### Explore with Timeout
Prevent infinite exploration.

```python
simgr.explore(find=target_addr, avoid=avoid_addr, step_limit=10000)
```

## 7. Solution Extraction

### Extract from Stdin
```python
if simgr.found:
    solution_state = simgr.found[0]
    solution = solution_state.posix.dumps(sys.stdin.fileno())
    print(solution.decode())
```

### Extract Symbolic Variable
```python
if simgr.found:
    solution_state = simgr.found[0]

    # As bytes
    solution = solution_state.solver.eval(symbolic_var, cast_to=bytes)

    # As integer
    solution = solution_state.solver.eval(symbolic_var, cast_to=int)

    # As string
    solution = solution_state.solver.eval(symbolic_var).decode()
```

### Extract from Globals
Used with hooks and SimProcedures that store variables in state.globals.

```python
if simgr.found:
    solution_state = simgr.found[0]
    symbolic_var = solution_state.globals['var_name']
    solution = solution_state.solver.eval(symbolic_var, cast_to=bytes)
```

## 8. Memory Operations

### Loading from Memory
```python
# Load single byte
byte_val = state.memory.load(address, 1)

# Load multi-byte with endianness (CRITICAL for correctness)
value = state.memory.load(address, 4, endness=state.arch.memory_endness)

# Load and get concrete value
concrete = value.concrete_value
```

### Storing to Memory
```python
# Store symbolic variable
state.memory.store(address, symbolic_var,
                  size=var_size, endness=state.arch.memory_endness)

# Store concrete value
state.memory.store(address, claripy.BVV(0x41414141, 32))

# Store string (no endness needed)
state.memory.store(address, symbolic_string)
```

## 9. Constraints (Challenge 08)

### Adding Constraints
```python
# Byte-by-byte constraints (more performant)
for i in range(length):
    state.solver.add(symbolic_var.get_byte(i) == target_bytes[i])
    state.solver.add(symbolic_var.get_byte(i) >= 0x41)  # >= 'A'
    state.solver.add(symbolic_var.get_byte(i) <= 0x7a)  # <= 'z'

# Range constraints
state.solver.add(symbolic_var >= min_value)
state.solver.add(symbolic_var <= max_value)

# String equality
state.solver.add(symbolic_var == target_string)
```

### Checking Satisfiability
```python
if state.solver.satisfiable():
    solution = state.solver.eval(symbolic_var, cast_to=bytes)
else:
    print("No solution found!")
```

## 10. Common Options

### Useful Options for Entry State
```python
add_options={
    angr.options.SYMBOL_FILL_UNCONSTRAINED_MEMORY,    # Symbolize unconstrained memory
    angr.options.SYMBOL_FILL_UNCONSTRAINED_REGISTERS,  # Symbolize unconstrained registers
    angr.options.unicorn,                              # Use Unicorn engine for speed
}

remove_options={
    angr.options.LAZY_SOLVES,  # Disable lazy solving for better performance
}
```

## Complete Template

```python
import angr
import claripy
import sys

def solve(binary_path):
    # Load project
    project = angr.Project(binary_path, auto_load_libs=False)

    # Create initial state
    initial_state = project.factory.entry_state(add_options={
        angr.options.SYMBOL_FILL_UNCONSTRAINED_MEMORY,
        angr.options.SYMBOL_FILL_UNCONSTRAINED_REGISTERS
    })

    # Create simulation manager
    simgr = project.factory.simulation_manager(initial_state)

    # Explore
    simgr.explore(
        find=lambda s: b'Good Job.' in s.posix.dumps(1),
        avoid=lambda s: b'Try again.' in s.posix.dumps(1)
    )

    # Extract solution
    if simgr.found:
        solution_state = simgr.found[0]
        solution = solution_state.posix.dumps(0)
        print(solution.decode('utf-8'))
    else:
        raise Exception("No solution found!")

if __name__ == '__main__':
    solve(sys.argv[1])
```
