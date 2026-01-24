# Advanced angr Techniques

This document covers specialized techniques for complex binary analysis scenarios.

## 1. Function Hooking

### Simple Address Hook
Hook at a specific address, skip bytes of execution.

```python
@project.hook(address, length=num_bytes_to_skip)
def hook_function(state):
    # Access parameters from stack (x86)
    param1 = state.memory.load(state.regs.esp + 4, 4,
                              endness=state.arch.memory_endness)
    param2 = state.memory.load(state.regs.esp + 8, 4,
                              endness=state.arch.memory_endness)

    # Perform custom logic
    result = param1 + param2

    # Set return value
    state.regs.eax = result

    # Set return address (if needed)
    state.regs.eip = state.memory.load(state.regs.esp, 4,
                                      endness=state.arch.memory_endness)
```

### Symbol-Based Hooking
Hook by function name instead of address.

```python
# Hook by symbol name
project.hook_symbol('function_name', HookClass())

# Example: Hook strcmp
class StrcmpHook(angr.SimProcedure):
    def run(self, str1_addr, str2_addr):
        # Load strings
        str1 = state.memory.load(str1_addr, 100)
        str2 = state.memory.load(str2_addr, 100)

        # Compare
        if self.state.solver.symbolic(str1) or self.state.solver.symbolic(str2):
            # Return symbolic comparison
            return claripy.BVS('strcmp_result', 32)
        else:
            # Concrete comparison
            str1_str = self.state.solver.eval(str1, cast_to=bytes)
            str2_str = self.state.solver.eval(str2, cast_to=bytes)
            return claripy.BVV(0 if str1_str == str2_str else 1, 32)

project.hook_symbol('strcmp', StrcmpHook())
```

### SimProcedure Pattern
Create reusable procedure hooks.

```python
class CustomSimProcedure(angr.SimProcedure):
    def run(self, param1, param2, param3):
        # Parameters are automatically loaded based on calling convention

        # Create symbolic input
        symbolic_input = claripy.BVS('input', 8 * size)

        # Store to memory at param1 address
        self.state.memory.store(param1, symbolic_input,
                               endness=self.arch.memory_endness)

        # Store in globals for later retrieval
        self.state.globals['input'] = symbolic_input

        # Return value
        return claripy.BVV(1, 32)

# Hook the function
project.hook_symbol('function_name', CustomSimProcedure())
```

## 2. scanf Simulation (Challenge 11)

### Basic scanf Hook
```python
class ScanfHook(angr.SimProcedure):
    def run(self, format_str, *args):
        # Create symbolic inputs for each format specifier
        scanf_data = {}
        for i, arg in enumerate(args):
            # Create symbolic variable
            scanf_data[f'input_{i}'] = claripy.BVS(f'scanf_{i}', 32)

            # Store to argument address
            self.state.memory.store(arg, scanf_data[f'input_{i}'],
                                   endness=self.arch.memory_endness)

        # Store in globals
        self.state.globals['scanf_inputs'] = scanf_data

        # Return number of items read
        return claripy.BVV(len(args), 32)

project.hook_symbol('__isoc99_scanf', ScanfHook())
```

### SimProcedures Library (Challenge 10)
```python
from angr import SIM_PROCEDURES

# Use built-in SimProcedures for libc functions
scanf_simproc = SIM_PROCEDURES['libc']['scanf']()
project.hook_symbol('scanf', scanf_simproc)

printf_simproc = SIM_PROCEDURES['libc']['printf']()
project.hook_symbol('printf', printf_simproc)

strcmp_simproc = SIM_PROCEDURES['libc']['strcmp']()
project.hook_symbol('strcmp', strcmp_simproc)
```

## 3. Static Binary Analysis (Challenge 13)

### Hooking Libc Functions
For static binaries, hook commonly-used libc functions.

```python
from angr import SIM_PROCEDURES

# Get libc SimProcedures
libc = SIM_PROCEDURES['libc']

# Find and hook strcmp calls
strcmp = libc['strcmp']
for addr, func in project.kb.functions.items():
    if func.name and 'strcmp' in func.name:
        project.hook(func.addr, strcmp())

# Hook other common functions
project.hook(addr_printf, libc['printf']())
project.hook(addr_scanf, libc['scanf']())
project.hook(addr_strlen, libc['strlen']())
project.hook(addr_memcpy, libc['memcpy']())
```

### Complete Static Binary Setup
```python
import angr
from angr import SIM_PROCEDURES

project = angr.Project(static_binary, auto_load_libs=False)

# Hook libc functions
libc = SIM_PROCEDURES['libc']

# You'll need to find these addresses with objdump/radare2
project.hook(0x08048450, libc['strcmp']())
project.hook(0x08048460, libc['printf']())
project.hook(0x08048470, libc['scanf']())

# Continue with normal analysis
initial_state = project.factory.entry_state()
simgr = project.factory.simgr(initial_state)
```

## 4. Shared Library Analysis (Challenge 14)

### Setting Base Address
```python
# Load with specific base address for PIC
project = angr.Project(library_path, load_options={
    'main_opts': {'base_addr': 0x10000000}
})

# Get base address from loader
base_addr = project.loader.main_object.mapped_base

# Call function at offset
function_offset = 0x1234  # From objdump/radare2
state = project.factory.call_state(
    base_addr + function_offset,
    param1,
    param2
)
```

### Constraining Return Values
```python
# Explore to function end
simgr.explore(find=lambda s: s.addr == base_addr + return_offset)

if simgr.found:
    solution_state = simgr.found[0]

    # Constrain return value (eax for x86)
    solution_state.add_constraints(solution_state.regs.eax == 0)

    # Solve for parameters
    param1_solution = solution_state.solver.eval(param1, cast_to=bytes)
    param2_solution = solution_state.solver.eval(param2, cast_to=bytes)
```

## 5. Taint Analysis (Challenges 15-17, xx)

### Taint Detection
Check if a value is controlled by user input.

```python
def is_controlled_by_user(state, value):
    """Check if value is symbolic and from user input"""
    if not state.solver.symbolic(value):
        return False

    # Get variable name
    sym_name = list(value.variables)[0]
    return 'user_input' in sym_name or 'stdin' in sym_name

# Usage
if is_controlled_by_user(state, state.regs.eip):
    print("Controlled flow hijack detected!")
```

### Arbitrary Read Detection (Challenge 15)
```python
# Load value from controlled address
controlled_addr = state.memory.load(base_addr, 4,
                                    endness=state.arch.memory_endness)

# Check if address is controlled
if state.solver.symbolic(controlled_addr):
    # Try to read from that address
    leaked_value = state.memory.load(controlled_addr, 4)

    # Constrain to specific target
    state.solver.add(leaked_value == target_value)

    # Check if satisfiable
    if state.solver.satisfiable():
        print(f"Arbitrary read at {controlled_addr}")
```

### Arbitrary Write Detection (Challenge 16)
```python
# Load controlled address and value
controlled_addr = state.memory.load(base_addr, 4)
controlled_value = state.memory.load(base_addr + 4, 4)

# Check if both are controlled
if state.solver.symbolic(controlled_addr) and \
   state.solver.symbolic(controlled_value):

    # Perform the write
    state.memory.store(controlled_addr, controlled_value,
                      endness=state.arch.memory_endness)

    # Check for target address overwrite
    state.solver.add(controlled_addr == target_address)
    state.solver.add(controlled_value == target_value)
```

### Arbitrary Jump Detection (Challenge 17)
```python
# Use unconstrained stash to catch control flow hijacks
simgr = project.factory.simgr(initial_state, veritesting=True)

while (simgr.active or simgr.unconstrained) and not simgr.found:
    if simgr.unconstrained:
        for state in list(simgr.unconstrained):
            # Check if we can jump to target
            state.add_constraints(state.regs.eip == target_address)

            if state.solver.satisfiable():
                # Move to found
                simgr.move(from_stash='unconstrained', to_stash='found',
                          filter_func=lambda s: s == state)

    simgr.step()

if simgr.found:
    solution_state = simgr.found[0]
    print(f"Jump to {hex(solution_state.solver.eval(solution_state.regs.eip))}")
```

## 6. Unconstrained State Handling

### Basic Unconstrained Handling
```python
while simgr.active and not simgr.found:
    simgr.step()

    # Process unconstrained states
    if simgr.unconstrained:
        for state in simgr.unconstrained:
            # Try to constrain EIP to target
            state.add_constraints(state.regs.eip == success_addr)

            if state.solver.satisfiable():
                simgr.move(from_stash='unconstrained', to_stash='found',
                          filter_func=lambda s: s == state)
                break
```

### Advanced Unconstrained with Multiple Targets
```python
targets = [addr1, addr2, addr3]

def process_unconstrained(simgr):
    if not simgr.unconstrained:
        return

    for state in list(simgr.unconstrained):
        for target in targets:
            # Try each target
            test_state = state.copy()
            test_state.add_constraints(test_state.regs.eip == target)

            if test_state.solver.satisfiable():
                # This state can reach target
                state.add_constraints(state.regs.eip == target)
                simgr.move(from_stash='unconstrained', to_stash='found',
                          filter_func=lambda s: s == state)
                return

while (simgr.active or simgr.unconstrained) and not simgr.found:
    simgr.step()
    process_unconstrained(simgr)
```

## 7. Memory Constraints

### Pointer Dereference Constraints
```python
# Load symbolic pointer
ptr = state.memory.load(symbolic_ptr_addr, 4,
                       endness=state.arch.memory_endness)

# Constrain pointed-to value
value = state.memory.load(ptr, 4, endness=state.arch.memory_endness)
state.solver.add(value == target_value)

# Also constrain pointer to valid range
state.solver.add(ptr >= 0x08000000)
state.solver.add(ptr <= 0x0fffffff)
```

### String Comparison Constraints
```python
# Load two strings
str1 = state.memory.load(addr1, 100)
str2 = state.memory.load(addr2, 100)

# Constrain equality
state.solver.add(str1 == str2)

# Or constrain character-by-character for better performance
for i in range(length):
    state.solver.add(str1.get_byte(i) == str2.get_byte(i))
```

## 8. Performance Optimization

### Veritesting for State Merging
```python
# Enable veritesting to merge similar states
simgr = project.factory.simgr(initial_state, veritesting=True)

# OR
simgr = project.factory.simgr(initial_state)
simgr.use_technique(angr.exploration_techniques.Veritesting())
```

### Unicorn Engine for Concrete Execution
```python
# Use Unicorn for fast concrete execution
initial_state = project.factory.entry_state(add_options={
    angr.options.unicorn
})
```

### Loop Prevention
```python
# Use LoopLimiter technique
simgr = project.factory.simgr(initial_state)
simgr.use_technique(angr.exploration_techniques.LoopLimiter())
```

### Exploration Limits
```python
# Limit exploration steps
simgr.explore(find=target, step_limit=100000)

# Limit time
import time
start = time.time()
def timeout_check(simgr):
    if time.time() - start > 60:  # 60 second timeout
        return True
    return False

simgr.explore(find=target, step_limit=100000, num_find=1)
```

## 9. Advanced Solution Extraction

### Extracting Multiple Values
```python
if simgr.found:
    solution_state = simgr.found[0]

    # Extract multiple symbolic variables
    solutions = []
    for var_name in ['input0', 'input1', 'input2']:
        var = solution_state.globals[var_name]
        value = solution_state.solver.eval(var, cast_to=bytes)
        solutions.append(value)

    print(' '.join(s.decode() for s in solutions))
```

### Extracting with Formatting
```python
if simgr.found:
    solution_state = simgr.found[0]

    # Extract as hex
    solution = solution_state.solver.eval(symbolic_var)
    print(hex(solution))

    # Extract as string
    solution = solution_state.solver.eval(symbolic_var, cast_to=bytes)
    print(solution.decode('utf-8', errors='ignore'))

    # Extract as integer array
    solution = solution_state.solver.eval(symbolic_var, cast_to=bytes)
    print([b for b in solution])
```

## 10. Debugging Techniques

### State Inspection
```python
# Interactive debugging with IPython
import IPython
IPython.embed()

# Check simulation manager state
print(f"Active: {len(simgr.active)}")
print(f"Found: {len(simgr.found)}")
print(f"Deadended: {len(simgr.deadended)}")
print(f"Unconstrained: {len(simgr.unconstrained)}")

# Inspect a state
state = simgr.active[0]
print(f"Address: {hex(state.addr)}")
print(f"EIP: {hex(state.regs.eip)}")
print(f"EAX: {hex(state.regs.eax)}")
```

### Logging
```python
import logging
logging.getLogger('angr').setLevel(logging.DEBUG)

# Or for specific components
logging.getLogger('angr.exploration_techniques').setLevel(logging.INFO)
```

### State Export
```python
# Save state for later analysis
state = simgr.found[0]
state.history.descriptions
state.history.recent_description
state.regs.eip
state.memory.load(addr, size)
```
