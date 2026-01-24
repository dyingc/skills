#!/usr/bin/env python3
"""
Automated binary analysis script for angr symbolic execution.
Integrates static analysis tools (objdump, radare2, Ghidra) to automatically
determine binary characteristics and generate appropriate angr solutions.

Usage:
    python analyze_binary.py <binary_path> [--output OUTPUT_FILE]
                                          [--technique TECHNIQUE]
                                          [--verbose]
"""

import sys
import argparse
import subprocess
import re
from pathlib import Path
from typing import Dict, List, Tuple, Optional

class BinaryAnalyzer:
    """Analyze binary to determine characteristics for angr solving."""

    def __init__(self, binary_path: str):
        self.binary_path = Path(binary_path)
        if not self.binary_path.exists():
            raise FileNotFoundError(f"Binary not found: {binary_path}")

        self.binary_path = str(self.binary_path)

        # Analysis results
        self.arch = None
        self.is_static = False
        self.is_pie = False
        self.is_lib = False
        self.base_addr = None
        self.functions = {}
        self.strings = []
        self.imports = []
        self.main_addr = None
        self.success_strings = []
        self.failure_strings = []

    def run_command(self, cmd: List[str]) -> str:
        """Run shell command and return output."""
        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
            return result.stdout
        except (subprocess.TimeoutExpired, FileNotFoundError) as e:
            return ""

    def analyze_with_file(self):
        """Use 'file' command to determine basic properties."""
        output = self.run_command(['file', self.binary_path])

        # Architecture
        if 'Intel 80386' in output or '80386' in output:
            self.arch = 'x86'
        elif 'x86-64' in output:
            self.arch = 'x86_64'
        elif 'ARM' in output:
            self.arch = 'ARM'
        elif 'MIPS' in output:
            self.arch = 'MIPS'

        # Static vs Dynamic
        self.is_static = 'statically linked' in output

        # PIE
        self.is_pie = 'pie' in output.lower()

        # Shared library
        self.is_lib = 'shared object' in output

        return output

    def analyze_with_objdump(self):
        """Use objdump to find functions, imports, and strings."""
        # Get disassembly
        output = self.run_command(['objdump', '-d', self.binary_path])

        # Find main function
        main_match = re.search(r'<main>:\n.*?\n\s+([0-9a-f]+):\s', output)
        if main_match:
            self.main_addr = int(main_match.group(1), 16)

        # Find function calls (simple heuristic)
        call_pattern = r'call\s+([0-9a-f]+)\s*<([^>]+)>'
        calls = re.findall(call_pattern, output)

        # Identify suspicious functions
        suspicious_funcs = ['scanf', 'gets', 'strcpy', 'strcmp', 'strlen', 'printf']
        for addr, func in calls:
            if any(sus in func for sus in suspicious_funcs):
                if func not in self.functions:
                    self.functions[func] = []
                self.functions[func].append(int(addr, 16))

        return output

    def analyze_with_strings(self):
        """Find strings in binary."""
        output = self.run_command(['strings', self.binary_path])

        # Look for success/failure indicators
        success_patterns = [b'Good Job', b'good job', b'correct', b'success',
                           b'flag', b'FLAG', b'CTF']
        failure_patterns = [b'Try again', b'wrong', b'incorrect', b'fail']

        # Convert to strings list
        self.strings = output.split('\n')

        # Find success/failure strings
        for s in self.strings:
            s_lower = s.lower()
            if any(p.decode() in s_lower for p in success_patterns):
                self.success_strings.append(s)
            if any(p.decode() in s_lower for p in failure_patterns):
                self.failure_strings.append(s)

        return self.strings

    def analyze_with_radare2(self) -> bool:
        """Use radare2 for deeper analysis if available."""
        try:
            # Test if r2 is available
            subprocess.run(['r2', '--version'], capture_output=True, check=True)
        except (subprocess.CalledProcessError, FileNotFoundError):
            return False

        try:
            # Use r2 to analyze
            cmd = f'aaa; pdf @main; iz'
            output = subprocess.run(
                ['r2', '-q', '-c', cmd, self.binary_path],
                capture_output=True, text=True, timeout=30
            ).stdout

            # Parse functions from r2 output
            # (Basic implementation - can be extended)

            return True
        except Exception:
            return False

    def get_base_addr(self) -> int:
        """Determine base address for PIE/shared libraries."""
        if self.is_lib:
            return 0x10000000  # Common default
        elif self.is_pie:
            return 0x08048000 if self.arch == 'x86' else 0x400000
        else:
            return 0x08048000 if self.arch == 'x86' else 0x400000

    def determine_angr_technique(self) -> str:
        """Determine which angr technique to use based on analysis."""
        if self.is_static:
            return "static"
        elif self.is_lib:
            return "shared_library"
        elif any('scanf' in f for f in self.functions.keys()):
            return "scanf"
        elif self.success_strings and self.failure_strings:
            return "basic_explore"
        elif self.main_addr:
            return "symbolic_registers"
        else:
            return "generic"

    def generate_angr_template(self) -> str:
        """Generate angr solution template based on analysis."""
        technique = self.determine_angr_technique()

        template = f'''#!/usr/bin/env python3
"""
Auto-generated angr solution for: {self.binary_path}
Binary Type: {self.arch}, {'Static' if self.is_static else 'Dynamic'},
{'PIE' if self.is_pie else 'No-PIE'}, {'Shared Lib' if self.is_lib else 'Executable'}
Technique: {technique}
"""

import angr
import claripy
import sys

def solve():
    # Load binary
'''

        if self.is_lib:
            template += f'''    project = angr.Project(r"{self.binary_path}", load_options={{
        'main_opts': {{'base_addr': {hex(self.get_base_addr())}}}
    }})
'''
        else:
            template += f'''    project = angr.Project(r"{self.binary_path}", auto_load_libs=False)
'''

        # Add technique-specific setup
        if technique == "static":
            template += '''
    # Hook libc functions for static binary
    from angr import SIM_PROCEDURES
    libc = SIM_PROCEDURES['libc']

    # You'll need to find these addresses with objdump/radare2
    # Example: project.hook(addr, libc['strcmp']())
'''

        elif technique == "scanf":
            template += '''
    # Hook scanf to provide symbolic input
    class ScanfHook(angr.SimProcedure):
        def run(self, format_str, *args):
            scanf_inputs = []
            for i, arg in enumerate(args):
                # Create symbolic input for each format specifier
                scanf_input = claripy.BVS(f'scanf_{i}', 32)
                self.state.memory.store(arg, scanf_input,
                                       endness=self.arch.memory_endness)
                scanf_inputs.append(scanf_input)

            # Store in globals for later extraction
            self.state.globals['scanf_inputs'] = scanf_inputs
            return claripy.BVV(len(args), 32)

    project.hook_symbol('__isoc99_scanf', ScanfHook())
    project.hook_symbol('scanf', ScanfHook())
'''

        # Common state creation
        template += '''
    # Create initial state
    initial_state = project.factory.entry_state(add_options={
        angr.options.SYMBOL_FILL_UNCONSTRAINED_MEMORY,
        angr.options.SYMBOL_FILL_UNCONSTRAINED_REGISTERS
    })

    # Create simulation manager
'''

        if technique in ["symbolic_registers", "arbitrary_jump"]:
            template += '''    simgr = project.factory.simgr(initial_state, veritesting=True)
'''
        else:
            template += '''    simgr = project.factory.simulation_manager(initial_state)
'''

        # Add exploration
        if self.success_strings:
            success_str = self.success_strings[0]
            template += f'''
    # Explore to success condition
    simgr.explore(
        find=lambda s: b"{success_str}" in s.posix.dumps(sys.stdout.fileno())
'''
            if self.failure_strings:
                failure_str = self.failure_strings[0]
                template += f''',
        avoid=lambda s: b"{failure_str}" in s.posix.dumps(sys.stdout.fileno())
'''
            template += ''')
'''
        else:
            template += '''
    # You'll need to determine the success address with objdump/radare2
    # simgr.explore(find=success_addr)
    print("TODO: Determine success address and run exploration")
    return None
'''

        # Add solution extraction
        template += '''
    # Extract solution
    if simgr.found:
        solution_state = simgr.found[0]
'''

        if technique == "scanf":
            template += '''        # Extract scanf inputs
        scanf_inputs = solution_state.globals['scanf_inputs']
        solution = b''.join(
            solution_state.solver.eval(var, cast_to=bytes) for var in scanf_inputs
        )
        print(solution.decode('utf-8'))
'''
        else:
            template += '''        # Extract from stdin
        solution = solution_state.posix.dumps(sys.stdin.fileno())
        print(solution.decode('utf-8'))
'''
        template += '''
    else:
        print("No solution found!")
        sys.exit(1)

if __name__ == '__main__':
    solve()
'''
        return template

    def analyze(self) -> Dict:
        """Run complete binary analysis."""
        print(f"[*] Analyzing {self.binary_path}...")

        # Basic properties
        print("[*] Determining architecture and linking...")
        self.analyze_with_file()
        print(f"    Architecture: {self.arch}")
        print(f"    Static: {self.is_static}, PIE: {self.is_pie}, Lib: {self.is_lib}")

        # Functions and imports
        print("[*] Analyzing functions and imports...")
        self.analyze_with_objdump()
        print(f"    Found {len(self.functions)} interesting functions")
        for func, addrs in self.functions.items():
            print(f"      {func}: {len(addrs)} calls")

        # Strings
        print("[*] Extracting strings...")
        self.analyze_with_strings()
        print(f"    Success indicators: {len(self.success_strings)}")
        print(f"    Failure indicators: {len(self.failure_strings)}")

        # Try radare2
        print("[*] Attempting radare2 analysis...")
        if self.analyze_with_radare2():
            print("    Radare2 analysis successful")
        else:
            print("    Radare2 not available")

        # Determine technique
        technique = self.determine_angr_technique()
        print(f"[*] Recommended technique: {technique}")

        return {
            'arch': self.arch,
            'is_static': self.is_static,
            'is_pie': self.is_pie,
            'is_lib': self.is_lib,
            'base_addr': self.get_base_addr(),
            'functions': self.functions,
            'success_strings': self.success_strings,
            'failure_strings': self.failure_strings,
            'technique': technique,
            'main_addr': self.main_addr
        }


def main():
    parser = argparse.ArgumentParser(description='Analyze binary for angr solving')
    parser.add_argument('binary', help='Path to binary to analyze')
    parser.add_argument('--output', '-o', help='Output file for generated script')
    parser.add_argument('--technique', '-t', choices=[
        'basic', 'scanf', 'static', 'shared_library', 'generic'
    ], help='Force specific technique')
    parser.add_argument('--verbose', '-v', action='store_true',
                       help='Verbose output')

    args = parser.parse_args()

    try:
        analyzer = BinaryAnalyzer(args.binary)
        analysis = analyzer.analyze()

        # Generate template
        print("\n[*] Generating angr solution template...")
        template = analyzer.generate_angr_template()

        # Output
        if args.output:
            with open(args.output, 'w') as f:
                f.write(template)
            print(f"[+] Script written to {args.output}")
        else:
            print("\n" + "="*60)
            print("Generated Script:")
            print("="*60)
            print(template)

        print("\n[*] Analysis complete!")

    except Exception as e:
        print(f"[!] Error: {e}", file=sys.stderr)
        sys.exit(1)


if __name__ == '__main__':
    main()
