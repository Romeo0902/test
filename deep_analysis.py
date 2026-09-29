#!/usr/bin/env python3
"""
Automated analysis using radare2 to find site.key read function
"""

import subprocess
import re

def run_r2_cmd(cmd):
    """Execute radare2 command"""
    full_cmd = f'r2 -q -c "{cmd}" ./kexd'
    result = subprocess.run(full_cmd, shell=True, capture_output=True, text=True)
    return result.stdout

def analyze_key_usage():
    """Find where /etc/kexd/site.key is used"""
    
    print("="*80)
    print("ANALYZING site.key USAGE")
    print("="*80)
    
    # Address of the string
    key_addr = "0x0040933c"
    
    print(f"\n[*] String address: {key_addr}")
    print("[*] Looking for all references to this string...")
    
    # Get all xrefs
    xrefs = run_r2_cmd(f"axt @ {key_addr}")
    print("\nXrefs found:")
    print(xrefs)
    
    # Parse xrefs to get calling functions
    lines = xrefs.strip().split('\n')
    caller_addresses = []
    
    for line in lines:
        if ' -> ' in line:
            parts = line.split(' -> ')
            if len(parts) >= 1:
                addr = parts[0].strip()
                caller_addresses.append(addr)
    
    if not caller_addresses:
        print("[-] No xrefs found, trying alternative search...")
        # Try searching in instruction stream
        search = run_r2_cmd(f"ps {key_addr}")
        print("Search results:", search)
        return
    
    # Analyze each caller
    for addr in set(caller_addresses):
        print(f"\n[*] Analyzing caller at {addr}")
        print("-" * 60)
        
        # Get the function containing this address
        func_info = run_r2_cmd(f"af @ {addr}; afi @ {addr}")
        print("Function info:")
        print(func_info)
        
        # Disassemble around this point
        disasm = run_r2_cmd(f"pd 30 @ {addr}")
        print("\nDisassembly:")
        print(disasm)

def find_socket_handlers():
    """Find socket-related functions"""
    
    print("\n" + "="*80)
    print("FINDING SOCKET HANDLERS")
    print("="*80)
    
    # Get all functions
    functions = run_r2_cmd("afl")
    print("\nFunctions in binary:")
    print(functions[:2000])
    
    # Look for suspicious function sizes
    print("\n[*] Large functions (potential main handler):")
    for line in functions.split('\n'):
        if line.strip():
            try:
                parts = line.split()
                if len(parts) >= 3:
                    size = int(parts[1])
                    name = ' '.join(parts[3:])
                    if size > 500:  # Large function
                        print(f"  {line}")
            except:
                pass

def trace_network_flow():
    """Trace the network input handling"""
    
    print("\n" + "="*80)
    print("TRACING NETWORK INPUT FLOW")
    print("="*80)
    
    # Look for socket operations
    print("\n[*] Looking for socket, bind, listen, accept...")
    
    for func in ['socket', 'bind', 'listen', 'accept', 'read', 'fopen']:
        print(f"\n[*] Function: {func}")
        result = run_r2_cmd(f'afl~{func}')
        if result.strip():
            print(result)
        
        # Find xrefs to this imported function
        result = run_r2_cmd(f'aflm~{func}')
        if result.strip():
            print(f"Callers of {func}:")
            print(result)

def search_for_format_string():
    """Look for format string vulnerabilities"""
    
    print("\n" + "="*80)
    print("SEARCHING FOR FORMAT STRINGS")
    print("="*80)
    
    # Look for printf-like functions with user input
    print("\n[*] Searching for potential format string patterns...")
    
    strings_result = subprocess.run(
        'strings -a ./kexd | grep -E "%[0-9]*[dxps]"',
        shell=True,
        capture_output=True,
        text=True
    )
    
    print("Format strings found:")
    print(strings_result.stdout[:1000])

def extract_protocol_commands():
    """Extract protocol command strings"""
    
    print("\n" + "="*80)
    print("PROTOCOL COMMAND ANALYSIS")
    print("="*80)
    
    # Get all strings with offsets
    result = subprocess.run(
        'strings -a -t x ./kexd | grep -Ei "TK|command|request|response|GET|SET|auth"',
        shell=True,
        capture_output=True,
        text=True
    )
    
    print("Protocol-related strings:")
    print(result.stdout)
    
    # Look specifically at the parsing format
    print("\n[*] Looking for scanf/sscanf format strings...")
    result = subprocess.run(
        'strings -a ./kexd | grep "%"',
        shell=True,
        capture_output=True,
        text=True
    )
    print(result.stdout[:1000])

def dump_hex_around_key_string():
    """Show hex dump around the key string"""
    
    print("\n" + "="*80)
    print("HEX DUMP AROUND site.key STRING")
    print("="*80)
    
    print("\n[*] Address: 0x0040933c")
    
    # Use radare2 to show bytes around this address
    result = run_r2_cmd("px 256 @ 0x0040933c")
    print(result)

def main():
    print("""
╔════════════════════════════════════════════════════════════════════════════╗
║                 DEEP BINARY ANALYSIS - KX01 PROTOCOL                       ║
║                                                                            ║
║ Target: Find how /etc/kexd/site.key is read and transmitted                ║
║ Key Address: 0x0040933c                                                    ║
║                                                                            ║
║ Strategy:                                                                   ║
║  1. Find all references to site.key string                                 ║
║  2. Analyze the calling function                                           ║
║  3. Identify protocol handlers                                             ║
║  4. Find vulnerability (overflow, format string, logic error)              ║
╚════════════════════════════════════════════════════════════════════════════╝
    """)
    
    try:
        analyze_key_usage()
        dump_hex_around_key_string()
        extract_protocol_commands()
        find_socket_handlers()
        search_for_format_string()
        trace_network_flow()
    except Exception as e:
        print(f"\n[-] Error: {e}")
        print("[-] Make sure radare2 is installed: sudo apt install radare2")

if __name__ == '__main__':
    main()
