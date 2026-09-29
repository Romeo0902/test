#!/usr/bin/env python3
"""
Reverse engineering the kexd binary
Focus on: socket handling, file operations, key reading
"""

import subprocess
import re
import sys

def run_cmd(cmd):
    """Execute command and return output"""
    try:
        result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
        return result.stdout + result.stderr
    except Exception as e:
        return f"Error: {e}"

def analyze_with_objdump():
    """Use objdump to find key functions"""
    print("\n" + "="*80)
    print("OBJDUMP ANALYSIS - Key Functions")
    print("="*80)
    
    # Find all functions
    print("\n[*] Extracting function symbols...")
    cmd = "objdump -t ./kexd | grep -E '\.text.*DF' | head -30"
    output = run_cmd(cmd)
    print(output)
    
    # Disassemble main (if we can find it)
    print("\n[*] Attempting to find main function...")
    cmd = "objdump -d ./kexd | grep -A 50 '<main>:' | head -60"
    output = run_cmd(cmd)
    if output:
        print(output)
    else:
        print("[-] main() not found (stripped binary)")
    
    # Look for file operations (fopen, fread, etc.)
    print("\n[*] Looking for file operations (fopen, fclose, fread, fgets)...")
    cmd = "objdump -d ./kexd | grep -E 'fopen|fread|fgets|fclose|open|read' | head -20"
    output = run_cmd(cmd)
    print(output if output else "[-] No direct file operation calls found")
    
    # Look for socket operations
    print("\n[*] Looking for socket operations...")
    cmd = "objdump -d ./kexd | grep -E 'socket|bind|listen|accept|connect' | head -20"
    output = run_cmd(cmd)
    print(output if output else "[-] No direct socket calls found")

def analyze_with_radare2():
    """Use radare2 for deeper analysis"""
    print("\n" + "="*80)
    print("RADARE2 ANALYSIS")
    print("="*80)
    
    # Check if radare2 is installed
    if not run_cmd("which r2"):
        print("[-] radare2 not installed, skipping")
        return
    
    print("\n[*] Getting entry point and main functions...")
    cmd = 'r2 -q -c "aa; afl" ./kexd | head -50'
    output = run_cmd(cmd)
    print(output)

def search_for_key_patterns():
    """Search for potential key locations"""
    print("\n" + "="*80)
    print("SEARCHING FOR KEY PATTERNS")
    print("="*80)
    
    # Dump all readable strings
    print("\n[*] All strings containing 'key', 'site', 'provision'...")
    cmd = "strings -a ./kexd | grep -i 'key\\|site\\|provision\\|secret\\|password'"
    output = run_cmd(cmd)
    print(output)
    
    # Hex dump around key references
    print("\n[*] Hex dump (first 1000 bytes)...")
    cmd = "hexdump -C ./kexd | head -100"
    output = run_cmd(cmd)
    print(output[:2000])
    
    # Look for hex patterns that might be keys
    print("\n[*] Looking for 16/32/64 byte hex patterns (potential keys)...")
    cmd = "strings -a ./kexd | grep -E '^[0-9A-Fa-f]{32,}$' | head -20"
    output = run_cmd(cmd)
    if output:
        print(output)
    else:
        print("[-] No obvious hex keys found in strings")

def analyze_imports():
    """Analyze imported functions"""
    print("\n" + "="*80)
    print("DYNAMIC IMPORTS ANALYSIS")
    print("="*80)
    
    print("\n[*] Imported functions (readelf)...")
    cmd = "readelf -s ./kexd | grep -E 'fopen|fread|socket|bind|listen|accept|getenv|strcpy|sprintf|sscanf'"
    output = run_cmd(cmd)
    print(output if output else "[-] No matching imports found")
    
    print("\n[*] PLT functions (objdump)...")
    cmd = "objdump -d ./kexd | grep -A 5 'plt' | head -40"
    output = run_cmd(cmd)
    print(output)

def main():
    print("""
╔════════════════════════════════════════════════════════════════════════════╗
║                    REVERSE ENGINEERING kexd BINARY                         ║
║                     Goal: Find key retrieval mechanism                      ║
╚════════════════════════════════════════════════════════════════════════════╝

CRITICAL FILE FOUND: /etc/kexd/site.key

Strategy:
  1. Find where /etc/kexd/site.key is opened and read
  2. Find the network protocol handler
  3. Identify the vulnerability (buffer overflow, format string, etc.)
  4. Craft exploit to extract key or trigger direct read
    """)
    
    if len(sys.argv) > 1 and sys.argv[1] == '--deep':
        analyze_with_objdump()
        analyze_with_radare2()
    
    search_for_key_patterns()
    analyze_imports()
    
    print("\n" + "="*80)
    print("NEXT STEPS:")
    print("="*80)
    print("""
1. Use Ghidra or IDA to decompile the binary
2. Search for functions that:
   - Open "/etc/kexd/site.key"
   - Read from sockets
   - Parse user input
   - Handle protocol commands

3. Identify the vulnerability:
   - Buffer overflow in sscanf/scanf
   - Format string in printf/sprintf
   - Logic error in authentication
   - Uninitialized memory
   
4. Build exploit to:
   - Leak the key from memory
   - Trigger file read and transmit over network
   - ROP chain to call system("cat /etc/kexd/site.key")
    """)

if __name__ == '__main__':
    main()
