#!/usr/bin/env python3
"""
Shellcode Embedder
Generates C header with shellcode (NO encryption - loader handles that)
"""

import argparse
import os
import random

def generate_header(data: bytes, output: str) -> None:
    """Generate C header with raw shellcode"""
    
    lines = []
    lines.append("// Auto-generated - do not edit")
    lines.append(f"// Size: {len(data)} bytes")
    lines.append("// Note: Shellcode is NOT pre-encrypted - loader encrypts at runtime")
    lines.append("")
    lines.append("#pragma once")
    lines.append("")
    # Provide both naming conventions for compatibility
    lines.append(f"#define SHELLCODE_SIZE {len(data)}")
    lines.append(f"unsigned int shellcode_len = {len(data)};")
    lines.append("")
    lines.append("unsigned char shellcode[] = {")
    
    for i in range(0, len(data), 16):
        chunk = data[i:i+16]
        hex_vals = ", ".join(f"0x{b:02X}" for b in chunk)
        lines.append(f"    {hex_vals},")
    
    lines.append("};")
    
    with open(output, "w") as f:
        f.write("\n".join(lines))
    
    print(f"[+] Generated: {output}")
    print(f"    Size: {len(data)} bytes")
    print(f"    First 8 bytes: {data[:8].hex()}")
    print(f"    Note: Not pre-encrypted (loader handles encryption)")

def main():
    parser = argparse.ArgumentParser(description="Shellcode Embedder (No Pre-Encryption)")
    parser.add_argument("-i", "--input", required=True, help="Input shellcode file")
    parser.add_argument("-o", "--output", default="shellcode.h", help="Output header file")
    args = parser.parse_args()
    
    if not os.path.exists(args.input):
        print(f"[!] Input file not found: {args.input}")
        return 1
    
    with open(args.input, "rb") as f:
        shellcode = f.read()
    
    if len(shellcode) == 0:
        print("[!] Empty shellcode file")
        return 1
    
    generate_header(shellcode, args.output)
    return 0

if __name__ == "__main__":
    exit(main())
