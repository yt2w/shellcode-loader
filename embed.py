#!/usr/bin/env python3
"""
Shellcode Embedder
Encrypts shellcode with rolling XOR and generates C header
"""

import argparse
import os
import random

def xor_encrypt(data: bytes, key: int) -> bytes:
    """Rolling XOR encryption with 32-bit key"""
    result = bytearray(len(data))
    k = key
    for i, b in enumerate(data):
        result[i] = b ^ (k & 0xFF)
        k = ((k >> 8) | (k << 24)) & 0xFFFFFFFF
    return bytes(result)

def generate_header(data: bytes, key: int, output: str) -> None:
    """Generate C header with encrypted shellcode"""
    
    encrypted = xor_encrypt(data, key)
    
    # Verify encryption actually changed the data
    if encrypted[:32] == data[:32]:
        raise ValueError("Encryption failed - data unchanged")
    
    lines = []
    lines.append("// Auto-generated - do not edit")
    lines.append(f"// Size: {len(data)} bytes")
    lines.append(f"// Key: 0x{key:08X}")
    lines.append("")
    lines.append("#pragma once")
    lines.append("")
    lines.append(f"#define SHELLCODE_SIZE {len(data)}")
    lines.append(f"#define SHELLCODE_KEY 0x{key:08X}U")
    lines.append("")
    lines.append("static const unsigned char SHELLCODE[] = {")
    
    for i in range(0, len(encrypted), 16):
        chunk = encrypted[i:i+16]
        hex_vals = ", ".join(f"0x{b:02X}" for b in chunk)
        lines.append(f"    {hex_vals},")
    
    lines.append("};")
    
    with open(output, "w") as f:
        f.write("\n".join(lines))
    
    print(f"[+] Generated: {output}")
    print(f"    Size: {len(data)} bytes")
    print(f"    Key: 0x{key:08X}")
    print(f"    Before: {data[:8].hex()}")
    print(f"    After:  {encrypted[:8].hex()}")

def main():
    parser = argparse.ArgumentParser(description="Shellcode Embedder")
    parser.add_argument("-i", "--input", required=True, help="Input shellcode file")
    parser.add_argument("-o", "--output", default="shellcode.h", help="Output header file")
    parser.add_argument("-k", "--key", type=lambda x: int(x, 0), help="Encryption key (hex)")
    args = parser.parse_args()
    
    if not os.path.exists(args.input):
        print(f"[!] Input file not found: {args.input}")
        return 1
    
    with open(args.input, "rb") as f:
        shellcode = f.read()
    
    if len(shellcode) == 0:
        print("[!] Empty shellcode file")
        return 1
    
    # Generate or use provided key
    if args.key:
        key = args.key
    else:
        key = random.randint(0x10000000, 0xFFFFFFFF)
        # Avoid weak/obvious keys
        while key in [0xDEADBEEF, 0xCAFEBABE, 0x12345678, 0xAAAAAAAA]:
            key = random.randint(0x10000000, 0xFFFFFFFF)
    
    generate_header(shellcode, key, args.output)
    return 0

if __name__ == "__main__":
    exit(main())
