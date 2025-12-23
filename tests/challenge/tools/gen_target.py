#!/usr/bin/env python3
import argparse
import hashlib
import textwrap

def c_array_bytes(name, data: bytes) -> str:
    items = ", ".join(f"0x{b:02x}" for b in data)
    return f"static const unsigned char {name}[{len(data)}] = {{ {items} }};"

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--flag", required=True)
    ap.add_argument("--out", required=True)
    args = ap.parse_args()

    flag = args.flag

    # part2 is everything after "FLAG{dual_" in this template.
    # You can change this split rule as you like for your own challenge.
    prefix = "FLAG{dual_"
    if not flag.startswith(prefix):
        raise SystemExit(f"flag must start with {prefix!r} for this template")

    part2 = flag[len(prefix):]  # e.g. "binary_static_analysis}"
    part2_bytes = part2.encode("utf-8")
    key = 0xA7
    part2_enc = bytes([b ^ key for b in part2_bytes])

    # Generate a fixed 32-byte target derived from the flag (deterministic),
    # so you can rebuild reliably while keeping the true flag private.
    # Note: Challenge solvability comes from reversing transform() in device_main
    # and extracting kTarget32 from secure_check.so.
    digest = hashlib.sha256(flag.encode("utf-8")).digest()  # 32 bytes
    target32 = digest

    part2_items = ", ".join(f"0x{b:02x}" for b in part2_enc)

    hdr = f"""\
#pragma once
// Auto-generated. Do not edit by hand.

{c_array_bytes("kTarget32", target32)}

#define PART2_ENC_BYTES {part2_items}
"""

    with open(args.out, "w", encoding="utf-8") as f:
        f.write(textwrap.dedent(hdr))

if __name__ == "__main__":
    main()
