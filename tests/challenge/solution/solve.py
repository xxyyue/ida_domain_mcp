#!/usr/bin/env python3
import hashlib
import sys

def ror8(x, r):
    r &= 7
    return ((x >> r) | ((x << (8 - r)) & 0xFF)) & 0xFF

def inverse_transform(buf32: bytes) -> bytes:
    b = list(buf32)
    for i in range(32):
        # inverse of: b[i] = b[i] + i*17
        b[i] = (b[i] - (i * 17)) & 0xFF
        # inverse of: rol8(..., i&7)
        b[i] = ror8(b[i], i & 7)
        # inverse of: xor 0x5A
        b[i] ^= 0x5A
    return bytes(b)

def main():
    if len(sys.argv) != 2:
        print(f"Usage: {sys.argv[0]} 'FLAG{{...}}'", file=sys.stderr)
        sys.exit(1)

    flag = sys.argv[1]
    target32 = hashlib.sha256(flag.encode()).digest()
    token = inverse_transform(target32)
    sys.stdout.buffer.write(token)

if __name__ == "__main__":
    main()
