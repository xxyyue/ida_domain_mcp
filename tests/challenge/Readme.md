# Dual Binary Static Analysis (CTF)

This challenge ships two binaries:

- `device_main` (main executable)
- `secure_check.so` (shared object loaded via dlopen)

Workflow:
1. `device_main` reads 32 bytes from stdin.
2. It applies a reversible transform.
3. It dlopen()s `secure_check.so` and calls `secure_validate(transformed, 32)`.
4. On success, it prints a flag assembled from two halves:
   - first half stored (obfuscated) in `device_main`
   - second half stored (obfuscated) in `secure_check.so`

## Build

```bash
make
```

## Run

```
cd binaries
python3 - << 'PY'
import sys
sys.stdout.buffer.write(b'A'*32)
PY | ./device_main
```

By default the build embeds FLAG=FLAG{dual_binary_static_analysis} into the target generation step.
For real CTF, keep source private and only distribute dist/.

## Validation

```
make FLAG='FLAG{dual_binary_static_analysis}'

python3 solution/solve.py 'FLAG{dual_binary_static_analysis}' | (cd binaries && ./device_main)
```
expect output:

```
FLAG{dual_binary_static_analysis}
```

## Clean

```bash
make clean
```