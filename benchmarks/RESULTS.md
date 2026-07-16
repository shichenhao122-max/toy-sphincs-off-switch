# SLH-DSA Benchmark Results

Measurement date: 2026-07-15 (Europe/London)

## Environment

- WSL: Ubuntu 22.04 on WSL2.
- Python: 3.10.12 in the project-local `.venv`.
- liboqs-python: 0.16.0.dev0.
- liboqs: 0.16.0.
- liboqs build: standardized algorithm set, `OQS_USE_OPENSSL=OFF`.
- Message size: 64 bytes.
- Samples: 20 measured iterations after 2 warmup iterations.
- Streaming estimate: one 32-bit word per cycle at 100 MHz.

These are local software measurements of C implementations called through
Python. They are not predictions of RTL latency.

## Results

| Measurement | SHA2-128s | SHA2-128f |
|---|---:|---:|
| Public key | 32 B | 32 B |
| Secret key | 64 B | 64 B |
| Signature | 7,856 B | 17,088 B |
| Keygen median | 41.225 ms | 0.635 ms |
| Keygen P95 | 42.584 ms | 0.659 ms |
| Sign median | 307.990 ms | 15.036 ms |
| Sign P95 | 312.042 ms | 17.308 ms |
| Verify median | 0.327 ms | 0.901 ms |
| Verify P95 | 0.334 ms | 0.930 ms |
| 32-bit stream words | 1,964 | 4,272 |
| Input-only lower bound at 100 MHz | 19.64 us | 42.72 us |

Both profiles passed every functional check:

- a valid signature was accepted;
- a changed message was rejected;
- a one-bit-changed signature was rejected;
- a wrong public key was rejected;
- repeated signing of the same message produced different signatures;
- measured key and signature sizes matched the library metadata.

## Engineering feedback

1. A streaming signature interface is mandatory. Even the small profile is
   7,856 bytes, so the existing complete packed-license bus is not suitable.
2. SHA2-128s uses about 46% of the signature bytes and stream cycles required
   by SHA2-128f.
3. On this software build, SHA2-128s verification was about 2.8 times faster
   than SHA2-128f, while its signing was about 20 times slower.
4. The signing cost is paid by the host or license authority, whereas the
   Off-Switch device pays the signature-transfer and verification costs.
   Therefore SHA2-128s remains the better first RTL target.
5. Repeated signatures are randomized. Tests and protocols must verify the
   signature rather than expecting byte-for-byte equality.

## Reproduce

```bash
cd ~/toy-sphincs-off-switch
bash benchmarks/setup_no_sudo.sh
.venv/bin/python benchmarks/slh_dsa_benchmark.py \
  --iterations 20 \
  --warmup 2 \
  --json benchmarks/results/wsl.json
```
