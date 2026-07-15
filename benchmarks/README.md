# Real SLH-DSA Benchmark

This benchmark uses the official Open Quantum Safe Python wrapper around
`liboqs`. It is independent of the educational Mini-SPHINCS+ implementation
and exercises the FIPS 205 SLH-DSA parameter sets with their real key and
signature sizes.

The default comparison is:

- `SLH_DSA_PURE_SHA2_128S`: smaller 7,856-byte signature.
- `SLH_DSA_PURE_SHA2_128F`: faster signing profile with a 17,088-byte signature.

## Install in an isolated WSL environment

The recommended setup does not require sudo or modify conda `base`:

```bash
cd /home/chenhao/toy-sphincs-off-switch
bash benchmarks/setup_no_sudo.sh
```

It creates `.venv`, installs the Python wrapper and build tools, and builds the
standardized liboqs algorithms with `OQS_USE_OPENSSL=OFF` into
`.venv/liboqs`. The benchmark automatically discovers that local installation.
The setup requires GCC, Git, network access, and Python's `venv` module.

If the machine already has a compatible system liboqs and OpenSSL development
files, the shorter standard installation also works:

```bash
python3 -m venv .venv
.venv/bin/python -m pip install --upgrade pip
.venv/bin/python -m pip install -r benchmarks/requirements.txt
```

## Run

Quick smoke benchmark:

```bash
.venv/bin/python benchmarks/slh_dsa_benchmark.py --iterations 3
```

More stable measurements with JSON output:

```bash
mkdir -p benchmarks/results
.venv/bin/python benchmarks/slh_dsa_benchmark.py \
  --iterations 20 \
  --warmup 2 \
  --json benchmarks/results/wsl.json
```

The output includes:

- actual public-key, secret-key, and signature sizes;
- key-generation, signing, and verification mean/median/P95 latency;
- correct verification and rejection of a changed message, changed signature,
  and wrong public key;
- whether repeated signing produces different signatures;
- the number of stream words and input-only latency for a configurable bus.

The default hardware estimate assumes one 32-bit word per cycle at 100 MHz.
Change it with `--bus-width-bits` and `--clock-mhz`.

## Interpretation

The timings measure optimized C code called through Python, not Python
cryptography and not RTL. Use them to compare parameter sets and establish
interface sizes. They are not predictions of hardware verification latency.

`liboqs` and `liboqs-python` are intended for prototyping and evaluation. This
benchmark is not a production-security validation or a substitute for FIPS 205
known-answer tests.
