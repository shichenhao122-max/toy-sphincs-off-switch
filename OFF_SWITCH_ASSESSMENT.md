# Local Off-Switch Environment and SPHINCS+ Integration Assessment

Assessment date: 2026-07-14 (Europe/London)

## Conclusion

The Off-Switch repository can be rebuilt and simulated successfully in the local WSL environment. The WSL checkout matched GitHub `main` at:

```text
eccb54d823b71086a11d069bf321517fe1e29357
```

The only environment-specific detail is that Verilator 5.044 is installed in `/home/chenhao/verilator/bin`, which a non-interactive login shell does not add to `PATH`. Automated commands must therefore set `PATH` explicitly. The compiler and project source are working correctly.

## Verified environment

- WSL: Ubuntu 22.04 on WSL2.
- Repository: `/home/chenhao/off-switch`.
- Upstream: `https://github.com/JamesPetrie/off-switch`.
- Local `HEAD` and remote `refs/heads/main`: both `eccb54d...`.
- `sha256` Git submodule: `837c5cc396f001d18f2c765721c585716eb439ae`.
- Verilator: 5.044, matching the repository's CI target.
- GNU Make: 4.3.
- g++: 11.4.0.
- Python: 3.10.12.
- Tracked files had no local differences. Existing untracked files included `.vscode/`, `verilog/build/`, `verilog/build2/`, and `verilog/dump.fst`. Simulation regenerated `verilog/build/` without changing tracked source.

## Reproducible commands and results

```bash
export PATH=/home/chenhao/verilator/bin:$PATH
cd /home/chenhao/off-switch/verilog

make lint TOOL=verilator CRYPTO_TYPE=0
make lint TOOL=verilator CRYPTO_TYPE=1
make sim TB=top_ecdsa
make sim TB=top_hss
```

Results:

- ECDSA lint passed.
- HSS-LMS lint passed.
- `top_ecdsa`: 16/16 tests passed; full rebuild and simulation took about 242.5 seconds.
- `top_hss`: 17/17 tests passed; full rebuild and simulation took about 63.4 seconds.
- Coverage included initial fail-secure behavior, workload gating, 2-of-2 multisignature verification, allowance updates, invalid signatures, invalid nonces, and replay rejection.

Equivalent direct invocation from Windows:

```powershell
wsl -d Ubuntu2204 -- env `
  PATH=/home/chenhao/verilator/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin `
  make -C /home/chenhao/off-switch/verilog sim TB=top_hss
```

## Capabilities already present

1. `security_block.sv` centrally manages the TRNG, nonce, allowance, workload gating, and verifier selection.
2. `CRYPTO_TYPE=0/1` selects ECDSA or HSS-LMS at compile time.
3. `NUM_SIGNERS=2` implements fixed-order 2-of-2 verification: the same nonce must be accepted by both signers before allowance increases and the nonce changes. The prototype plan's multi-key support is therefore already implemented and covered by top-level tests.
4. The HSS-LMS configuration uses `HSS_LEVELS=2`, `TREE_H=5` per level, LM-OTS `w=8`, and one top-level public root per signer.
5. HSS verification reuses one SHA-256 core from the bottom up. A finite-state machine schedules WOTS, Kc, leaf, and Merkle-path operations sequentially.

## Mapping to the prototype plan

### Highest priority: stateless PQC

The engineering target should use the standardized name **SLH-DSA (FIPS 205)**. A practical first profile is `SLH-DSA-SHA2-128s` because:

- it is closest to the existing SHA-256 hardware;
- Category 1 security is sufficient for the first prototype;
- its public key is 32 bytes, private key is 64 bytes, and signature is 7,856 bytes;
- `128s` is a better verifier-side fit than `128f`: the signature is much smaller and verification requires less hashing, while signing speed is not a chip-side bottleneck because signing occurs on the host or authority.

The SPHINCS+ v3.1 document remains useful for learning the construction, but interoperability and KAT work must use FIPS 205 as the final specification.

### Required companion feature: signature streaming

The current `hss_pkg::license_t` and `security_block` place a complete license on a very wide packed bus. A 7,856-byte SLH-DSA signature cannot use the same interface.

A suitable baseline stream is:

```text
sig_valid, sig_ready, sig_data[31:0], sig_last, sig_error
```

Use a separate fixed-size metadata handshake for the algorithm/profile, total signature length, message or nonce, and signer index. The parser must:

- accept only the exact length and fail closed on truncation, excess data, or an early `last`;
- consume fields in `R -> FORS -> HT(layer 0..d-1)` order;
- apply backpressure to data that cannot yet be consumed instead of building very wide multiplexers;
- bounds-check every counter and clear intermediate state on reset or error.

### SHA state loading and multiple contexts

`sha256_wrap.sv` tracks only one continuous message through `first_q`. It cannot pause a long `T_len` or Kc hash, use the same core for a single-block WOTS chain hash, and then resume the long hash.

Recommended implementation order:

1. **Functional baseline:** store all WOTS endpoints. SLH-DSA-128s needs `35 x 16 = 560` bytes. Generate them first, then calculate `T_len`. This is easiest to verify.
2. **Area optimization:** add SHA state export/import and save the eight 32-bit chaining words, block count, and partial block. Switch between the WOTS-chain context and `T_len` context.
3. **Throughput option:** use two SHA contexts or cores, with one processing chains and the other absorbing endpoints. Evaluate the extra area only after the baseline is stable.

The 14 FORS roots require only 224 bytes, so storing them is acceptable initially. Stream their compression only after functional correctness is established.

### Chip-ID binding and license aggregation

Use a versioned and unambiguous signed message encoding that commits to at least:

```text
protocol_version || algorithm_id || fleet_id || leaf_count || allowance || license_root
```

Per-chip verification should:

1. Reconstruct `nonce_root` from the local nonce and nonce authentication path.
2. Combine the provisioned `chip_id`, position, and `nonce_root` into the license leaf.
3. Reconstruct `license_root` from the license authentication path.
4. Verify the SLH-DSA root signature.
5. Update allowance and rotate the nonce only after every check succeeds.

The Python aggregation toy also signs `id_root` and verifies a separate ID path so that identity binding is visible. The RTL can retain or remove the separate path after the threat model is fixed.

### Deferred items

- **Bitwise gating:** partial signature-bit matches must not be treated as fractional security. A random forgery already matches about half the bits, and unforgeability does not decompose by output bit. This idea may illustrate fault diffusion but cannot define an authorization boundary.
- **Crypto diversification:** retain the current `CRYPTO_TYPE` architecture, but extend it only after the SLH-DSA baseline, streaming interface, and verification coverage are stable.
- **Narrow ECDSA path or branch removal:** these tasks are orthogonal to the stateless-PQC work and should be scheduled separately.

## Suggested RTL module boundaries

```text
security_block
  -> license_stream_parser
  -> slh_dsa_verify_ctrl
       -> h_msg_sha2_mgf1
       -> fors_pk_from_sig
       -> hypertree_verify
            -> wots_pk_from_sig
            -> xmss_root_from_sig
       -> thash_sha2
            -> sha256_context_scheduler
                 -> secworks sha256_core
```

The device does not need secret-PRF or signing logic. The host or authority signs with a standard library; the RTL implements public verification only, which significantly reduces scope.

## Definition of done

Before claiming that SPHINCS+/SLH-DSA is integrated, require at least:

1. A software golden model that matches FIPS 205 or reference KATs byte for byte.
2. Official vectors and randomized differential tests for every RTL building block.
3. Top-level coverage for valid signatures; one-bit changes in every field; incorrect nonce, chip ID, and signer; truncated and oversized streams; replay; and reset interruption.
4. No simulation assertion failures, with both existing `CRYPTO_TYPE` regressions still passing.
5. A synthesis report covering GE/BRAM, maximum frequency, total cycles, signature input time, and hash-block count per stage.
6. Fail-closed behavior: no parsing, length, counter, or SHA scheduling error may increase allowance.

## Version notes

- The local `sphincs+-r3.1-specification.pdf` is the 2022 submission specification.
- NIST published FIPS 205 on 2024-08-13 under the standardized name SLH-DSA, based on SPHINCS+.
- RFC 8554 requires the signing API to update dynamic private-key state and forbids one-time-key reuse. Removing that operational state risk is the motivation for the stateless direction.
