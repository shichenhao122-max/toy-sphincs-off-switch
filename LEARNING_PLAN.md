# PQC, SPHINCS+/SLH-DSA, and Off-Switch Intensive Learning Plan

The goal is not merely to finish reading cryptography material. Within 20 working days, you should reach three testable outcomes:

1. Explain the LM-OTS/WOTS+, Merkle, FORS, XMSS/hypertree, and SLH-DSA verification chain from the security properties of hash functions.
2. Trace every field of a FIPS 205 signature and validate a software golden model against an official reference implementation or KAT.
3. Specify the streaming SLH-DSA verifier microarchitecture, test plan, and first RTL block for Off-Switch.

Plan for three to five hours per day: about 40% reading, 50% coding or experiments, and 10% oral explanation and notes. If only half a day is available, preserve the order and do not skip the daily acceptance check.

## Study method

Use the same four-step loop for every concept:

1. State in one sentence what problem it solves.
2. Calculate a two-to-four-level example by hand.
3. Locate the corresponding function in this Python toy and print intermediate values.
4. Find the exact input encoding, domain separation, and parameters in the real specification.

For every formula, ask three questions first: What is the byte order? How many bytes are produced? Which address or domain tag prevents cross-purpose reuse? These answers determine whether the RTL can interoperate with the standard.

## Day 0: environment baseline — completed

Tasks:

- Confirm that the WSL checkout matches GitHub `main`.
- Run ECDSA and HSS-LMS lint plus top-level simulation.
- Record the toolchain, run times, and worktree state.

Acceptance: `top_ecdsa` passes 16/16 tests and `top_hss` passes 17/17. See `OFF_SWITCH_ASSESSMENT.md`.

## Days 1-5: hash-signature foundations and RFC 8554

### Day 1: turning a hash function into public-key cryptography

Read SPHINCS+ v3.1 sections 1 and 2.7. Review preimage, second-preimage, collision, multi-target attacks, and Grover search.

Code: run `utils.thash`; remove its domain label to demonstrate cross-purpose ambiguity; compare ambiguous concatenation with and without length prefixes.

You must be able to answer:

- Why does signature security require more than collision resistance?
- Why does quantum search reduce the intuitive security of an n-bit preimage problem to roughly n/2 bits?
- Why is domain separation still required when every function shares one SHA-256 core?

Acceptance: write one page listing the inputs and purpose of `H_msg`, `F`, `H`, and `T_len` in the planned verifier.

### Day 2: Lamport, Winternitz chains, and the checksum

Read RFC 8554 section 4 and SPHINCS+ sections 3.1-3.6.

Code: trace `wots.message_digits`, `wots.chain`, `wots.sign`, and `public_key_from_signature` line by line. Calculate two or three `w=4` chains by hand.

You must be able to explain why the checksum prevents an attacker from only increasing every message digit along the one-way chains, and how increasing `w` changes signature size, chain length, and speed.

Acceptance: after changing one WOTS+ signature element, the recovered WOTS+ public key must change.

### Day 3: Merkle trees and authentication paths

Read RFC 8554 sections 5.3-5.4 and SPHINCS+ sections 4.1.3, 4.1.5, and 4.1.7.

Code: draw a four-leaf tree, calculate the path for index 2, and print the left/right order at each step in `merkle.root_from_path`.

You must be able to explain why the path occupies `h x n` bytes and why each bit of the leaf index selects left or right ordering.

Acceptance: an incorrect index, sibling, or leaf must never recover the original root.

### Day 4: LM-OTS to LMS to HSS — understanding state

Read RFC 8554 sections 2, 4, 5, and 6, especially `q`, key exhaustion, and HSS private-key updates.

Map the code:

- `verilog/rtl/hss_pkg.sv`: `HSS_LEVELS=2`, `TREE_H=5`, `w=8`, and the license layout.
- `verilog/rtl/hss_verify.sv`: Q -> WOTS -> Kc -> Leaf -> Merkle.
- `test/reference_lms.py`: software reference and test-vector generation.

Acceptance: explain in your own words that the verifier needs no persistent state, but the signer must reliably persist `q`; rollback or concurrent reuse of `q` breaks security.

### Day 5: existing Off-Switch data flow

Read `security_block.sv`, `hss_verify.sv`, `sha256_wrap.sv`, and both top-level testbenches.

Produce a diagram covering valid/ready behavior, the nonce lifetime, fixed 2-of-2 signer ordering, allowance updates, and error returns.

Acceptance: identify three concrete bottlenecks: the complete packed-signature bus, the `34 x 256-bit` `pk_store`, and the inability to pause and resume the single SHA context.

## Days 6-11: complete SPHINCS+/SLH-DSA understanding

### Day 6: assemble the full construction

Read SPHINCS+ sections 1 and 6. Learn the data flow before studying security proofs.

Run `examples/demo.py` and trace:

```text
H_msg -> FORS pk -> WOTS+ pk from signature -> XMSS root -> top public root
```

Acceptance: without notes, draw the signature layout `R || SIG_FORS || SIG_HT` and explain why the verifier needs only a small public key.

### Day 7: ADRS and tweakable hashes

Read SPHINCS+ sections 2.7.1-2.7.3 and 7.2.2, then compare the FIPS 205 ADRS structure and SHA2 instantiation.

List the address fields for WOTS hash, WOTS public key, tree, FORS tree, and FORS roots. Mark which fields must be cleared or updated before every call.

Acceptance: construct an incorrect-address-reuse example and explain how it can make different nodes or functions receive the same input.

### Day 8: FORS

Read all of SPHINCS+ section 5, focusing on sections 5.5-5.6.

Code: print the toy digest's three two-bit indices, selected secrets, authentication paths, and three reconstructed roots.

You must be able to answer: Why is FORS a forest instead of one large tree? Why does a signature reveal one secret per tree rather than a whole tree? How do `k` and `a=log(t)` affect size and security?

Acceptance: the FORS public key recovered from the signature equals the signer-side value.

### Day 9: XMSS and the hypertree

Read SPHINCS+ sections 4.1 and 4.2.

Generalize the one-layer toy to `d` layers: the bottom XMSS tree signs the FORS public key, and every higher XMSS tree signs the root below it.

Acceptance: given `(h,d)`, calculate the per-layer height `h/d`, the number of WOTS+ signatures in the hypertree, and the total number of authentication-path nodes.

### Day 10: SPX key generation, signing, and verification

Read SPHINCS+ sections 6.2-6.5 and follow the pseudocode line by line.

Create a three-column trace containing the specification variable, Python-toy variable, and planned RTL register or FIFO. Include `R`, `md`, `idx_tree`, and `idx_leaf`.

Acceptance: starting from a message and one toy signature, list every verifier input and output in order.

### Day 11: parameters, security, and engineering tradeoffs

Read SPHINCS+ sections 7.1, 8, 9.4, 10, and 11.

Compare 128s and 128f by signature size, signing time, verification hashes, and tree layers. Prefer `SLH-DSA-SHA2-128s` for the first Off-Switch verifier.

Acceptance: write the selection rationale: why not start at 256-bit security, why choose SHA2, and why choose the small profile rather than the fast profile.

## Days 12-14: move from the toy to a standards-compliant golden model

### Day 12: FIPS 205 difference list

Read FIPS 205 and build a terminology and encoding comparison against the 2022 v3.1 submission. Use SLH-DSA as the final engineering name and SPHINCS+ only to explain its origin.

Acceptance: list every non-compliant toy feature, including parameters, ADRS, hash instantiation, context/prefix handling, tree layers, KAT coverage, and randomization rules.

### Day 13: official reference implementation and KATs

Use `https://github.com/sphincs/sphincsplus` or a FIPS 205-compatible reference and fix the profile to `SLH-DSA-SHA2-128s`.

Tasks:

- Build the reference implementation.
- Generate a key and signature from fixed seed, message, and `optrand` values.
- Save the public key, signature, and every field offset.
- Confirm that an incorrect message and a one-bit change in every signature region fail.

Acceptance: the standard implementation produces a 7,856-byte signature and passes KAT or reference verification.

### Day 14: exact verifier golden model

Do not keep expanding the toy. Create `golden/slh_dsa_sha2_128s`, implement or wrap the standard exactly, and expose a stage-by-stage trace.

Acceptance: the Python or C golden trace matches the reference final root, FORS public key, and every XMSS-layer root.

## Days 15-20: RTL microarchitecture and integration

### Day 15: freeze the streaming interface and error model

Define a 32-bit or 64-bit signature stream, metadata handshake, backpressure, exact-length checking, reset/abort behavior, and error codes. Write the SystemVerilog interface and assertions before adding cryptographic logic.

Acceptance: random stalls, truncation, excess data, duplicate `last`, and reset interruption all fail closed.

### Day 16: SHA2 function family

Implement and verify BlockPad(PK.seed), compressed ADRS, `F`, `H`, `T_len`, and `H_msg/MGF1`. Start with one SHA context and an endpoint buffer.

Acceptance: each function matches the golden model byte for byte on at least 100 randomized vectors.

### Day 17: WOTS+ and XMSS root from signature

Reuse the existing WOTS/Merkle state-machine approach, but use FIPS 205 parameters and 16-byte elements. Do not optimize state loading yet.

Acceptance: the standalone block recovers a leaf from a standard WOTS+ signature and then recovers the XMSS root from its authentication path.

### Day 18: FORS public key from signature

Recover the roots of 14 trees of height 12. Consume the signature as a stream and retain only the current secret, node, path, and 14 roots.

Acceptance: the FORS public key matches the golden trace, and changing any secret or path bit fails verification.

### Day 19: hypertree and top-level verification

Feed the FORS public key into seven XMSS layers for the 128s profile. Each layer consumes one WOTS+ signature and authentication path; compare the final result with `PK.root`.

Acceptance: an official complete signature passes; changes to the message, R, FORS, or any hypertree layer fail.

### Day 20: Off-Switch integration, aggregation, and synthesis

Connect the verifier to the `security_block` cryptographic abstraction while preserving ECDSA and HSS regressions. Add Chip-ID/nonce message encoding and an aggregate-root verifier.

Acceptance:

- Existing ECDSA passes 16/16 and HSS passes 17/17.
- SLH-DSA direct and aggregate top-level tests pass.
- Produce Yosys/STA results for GE, BRAM, Fmax, total cycles, and hash-block count per stage.
- State signature-transfer time. For example, 7,856 bytes on a 32-bit, 100 MHz stream with no stalls has a pure input lower bound of about 19.64 microseconds; hash verification dominates real latency.

## Optimization order after the baseline

1. Add SHA state export/import to remove the 560-byte WOTS endpoint buffer.
2. Compress FORS roots through `T_k` as a stream.
3. Compare 32-bit, 64-bit, and 256-bit input widths against the scan, UART, or management fabric.
4. Use formal assertions to prove that allowance can increase only after complete successful verification.
5. Add fault detection through duplicated state/counters, recomputed final roots, temporal redundancy, and latched errors.
6. Evaluate cryptographic diversification and higher security categories only afterward.

## Weekly review questions

- Can I identify whether arbitrary signature bytes belong to R, FORS, or a particular XMSS layer?
- Can I write the exact byte string for the current hash call instead of saying only "hash it"?
- Can I identify the minimum verifier state that must be stored?
- Does every malformed stream fail closed?
- Do the Python golden model, reference implementation, and RTL use the same vectors?
- Am I incorrectly treating a passing educational toy as a secure standard implementation?

## Reading order — do not start with the security proofs

1. This project's `README.md` and `examples/demo.py`.
2. RFC 8554 sections 2, 4, 5, and 6.
3. SPHINCS+ v3.1 sections 1, 2.7, 3, 4, 5, and 6.
4. SPHINCS+ sections 7.1, 7.2.2, 8, 9.4, 10, and 11.
5. All of FIPS 205 as the final interoperability specification.
6. The SPHINCS+ reference `ref/` directory: start at the sign/verify call graph, then inspect address, hash, and thash code.
7. Off-Switch `hss_pkg.sv`, `hss_verify.sv`, `sha256_wrap.sv`, `security_block.sv`, and the testbenches.

The final readiness test is simple: if you can stream a FIPS 205 signature through a hand-drawn RTL state machine and predict every SHA block, saved state, and reconstructed root, you have moved from understanding the theory to being able to implement it.
