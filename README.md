# Mini-SPHINCS+ Off-Switch Prototype


This repository implements a small end-to-end path from hash chains to an experimental Off-Switch license system:

1. WOTS+ maps base-w message digits to one-way hash chains.
2. Merkle/XMSS compresses WOTS+ public keys into leaves and authenticates them to a fixed root.
3. FORS selects one secret from each small tree according to the message digest and reconstructs a FORS public key.
4. Mini-SPHINCS+ signs the FORS public key with WOTS+ and authenticates it through one XMSS tree without updating secret-key state.
5. The Off-Switch license layer binds `chip_id + nonce + allowance`, grants allowance after successful verification, and immediately rotates the nonce.
6. License aggregation lets four chips share one Mini-SPHINCS+ root signature while each chip carries three Merkle paths for its ID, nonce, and license leaf.
7. Signature streaming emits the signature at any byte width to model an RTL ready/valid input.

## Run the project

In WSL:

```bash
cd ~/toy-sphincs-off-switch
python3 -m unittest discover -s tests -v
python3 examples/demo.py
```

In Windows PowerShell:

```powershell
cd E:\MARS\Off_switch\toy-sphincs-off-switch
python -m unittest discover -s tests -v
python -m examples.demo
```

You can also use:

```powershell
.\run_tests.ps1
.\run_demo.ps1
```

The project uses only the Python standard library and requires Python 3.10 or newer.

## Toy parameters

| Parameter | Toy value | Role in SPHINCS+/SLH-DSA |
|---|---:|---|
| `n` | 4 bytes | Hash-node and security-parameter length; at most 32 bits here and completely insecure |
| `w` | 4 | Winternitz base |
| WOTS+ `len` | 19 | Number of chain elements in each WOTS+ signature |
| FORS | 3 trees of height 2 | Extracts three indices from the message digest |
| XMSS height | 2 | Only four WOTS+ leaves, so keys are reused frequently; demonstration only |
| Signature size | 124 bytes | `R || SIG_FORS || SIG_WOTS || AUTH_XMSS` |

Real SPHINCS+-128s / SLH-DSA-SHA2-128s uses `n=16`, a much taller hypertree, and 14 larger FORS trees. Its signature is 7,856 bytes. The 124-byte toy signature must not be used to estimate real security, area, or bandwidth.

## Signature data flow

```text
message + optrand
        |
        v
  R, H_msg(R, PK, message)
        |
        +--> FORS indices --> selected secrets + auth paths --> FORS public key
                                                            |
                                                            v
                                               WOTS+ signs FORS public key
                                                            |
                                                            v
                                         XMSS auth path --> public root
```

The verifier stores only `(PK.seed, PK.root)`. It reconstructs the FORS public key, WOTS+ public key, XMSS leaf, and final root from the message and signature. Verification succeeds only when the reconstructed root equals `PK.root`.

Here, stateless means that signing does not maintain a monotonically increasing `q` value like RFC 8554. `ToySecretKey` is immutable, so signing never updates it. Real SPHINCS+/SLH-DSA relies on large parameters and a security analysis to control few-time-key selection risk; this tiny tree provides no such guarantee.

## Off-Switch license flow

Direct license:

```text
authority signs(domain || chip_id || current_nonce || allowance)
    -> device verifies
    -> allowance += signed amount
    -> nonce rotates immediately
    -> replay of the old license fails
```

Aggregated license:

```text
ID leaves       -> id_root       --\
nonce leaves    -> nonce_root       +-> authority signs one aggregate message
H(ID_i, root)   -> license_root  --/

each device receives:
  shared signature + its ID path + nonce path + license path
```

The aggregate message signs both `leaf_count` and `allowance`, so the roots cannot be interpreted without their tree-size and authorization semantics. Each leaf also commits to its position to prevent simple reordering.

## Code map

- `toy_sphincs/params.py`: tiny parameters and signature-size formulas.
- `toy_sphincs/utils.py`: domain-separated hashing, integer encoding, and digest-bit parsing.
- `toy_sphincs/merkle.py`: tree construction, authentication paths, and root recovery.
- `toy_sphincs/wots.py`: base-w conversion, checksum, hash chains, signing, and public-key recovery.
- `toy_sphincs/fors.py`: FORS secrets, trees, signing, and public-key recovery.
- `toy_sphincs/sphincs.py`: Mini-SPHINCS+ key generation, signing, verification, and streaming serialization.
- `toy_sphincs/off_switch.py`: nonce handling, allowance, replay protection, and gated workload.
- `toy_sphincs/aggregation.py`: Chip-ID, nonce, and license aggregation trees.
- `tests/test_toy.py`: valid signatures, tampering, wrong messages, statelessness, streaming, replay, chip binding, nonce binding, and aggregation.
- `examples/demo.py`: a Mini-SPHINCS+-only demonstration. It intentionally prints no Off-Switch output.

## Deliberate differences from the standards

- The project does not implement the exact FIPS 205 ADRS encoding, context/prefix interface, or parameter sets.
- `thash` is a project-specific length-prefixed, domain-separated SHA-256 function, not the exact SLH-DSA-SHA2 function family.
- It has one XMSS layer rather than a real multi-layer hypertree.
- `n=4` and height-2 trees provide essentially no security.
- It has no KAT coverage, side-channel hardening, fault protection, constant-time guarantee, or formal security claim.
- Device nonces use a reproducible deterministic generator for testing; production RTL needs an appropriate uniqueness and entropy design.

The next engineering step is not to enlarge the toy parameters. It is to build a FIPS 205-compatible software golden model and compare every field against official KATs or the reference implementation. See `LEARNING_PLAN.md` and `OFF_SWITCH_ASSESSMENT.md`.

## Primary references

- FIPS 205, SLH-DSA based on SPHINCS+: https://csrc.nist.gov/pubs/fips/205/final
- SPHINCS+ v3.1 specification: the PDF supplied with this project
- SPHINCS+ reference implementation: https://github.com/sphincs/sphincsplus
- RFC 8554, HSS/LMS: https://datatracker.ietf.org/doc/html/rfc8554
- Original Off-Switch repository: https://github.com/JamesPetrie/off-switch
