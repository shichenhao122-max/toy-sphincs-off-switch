from __future__ import annotations

import sys
from pathlib import Path

# When this file is executed directly, Python adds examples/ rather than the
# project root to sys.path. Add the root so both `python examples/demo.py` and
# `python -m examples.demo` work without installing the package.
if __package__ in (None, ""):
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from toy_sphincs.params import DEFAULT_PARAMS
from toy_sphincs.sphincs import keygen, sign, verify


# Temporarily keep the Off-Switch license demos disabled. Set this to True to
# restore the direct-license and four-chip aggregation sections below.
RUN_OFF_SWITCH_DEMOS = False

if RUN_OFF_SWITCH_DEMOS:
    from toy_sphincs.aggregation import (
        issue_aggregate_licenses,
        verify_aggregate_license,
    )
    from toy_sphincs.off_switch import OffSwitch, issue_direct_license


def short(value: bytes) -> str:
    return value.hex()


def main() -> None:
    params = DEFAULT_PARAMS
    secret_key, public_key = keygen(b"reproducible classroom seed", params)

    print("=== Mini-SPHINCS+ building blocks (INSECURE TOY) ===")
    print(
        f"n={params.n} bytes, w={params.w}, WOTS len={params.wots_len}, "
        f"FORS={params.fors_trees}x2^{params.fors_height}, "
        f"XMSS height={params.xmss_height}"
    )
    print(f"public root={short(public_key.root)}")

    message = b"license-demo"
    sig_a = sign(secret_key, message, optrand=b"AAAA", params=params)
    sig_b = sign(secret_key, message, optrand=b"BBBB", params=params)
    print(f"signature bytes={len(sig_a.to_bytes(params))}")
    print(f"signature A verifies={verify(public_key, message, sig_a, params)}")
    print(f"signature B verifies={verify(public_key, message, sig_b, params)}")
    print(f"stateless signatures differ={sig_a != sig_b}")
    print(
        "streamed as 8-byte words="
        f"{len(list(sig_a.iter_chunks(8, params)))} chunks"
    )

    if not RUN_OFF_SWITCH_DEMOS:
        return

    print("\n=== Direct Off-Switch license ===")
    switch = OffSwitch(public_key, b"chip-0001", params=params)
    print(f"initial nonce={short(switch.nonce)}, work(50,30)={switch.work(50, 30)}")
    direct = issue_direct_license(
        secret_key,
        switch.chip_id,
        switch.nonce,
        allowance=5,
        optrand=b"DIR1",
        params=params,
    )
    old_nonce = switch.nonce
    print(f"accepted={switch.accept_direct_license(direct)}, allowance={switch.allowance}")
    print(f"work(50,30)={switch.work(50, 30)}, nonce rotated={switch.nonce != old_nonce}")
    print(f"replay accepted={switch.accept_direct_license(direct)}")
    switch.tick(5)
    print(f"after five cycles: enabled={switch.enabled}, work(50,30)={switch.work(50, 30)}")

    print("\n=== One signature aggregated across four chips ===")
    fleet = [OffSwitch(public_key, f"chip-{index:04d}".encode(), params=params) for index in range(4)]
    batch = issue_aggregate_licenses(
        secret_key,
        [(device.chip_id, device.nonce) for device in fleet],
        allowance=7,
        optrand=b"AGG1",
        params=params,
    )
    shared_signature = all(
        license.signature is batch.licenses[0].signature for license in batch.licenses
    )
    print(f"id_root={short(batch.id_root)}")
    print(f"nonce_root={short(batch.nonce_root)}")
    print(f"license_root={short(batch.license_root)}")
    print(f"all proofs share one signature object={shared_signature}")
    results = [
        device.accept_aggregate_license(license)
        for device, license in zip(fleet, batch.licenses, strict=True)
    ]
    print(f"accepted by fleet={results}")

    fresh = OffSwitch(public_key, b"chip-0000", params=params)
    wrong_nonce = bytes([fresh.nonce[0] ^ 1]) + fresh.nonce[1:]
    print(
        "tampered nonce proof verifies="
        f"{verify_aggregate_license(public_key, fresh.chip_id, wrong_nonce, batch.licenses[0], params)}"
    )


if __name__ == "__main__":
    main()
