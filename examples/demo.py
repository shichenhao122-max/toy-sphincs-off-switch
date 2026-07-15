from __future__ import annotations

import sys
from pathlib import Path

# Direct execution adds examples/ rather than the project root to sys.path.
# Add the root so both supported invocation styles work without installation.
if __package__ in (None, ""):
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from toy_sphincs.params import DEFAULT_PARAMS
from toy_sphincs.sphincs import keygen, sign, verify


def short(value: bytes) -> str:
    return value.hex()


def main() -> None:
    params = DEFAULT_PARAMS
    secret_key, public_key = keygen(b"reproducible classroom seed", params)

    print("=== Mini-SPHINCS+ building blocks (INSECURE TOY) ===")
    print(
        f"n={params.n} bytes, w={params.w}, WOTS+ len={params.wots_len}, "
        f"FORS={params.fors_trees}x2^{params.fors_height}, "
        f"XMSS height={params.xmss_height}"
    )
    print(f"public root={short(public_key.root)}")

    message = b"Mini-SPHINCS+ demo"
    signature_a = sign(secret_key, message, optrand=b"AAAA", params=params)
    signature_b = sign(secret_key, message, optrand=b"BBBB", params=params)

    print(f"signature bytes={len(signature_a.to_bytes(params))}")
    print(
        f"signature A verifies={verify(public_key, message, signature_a, params)}"
    )
    print(
        f"signature B verifies={verify(public_key, message, signature_b, params)}"
    )
    print(f"stateless signatures differ={signature_a != signature_b}")
    print(
        "tampered message is rejected="
        f"{not verify(public_key, message + b'!', signature_a, params)}"
    )
    print(
        "streamed as 8-byte words="
        f"{len(list(signature_a.iter_chunks(8, params)))} chunks"
    )


if __name__ == "__main__":
    main()
