"""A self-contained, deliberately insecure Mini-SPHINCS+ demonstration.

This file uses tiny parameters and simplified encodings so that the complete
hash-based signature flow is easy to inspect. It is not compatible with
SPHINCS+, SLH-DSA, or any production cryptographic implementation.
"""

from __future__ import annotations

import hashlib
import hmac
import secrets
from dataclasses import dataclass
from typing import Sequence


@dataclass(frozen=True)
class ToyParams:
    """Tiny parameters chosen for visibility and speed, not security."""

    n: int = 4
    w: int = 4
    fors_trees: int = 3
    fors_height: int = 2
    xmss_height: int = 2

    def __post_init__(self) -> None:
        if self.n < 1:
            raise ValueError("n must be positive")
        if self.w < 2 or self.w & (self.w - 1):
            raise ValueError("w must be a power of two")
        if 8 % self.log_w:
            raise ValueError("this demo requires log2(w) to divide 8")
        if self.required_digest_bits > self.n * 8:
            raise ValueError("the digest is too short for the selected indices")

    @property
    def log_w(self) -> int:
        return self.w.bit_length() - 1

    @property
    def wots_len1(self) -> int:
        return (8 * self.n + self.log_w - 1) // self.log_w

    @property
    def wots_len2(self) -> int:
        value = self.wots_len1 * (self.w - 1)
        digits = 0
        while value:
            digits += 1
            value //= self.w
        return max(1, digits)

    @property
    def wots_len(self) -> int:
        return self.wots_len1 + self.wots_len2

    @property
    def required_digest_bits(self) -> int:
        return self.fors_trees * self.fors_height + self.xmss_height

    @property
    def signature_bytes(self) -> int:
        randomizer = self.n
        fors = self.fors_trees * (1 + self.fors_height) * self.n
        wots = self.wots_len * self.n
        xmss_path = self.xmss_height * self.n
        return randomizer + fors + wots + xmss_path


PARAMS = ToyParams()


def u16(value: int) -> bytes:
    return value.to_bytes(2, "big")


def u32(value: int) -> bytes:
    return value.to_bytes(4, "big")


def toy_hash(params: ToyParams, domain: bytes, *parts: bytes) -> bytes:
    """Return a domain-separated SHA-256 result truncated to n bytes."""

    if len(domain) > 255:
        raise ValueError("domain label is too long")
    state = hashlib.sha256()
    state.update(b"MINI-SPHINCS+\x00")
    state.update(bytes([len(domain)]))
    state.update(domain)
    for part in parts:
        state.update(u32(len(part)))
        state.update(part)
    return state.digest()[: params.n]


def extract_msb_fields(data: bytes, widths: Sequence[int]) -> list[int]:
    """Split the most significant digest bits into fixed-width integers."""

    total_width = sum(widths)
    if total_width > len(data) * 8:
        raise ValueError("not enough digest bits")
    value = int.from_bytes(data, "big") >> (len(data) * 8 - total_width)
    fields: list[int] = []
    remaining = total_width
    for width in widths:
        remaining -= width
        fields.append((value >> remaining) & ((1 << width) - 1))
    return fields


# ---------------------------------------------------------------------------
# Merkle tree helpers
# ---------------------------------------------------------------------------


def merkle_levels(
    params: ToyParams, leaves: Sequence[bytes], tree_tag: bytes
) -> list[list[bytes]]:
    if not leaves or len(leaves) & (len(leaves) - 1):
        raise ValueError("the number of leaves must be a power of two")
    if any(len(leaf) != params.n for leaf in leaves):
        raise ValueError("every leaf must contain n bytes")

    levels = [list(leaves)]
    level_number = 0
    while len(levels[-1]) > 1:
        current = levels[-1]
        parent = [
            toy_hash(
                params,
                b"merkle-node:" + tree_tag,
                u32(level_number),
                current[index],
                current[index + 1],
            )
            for index in range(0, len(current), 2)
        ]
        levels.append(parent)
        level_number += 1
    return levels


def merkle_root(
    params: ToyParams, leaves: Sequence[bytes], tree_tag: bytes
) -> bytes:
    return merkle_levels(params, leaves, tree_tag)[-1][0]


def merkle_auth_path(
    params: ToyParams, leaves: Sequence[bytes], index: int, tree_tag: bytes
) -> tuple[bytes, ...]:
    levels = merkle_levels(params, leaves, tree_tag)
    if not 0 <= index < len(leaves):
        raise IndexError("leaf index is outside the tree")
    path: list[bytes] = []
    node_index = index
    for level in levels[:-1]:
        path.append(level[node_index ^ 1])
        node_index >>= 1
    return tuple(path)


def merkle_root_from_path(
    params: ToyParams,
    leaf: bytes,
    index: int,
    path: Sequence[bytes],
    tree_tag: bytes,
) -> bytes:
    if len(leaf) != params.n or any(len(node) != params.n for node in path):
        raise ValueError("leaf and authentication nodes must contain n bytes")
    node = leaf
    node_index = index
    for level_number, sibling in enumerate(path):
        left, right = (sibling, node) if node_index & 1 else (node, sibling)
        node = toy_hash(
            params,
            b"merkle-node:" + tree_tag,
            u32(level_number),
            left,
            right,
        )
        node_index >>= 1
    return node


# ---------------------------------------------------------------------------
# WOTS+: Winternitz one-time signatures
# ---------------------------------------------------------------------------


def base_w(params: ToyParams, data: bytes, output_length: int) -> list[int]:
    digits: list[int] = []
    accumulator = 0
    available_bits = 0
    mask = params.w - 1
    for byte in data:
        accumulator = (accumulator << 8) | byte
        available_bits += 8
        while available_bits >= params.log_w and len(digits) < output_length:
            available_bits -= params.log_w
            digits.append((accumulator >> available_bits) & mask)
    if len(digits) != output_length:
        raise ValueError("input does not contain enough base-w digits")
    return digits


def wots_message_digits(params: ToyParams, digest: bytes) -> list[int]:
    if len(digest) != params.n:
        raise ValueError("a WOTS+ digest must contain n bytes")
    digits = base_w(params, digest, params.wots_len1)
    checksum = sum(params.w - 1 - digit for digit in digits)
    checksum_digits = [0] * params.wots_len2
    for index in range(params.wots_len2 - 1, -1, -1):
        checksum_digits[index] = checksum % params.w
        checksum //= params.w
    return digits + checksum_digits


def wots_secret_element(
    params: ToyParams,
    secret_seed: bytes,
    public_seed: bytes,
    leaf_index: int,
    chain_index: int,
) -> bytes:
    return toy_hash(
        params,
        b"wots-secret",
        secret_seed,
        public_seed,
        u32(leaf_index),
        u16(chain_index),
    )


def wots_chain(
    params: ToyParams,
    start_value: bytes,
    start_step: int,
    steps: int,
    public_seed: bytes,
    leaf_index: int,
    chain_index: int,
) -> bytes:
    if len(start_value) != params.n:
        raise ValueError("a WOTS+ chain value must contain n bytes")
    if start_step < 0 or steps < 0 or start_step + steps > params.w - 1:
        raise ValueError("invalid WOTS+ chain range")
    value = start_value
    for step in range(start_step, start_step + steps):
        value = toy_hash(
            params,
            b"wots-chain",
            public_seed,
            u32(leaf_index),
            u16(chain_index),
            u16(step),
            value,
        )
    return value


def wots_public_key(
    params: ToyParams, secret_seed: bytes, public_seed: bytes, leaf_index: int
) -> bytes:
    endpoints = []
    for chain_index in range(params.wots_len):
        secret = wots_secret_element(
            params, secret_seed, public_seed, leaf_index, chain_index
        )
        endpoints.append(
            wots_chain(
                params,
                secret,
                0,
                params.w - 1,
                public_seed,
                leaf_index,
                chain_index,
            )
        )
    return toy_hash(
        params, b"wots-public-key", public_seed, u32(leaf_index), *endpoints
    )


def wots_sign(
    params: ToyParams,
    digest: bytes,
    secret_seed: bytes,
    public_seed: bytes,
    leaf_index: int,
) -> tuple[bytes, ...]:
    signature = []
    for chain_index, digit in enumerate(wots_message_digits(params, digest)):
        secret = wots_secret_element(
            params, secret_seed, public_seed, leaf_index, chain_index
        )
        signature.append(
            wots_chain(
                params,
                secret,
                0,
                digit,
                public_seed,
                leaf_index,
                chain_index,
            )
        )
    return tuple(signature)


def wots_public_key_from_signature(
    params: ToyParams,
    signature: Sequence[bytes],
    digest: bytes,
    public_seed: bytes,
    leaf_index: int,
) -> bytes:
    if len(signature) != params.wots_len:
        raise ValueError("wrong number of WOTS+ signature elements")
    endpoints = []
    for chain_index, (element, digit) in enumerate(
        zip(signature, wots_message_digits(params, digest), strict=True)
    ):
        endpoints.append(
            wots_chain(
                params,
                element,
                digit,
                params.w - 1 - digit,
                public_seed,
                leaf_index,
                chain_index,
            )
        )
    return toy_hash(
        params, b"wots-public-key", public_seed, u32(leaf_index), *endpoints
    )


# ---------------------------------------------------------------------------
# FORS: a forest of small Merkle trees
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class ForsProof:
    secret: bytes
    auth_path: tuple[bytes, ...]


def fors_indices(params: ToyParams, digest: bytes) -> list[int]:
    return extract_msb_fields(digest, [params.fors_height] * params.fors_trees)


def fors_secret(
    params: ToyParams,
    secret_seed: bytes,
    public_seed: bytes,
    tree_index: int,
    leaf_index: int,
) -> bytes:
    return toy_hash(
        params,
        b"fors-secret",
        secret_seed,
        public_seed,
        u16(tree_index),
        u32(leaf_index),
    )


def fors_leaf(
    params: ToyParams,
    secret: bytes,
    public_seed: bytes,
    tree_index: int,
    leaf_index: int,
) -> bytes:
    return toy_hash(
        params,
        b"fors-leaf",
        public_seed,
        u16(tree_index),
        u32(leaf_index),
        secret,
    )


def fors_leaves(
    params: ToyParams,
    secret_seed: bytes,
    public_seed: bytes,
    tree_index: int,
) -> list[bytes]:
    return [
        fors_leaf(
            params,
            fors_secret(params, secret_seed, public_seed, tree_index, leaf_index),
            public_seed,
            tree_index,
            leaf_index,
        )
        for leaf_index in range(1 << params.fors_height)
    ]


def fors_sign(
    params: ToyParams,
    digest: bytes,
    secret_seed: bytes,
    public_seed: bytes,
) -> tuple[tuple[ForsProof, ...], bytes]:
    proofs = []
    roots = []
    for tree_index, leaf_index in enumerate(fors_indices(params, digest)):
        leaves = fors_leaves(params, secret_seed, public_seed, tree_index)
        tag = b"fors-" + u16(tree_index)
        proofs.append(
            ForsProof(
                secret=fors_secret(
                    params, secret_seed, public_seed, tree_index, leaf_index
                ),
                auth_path=merkle_auth_path(params, leaves, leaf_index, tag),
            )
        )
        roots.append(merkle_root(params, leaves, tag))
    public_key = toy_hash(params, b"fors-public-key", public_seed, *roots)
    return tuple(proofs), public_key


def fors_public_key_from_signature(
    params: ToyParams,
    proofs: Sequence[ForsProof],
    digest: bytes,
    public_seed: bytes,
) -> bytes:
    if len(proofs) != params.fors_trees:
        raise ValueError("wrong number of FORS proofs")
    roots = []
    for tree_index, (proof, leaf_index) in enumerate(
        zip(proofs, fors_indices(params, digest), strict=True)
    ):
        if len(proof.auth_path) != params.fors_height:
            raise ValueError("wrong FORS authentication path length")
        leaf = fors_leaf(
            params, proof.secret, public_seed, tree_index, leaf_index
        )
        roots.append(
            merkle_root_from_path(
                params,
                leaf,
                leaf_index,
                proof.auth_path,
                b"fors-" + u16(tree_index),
            )
        )
    return toy_hash(params, b"fors-public-key", public_seed, *roots)


# ---------------------------------------------------------------------------
# Mini-SPHINCS+: FORS + WOTS+ + one XMSS tree
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class PublicKey:
    public_seed: bytes
    root: bytes


@dataclass(frozen=True)
class SecretKey:
    secret_seed: bytes
    secret_prf: bytes
    public_key: PublicKey


@dataclass(frozen=True)
class Signature:
    randomizer: bytes
    fors_proofs: tuple[ForsProof, ...]
    wots_signature: tuple[bytes, ...]
    xmss_auth_path: tuple[bytes, ...]

    def to_bytes(self, params: ToyParams = PARAMS) -> bytes:
        parts = [self.randomizer]
        for proof in self.fors_proofs:
            parts.append(proof.secret)
            parts.extend(proof.auth_path)
        parts.extend(self.wots_signature)
        parts.extend(self.xmss_auth_path)
        encoded = b"".join(parts)
        if len(encoded) != params.signature_bytes:
            raise ValueError("signature shape does not match the parameters")
        return encoded


def xmss_leaf(
    params: ToyParams,
    secret_seed: bytes,
    public_seed: bytes,
    leaf_index: int,
) -> bytes:
    return toy_hash(
        params,
        b"xmss-leaf",
        public_seed,
        u32(leaf_index),
        wots_public_key(params, secret_seed, public_seed, leaf_index),
    )


def xmss_leaves(
    params: ToyParams, secret_seed: bytes, public_seed: bytes
) -> list[bytes]:
    return [
        xmss_leaf(params, secret_seed, public_seed, leaf_index)
        for leaf_index in range(1 << params.xmss_height)
    ]


def keygen(
    master_seed: bytes | None = None, params: ToyParams = PARAMS
) -> tuple[SecretKey, PublicKey]:
    seed = master_seed if master_seed is not None else secrets.token_bytes(32)
    if not seed:
        raise ValueError("master seed must not be empty")
    secret_seed = toy_hash(params, b"derive-secret-seed", seed)
    secret_prf = toy_hash(params, b"derive-secret-prf", seed)
    public_seed = toy_hash(params, b"derive-public-seed", seed)
    root = merkle_root(
        params, xmss_leaves(params, secret_seed, public_seed), b"xmss"
    )
    public_key = PublicKey(public_seed=public_seed, root=root)
    return SecretKey(secret_seed, secret_prf, public_key), public_key


def message_digest(
    params: ToyParams, randomizer: bytes, public_key: PublicKey, message: bytes
) -> bytes:
    return toy_hash(
        params,
        b"message-digest",
        randomizer,
        public_key.public_seed,
        public_key.root,
        message,
    )


def xmss_leaf_index(params: ToyParams, digest: bytes) -> int:
    fields = extract_msb_fields(
        digest,
        [params.fors_trees * params.fors_height, params.xmss_height],
    )
    return fields[1]


def sign(
    secret_key: SecretKey,
    message: bytes,
    *,
    optrand: bytes | None = None,
    params: ToyParams = PARAMS,
) -> Signature:
    """Sign without modifying the secret key or maintaining an index."""

    randomness = optrand if optrand is not None else secrets.token_bytes(params.n)
    randomizer = toy_hash(
        params, b"randomizer", secret_key.secret_prf, randomness, message
    )
    digest = message_digest(params, randomizer, secret_key.public_key, message)
    leaf_index = xmss_leaf_index(params, digest)
    proofs, fors_public_key = fors_sign(
        params,
        digest,
        secret_key.secret_seed,
        secret_key.public_key.public_seed,
    )
    wots_signature = wots_sign(
        params,
        fors_public_key,
        secret_key.secret_seed,
        secret_key.public_key.public_seed,
        leaf_index,
    )
    path = merkle_auth_path(
        params,
        xmss_leaves(
            params, secret_key.secret_seed, secret_key.public_key.public_seed
        ),
        leaf_index,
        b"xmss",
    )
    return Signature(randomizer, proofs, wots_signature, path)


def verify(
    public_key: PublicKey,
    message: bytes,
    signature: Signature,
    params: ToyParams = PARAMS,
) -> bool:
    try:
        if len(signature.randomizer) != params.n:
            return False
        digest = message_digest(params, signature.randomizer, public_key, message)
        leaf_index = xmss_leaf_index(params, digest)
        fors_public_key = fors_public_key_from_signature(
            params, signature.fors_proofs, digest, public_key.public_seed
        )
        wots_key = wots_public_key_from_signature(
            params,
            signature.wots_signature,
            fors_public_key,
            public_key.public_seed,
            leaf_index,
        )
        leaf = toy_hash(
            params,
            b"xmss-leaf",
            public_key.public_seed,
            u32(leaf_index),
            wots_key,
        )
        candidate_root = merkle_root_from_path(
            params, leaf, leaf_index, signature.xmss_auth_path, b"xmss"
        )
        return hmac.compare_digest(candidate_root, public_key.root)
    except (IndexError, TypeError, ValueError):
        return False


def tamper_with_signature(signature: Signature) -> Signature:
    """Flip one bit in the first revealed FORS secret."""

    first = signature.fors_proofs[0]
    changed_secret = bytes([first.secret[0] ^ 1]) + first.secret[1:]
    changed_proof = ForsProof(changed_secret, first.auth_path)
    return Signature(
        signature.randomizer,
        (changed_proof, *signature.fors_proofs[1:]),
        signature.wots_signature,
        signature.xmss_auth_path,
    )


def main() -> None:
    params = PARAMS
    secret_key, public_key = keygen(b"reproducible classroom seed", params)
    original_secret_key = secret_key
    message = b"Mini-SPHINCS+ demonstration"

    signature_a = sign(secret_key, message, optrand=b"AAAA", params=params)
    signature_b = sign(secret_key, message, optrand=b"BBBB", params=params)
    tampered_signature = tamper_with_signature(signature_a)

    print("=== Mini-SPHINCS+ signature demo (INSECURE TOY) ===")
    print("This is an educational model, not production cryptography.")
    print(
        f"Parameters: n={params.n} bytes, w={params.w}, "
        f"WOTS+ chains={params.wots_len}, "
        f"FORS={params.fors_trees} x 2^{params.fors_height}, "
        f"XMSS height={params.xmss_height}"
    )
    print(f"Public root: {public_key.root.hex()}")
    print(f"Signature size: {len(signature_a.to_bytes(params))} bytes")
    print(f"Signature A verifies: {verify(public_key, message, signature_a, params)}")
    print(f"Signature B verifies: {verify(public_key, message, signature_b, params)}")
    print(f"Randomized signatures differ: {signature_a != signature_b}")
    print(f"Secret key stayed unchanged: {secret_key == original_secret_key}")
    print(
        "Modified message is rejected: "
        f"{not verify(public_key, message + b'!', signature_a, params)}"
    )
    print(
        "Tampered signature is rejected: "
        f"{not verify(public_key, message, tampered_signature, params)}"
    )


if __name__ == "__main__":
    main()
