from __future__ import annotations

import hmac
import secrets
from collections.abc import Iterable
from dataclasses import dataclass

from . import fors, merkle, wots
from .fors import FORSProof
from .params import DEFAULT_PARAMS, ToyParams
from .utils import chunks, extract_msb_fields, thash, u32


@dataclass(frozen=True)
class ToyPublicKey:
    pub_seed: bytes
    root: bytes


@dataclass(frozen=True)
class ToySecretKey:
    sk_seed: bytes
    sk_prf: bytes
    public_key: ToyPublicKey


@dataclass(frozen=True)
class ToySignature:
    randomizer: bytes
    fors_proofs: tuple[FORSProof, ...]
    wots_signature: tuple[bytes, ...]
    xmss_auth_path: tuple[bytes, ...]

    def to_bytes(self, params: ToyParams = DEFAULT_PARAMS) -> bytes:
        parts: list[bytes] = [self.randomizer]
        for proof in self.fors_proofs:
            parts.append(proof.secret)
            parts.extend(proof.auth_path)
        parts.extend(self.wots_signature)
        parts.extend(self.xmss_auth_path)
        encoded = b"".join(parts)
        if len(encoded) != params.signature_bytes:
            raise ValueError("signature shape does not match parameters")
        return encoded

    def iter_chunks(
        self,
        chunk_size: int,
        params: ToyParams = DEFAULT_PARAMS,
    ) -> Iterable[bytes]:
        return chunks(self.to_bytes(params), chunk_size)

    @classmethod
    def from_bytes(
        cls,
        data: bytes,
        params: ToyParams = DEFAULT_PARAMS,
    ) -> "ToySignature":
        if len(data) != params.signature_bytes:
            raise ValueError(
                f"expected {params.signature_bytes} signature bytes, got {len(data)}"
            )
        offset = 0

        def take() -> bytes:
            nonlocal offset
            value = data[offset : offset + params.n]
            offset += params.n
            return value

        randomizer = take()
        fors_proofs = []
        for _ in range(params.fors_trees):
            secret = take()
            path = tuple(take() for _ in range(params.fors_height))
            fors_proofs.append(FORSProof(secret=secret, auth_path=path))
        wots_signature = tuple(take() for _ in range(params.wots_len))
        xmss_auth_path = tuple(take() for _ in range(params.xmss_height))
        if offset != len(data):
            raise AssertionError("internal signature parser mismatch")
        return cls(
            randomizer=randomizer,
            fors_proofs=tuple(fors_proofs),
            wots_signature=wots_signature,
            xmss_auth_path=xmss_auth_path,
        )


def _xmss_leaf(
    params: ToyParams,
    sk_seed: bytes,
    pub_seed: bytes,
    leaf_index: int,
) -> bytes:
    wots_public_key = wots.public_key(params, sk_seed, pub_seed, leaf_index)
    return thash(
        params,
        b"xmss-leaf",
        pub_seed,
        u32(leaf_index),
        wots_public_key,
    )


def _xmss_leaves(params: ToyParams, sk_seed: bytes, pub_seed: bytes) -> list[bytes]:
    return [
        _xmss_leaf(params, sk_seed, pub_seed, leaf_index)
        for leaf_index in range(1 << params.xmss_height)
    ]


def keygen(
    master_seed: bytes | None = None,
    params: ToyParams = DEFAULT_PARAMS,
) -> tuple[ToySecretKey, ToyPublicKey]:
    seed = master_seed if master_seed is not None else secrets.token_bytes(32)
    if not seed:
        raise ValueError("master seed must not be empty")
    sk_seed = thash(params, b"derive-sk-seed", seed)
    sk_prf = thash(params, b"derive-sk-prf", seed)
    pub_seed = thash(params, b"derive-pub-seed", seed)
    leaves = _xmss_leaves(params, sk_seed, pub_seed)
    public_key = ToyPublicKey(
        pub_seed=pub_seed,
        root=merkle.root(params, leaves, b"xmss"),
    )
    return (
        ToySecretKey(sk_seed=sk_seed, sk_prf=sk_prf, public_key=public_key),
        public_key,
    )


def _message_digest(
    params: ToyParams,
    randomizer: bytes,
    public_key: ToyPublicKey,
    message: bytes,
) -> bytes:
    return thash(
        params,
        b"h-msg",
        randomizer,
        public_key.pub_seed,
        public_key.root,
        message,
    )


def _leaf_index(params: ToyParams, digest: bytes) -> int:
    fields = extract_msb_fields(
        digest,
        [params.fors_trees * params.fors_height, params.xmss_height],
    )
    return fields[1]


def sign(
    secret_key: ToySecretKey,
    message: bytes,
    *,
    optrand: bytes | None = None,
    params: ToyParams = DEFAULT_PARAMS,
) -> ToySignature:
    """Sign without updating secret-key state.

    The tiny tree means WOTS+ leaf reuse happens quickly; real SPHINCS+/SLH-DSA
    uses carefully selected, vastly larger parameters to make that safe.
    """

    randomness = optrand if optrand is not None else secrets.token_bytes(params.n)
    randomizer = thash(params, b"randomizer", secret_key.sk_prf, randomness, message)
    digest = _message_digest(params, randomizer, secret_key.public_key, message)
    leaf_index = _leaf_index(params, digest)

    fors_proofs, fors_public_key = fors.sign(
        params,
        digest,
        secret_key.sk_seed,
        secret_key.public_key.pub_seed,
    )
    wots_signature = wots.sign(
        params,
        fors_public_key,
        secret_key.sk_seed,
        secret_key.public_key.pub_seed,
        leaf_index,
    )
    leaves = _xmss_leaves(
        params,
        secret_key.sk_seed,
        secret_key.public_key.pub_seed,
    )
    xmss_auth_path = merkle.auth_path(params, leaves, leaf_index, b"xmss")
    return ToySignature(
        randomizer=randomizer,
        fors_proofs=fors_proofs,
        wots_signature=wots_signature,
        xmss_auth_path=xmss_auth_path,
    )


def verify(
    public_key: ToyPublicKey,
    message: bytes,
    signature: ToySignature,
    params: ToyParams = DEFAULT_PARAMS,
) -> bool:
    try:
        if len(signature.randomizer) != params.n:
            return False
        digest = _message_digest(params, signature.randomizer, public_key, message)
        leaf_index = _leaf_index(params, digest)
        fors_public_key = fors.public_key_from_signature(
            params,
            signature.fors_proofs,
            digest,
            public_key.pub_seed,
        )
        wots_public_key = wots.public_key_from_signature(
            params,
            signature.wots_signature,
            fors_public_key,
            public_key.pub_seed,
            leaf_index,
        )
        leaf = thash(
            params,
            b"xmss-leaf",
            public_key.pub_seed,
            u32(leaf_index),
            wots_public_key,
        )
        candidate_root = merkle.root_from_path(
            params,
            leaf,
            leaf_index,
            signature.xmss_auth_path,
            b"xmss",
        )
        return hmac.compare_digest(candidate_root, public_key.root)
    except (IndexError, TypeError, ValueError):
        return False
