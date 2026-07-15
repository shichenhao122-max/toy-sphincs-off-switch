from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass

from . import merkle
from .params import ToyParams
from .utils import extract_msb_fields, thash, u32


@dataclass(frozen=True)
class FORSProof:
    secret: bytes
    auth_path: tuple[bytes, ...]


def message_indices(params: ToyParams, digest: bytes) -> list[int]:
    return extract_msb_fields(digest, [params.fors_height] * params.fors_trees)


def _tree_tag(tree_index: int) -> bytes:
    return b"fors-" + u32(tree_index)


def _secret(
    params: ToyParams,
    sk_seed: bytes,
    pub_seed: bytes,
    tree_index: int,
    leaf_index: int,
) -> bytes:
    return thash(
        params,
        b"fors-secret",
        sk_seed,
        pub_seed,
        u32(tree_index),
        u32(leaf_index),
    )


def _leaf(
    params: ToyParams,
    pub_seed: bytes,
    tree_index: int,
    leaf_index: int,
    secret: bytes,
) -> bytes:
    return thash(
        params,
        b"fors-leaf",
        pub_seed,
        u32(tree_index),
        u32(leaf_index),
        secret,
    )


def _leaves(
    params: ToyParams,
    sk_seed: bytes,
    pub_seed: bytes,
    tree_index: int,
) -> list[bytes]:
    return [
        _leaf(
            params,
            pub_seed,
            tree_index,
            leaf_index,
            _secret(params, sk_seed, pub_seed, tree_index, leaf_index),
        )
        for leaf_index in range(1 << params.fors_height)
    ]


def sign(
    params: ToyParams,
    digest: bytes,
    sk_seed: bytes,
    pub_seed: bytes,
) -> tuple[tuple[FORSProof, ...], bytes]:
    proofs: list[FORSProof] = []
    roots: list[bytes] = []
    for tree_index, leaf_index in enumerate(message_indices(params, digest)):
        leaves = _leaves(params, sk_seed, pub_seed, tree_index)
        proofs.append(
            FORSProof(
                secret=_secret(params, sk_seed, pub_seed, tree_index, leaf_index),
                auth_path=merkle.auth_path(params, leaves, leaf_index, _tree_tag(tree_index)),
            )
        )
        roots.append(merkle.root(params, leaves, _tree_tag(tree_index)))
    public_key = thash(params, b"fors-public-key", pub_seed, *roots)
    return tuple(proofs), public_key


def public_key_from_signature(
    params: ToyParams,
    proofs: Sequence[FORSProof],
    digest: bytes,
    pub_seed: bytes,
) -> bytes:
    if len(proofs) != params.fors_trees:
        raise ValueError("wrong number of FORS proofs")
    roots: list[bytes] = []
    for tree_index, (leaf_index, proof) in enumerate(
        zip(message_indices(params, digest), proofs, strict=True)
    ):
        if len(proof.auth_path) != params.fors_height:
            raise ValueError("wrong FORS authentication path length")
        leaf = _leaf(params, pub_seed, tree_index, leaf_index, proof.secret)
        roots.append(
            merkle.root_from_path(
                params,
                leaf,
                leaf_index,
                proof.auth_path,
                _tree_tag(tree_index),
            )
        )
    return thash(params, b"fors-public-key", pub_seed, *roots)
