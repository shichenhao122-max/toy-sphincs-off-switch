from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass

from . import merkle
from .params import DEFAULT_PARAMS, ToyParams
from .sphincs import ToyPublicKey, ToySecretKey, ToySignature, sign, verify
from .utils import is_power_of_two, thash, u32, u64


@dataclass(frozen=True)
class AggregateLicense:
    leaf_index: int
    leaf_count: int
    allowance: int
    id_path: tuple[bytes, ...]
    nonce_path: tuple[bytes, ...]
    license_path: tuple[bytes, ...]
    signature: ToySignature


@dataclass(frozen=True)
class AggregateBatch:
    id_root: bytes
    nonce_root: bytes
    license_root: bytes
    licenses: tuple[AggregateLicense, ...]


def _id_leaf(params: ToyParams, index: int, chip_id: bytes) -> bytes:
    return thash(params, b"aggregate-id-leaf", u32(index), chip_id)


def _nonce_leaf(params: ToyParams, index: int, nonce: bytes) -> bytes:
    return thash(params, b"aggregate-nonce-leaf", u32(index), nonce)


def _license_leaf(
    params: ToyParams,
    index: int,
    chip_id: bytes,
    nonce_root: bytes,
) -> bytes:
    return thash(
        params,
        b"aggregate-license-leaf",
        u32(index),
        chip_id,
        nonce_root,
    )


def aggregate_message(
    id_root: bytes,
    license_root: bytes,
    leaf_count: int,
    allowance: int,
) -> bytes:
    return (
        b"OFF-SWITCH-AGGREGATE-V1\x00"
        + u32(leaf_count)
        + u64(allowance)
        + id_root
        + license_root
    )


def issue_aggregate_licenses(
    secret_key: ToySecretKey,
    devices: Sequence[tuple[bytes, bytes]],
    allowance: int,
    *,
    optrand: bytes | None = None,
    params: ToyParams = DEFAULT_PARAMS,
) -> AggregateBatch:
    """Sign one root for a power-of-two fleet of (chip_id, nonce) pairs."""

    if not is_power_of_two(len(devices)):
        raise ValueError("toy aggregation requires a power-of-two device count")
    if len({chip_id for chip_id, _ in devices}) != len(devices):
        raise ValueError("chip IDs must be unique")
    if not 0 < allowance < 1 << 64:
        raise ValueError("allowance must fit in an unsigned 64-bit integer")
    if any(len(nonce) != params.n for _, nonce in devices):
        raise ValueError("every nonce must be n bytes")

    id_leaves = [
        _id_leaf(params, index, chip_id)
        for index, (chip_id, _) in enumerate(devices)
    ]
    nonce_leaves = [
        _nonce_leaf(params, index, nonce)
        for index, (_, nonce) in enumerate(devices)
    ]
    id_root = merkle.root(params, id_leaves, b"aggregate-id")
    nonce_root = merkle.root(params, nonce_leaves, b"aggregate-nonce")
    license_leaves = [
        _license_leaf(params, index, chip_id, nonce_root)
        for index, (chip_id, _) in enumerate(devices)
    ]
    license_root = merkle.root(params, license_leaves, b"aggregate-license")
    message = aggregate_message(id_root, license_root, len(devices), allowance)
    signature = sign(
        secret_key,
        message,
        optrand=optrand,
        params=params,
    )
    licenses = tuple(
        AggregateLicense(
            leaf_index=index,
            leaf_count=len(devices),
            allowance=allowance,
            id_path=merkle.auth_path(params, id_leaves, index, b"aggregate-id"),
            nonce_path=merkle.auth_path(
                params,
                nonce_leaves,
                index,
                b"aggregate-nonce",
            ),
            license_path=merkle.auth_path(
                params,
                license_leaves,
                index,
                b"aggregate-license",
            ),
            signature=signature,
        )
        for index in range(len(devices))
    )
    return AggregateBatch(
        id_root=id_root,
        nonce_root=nonce_root,
        license_root=license_root,
        licenses=licenses,
    )


def verify_aggregate_license(
    public_key: ToyPublicKey,
    chip_id: bytes,
    nonce: bytes,
    license: AggregateLicense,
    params: ToyParams = DEFAULT_PARAMS,
) -> bool:
    if not is_power_of_two(license.leaf_count):
        return False
    if not 0 <= license.leaf_index < license.leaf_count:
        return False
    height = license.leaf_count.bit_length() - 1
    if not (
        len(license.id_path)
        == len(license.nonce_path)
        == len(license.license_path)
        == height
    ):
        return False
    if not 0 < license.allowance < 1 << 64 or len(nonce) != params.n:
        return False
    try:
        id_root = merkle.root_from_path(
            params,
            _id_leaf(params, license.leaf_index, chip_id),
            license.leaf_index,
            license.id_path,
            b"aggregate-id",
        )
        nonce_root = merkle.root_from_path(
            params,
            _nonce_leaf(params, license.leaf_index, nonce),
            license.leaf_index,
            license.nonce_path,
            b"aggregate-nonce",
        )
        license_root = merkle.root_from_path(
            params,
            _license_leaf(params, license.leaf_index, chip_id, nonce_root),
            license.leaf_index,
            license.license_path,
            b"aggregate-license",
        )
        message = aggregate_message(
            id_root,
            license_root,
            license.leaf_count,
            license.allowance,
        )
        return verify(public_key, message, license.signature, params)
    except (IndexError, TypeError, ValueError):
        return False
