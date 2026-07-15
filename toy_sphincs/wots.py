from __future__ import annotations

from collections.abc import Sequence

from .params import ToyParams
from .utils import thash, u16, u32


def base_w(params: ToyParams, data: bytes, out_len: int) -> list[int]:
    digits: list[int] = []
    accumulator = 0
    bits = 0
    mask = params.w - 1
    for byte in data:
        accumulator = (accumulator << 8) | byte
        bits += 8
        while bits >= params.log_w and len(digits) < out_len:
            bits -= params.log_w
            digits.append((accumulator >> bits) & mask)
    if len(digits) != out_len:
        raise ValueError("input does not contain the requested base-w digits")
    return digits


def message_digits(params: ToyParams, message_digest: bytes) -> list[int]:
    if len(message_digest) != params.n:
        raise ValueError("WOTS+ message digest must be n bytes")
    digits = base_w(params, message_digest, params.wots_len1)
    checksum = sum(params.w - 1 - digit for digit in digits)
    checksum_digits = [0] * params.wots_len2
    for index in range(params.wots_len2 - 1, -1, -1):
        checksum_digits[index] = checksum % params.w
        checksum //= params.w
    return digits + checksum_digits


def secret_element(
    params: ToyParams,
    sk_seed: bytes,
    pub_seed: bytes,
    leaf_index: int,
    chain_index: int,
) -> bytes:
    return thash(
        params,
        b"wots-secret",
        sk_seed,
        pub_seed,
        u32(leaf_index),
        u16(chain_index),
    )


def chain(
    params: ToyParams,
    start_value: bytes,
    start: int,
    steps: int,
    pub_seed: bytes,
    leaf_index: int,
    chain_index: int,
) -> bytes:
    if len(start_value) != params.n:
        raise ValueError("WOTS+ chain value must be n bytes")
    if start < 0 or steps < 0 or start + steps > params.w - 1:
        raise ValueError("invalid WOTS+ chain range")
    value = start_value
    for step in range(start, start + steps):
        value = thash(
            params,
            b"wots-chain",
            pub_seed,
            u32(leaf_index),
            u16(chain_index),
            u16(step),
            value,
        )
    return value


def public_key(
    params: ToyParams,
    sk_seed: bytes,
    pub_seed: bytes,
    leaf_index: int,
) -> bytes:
    endpoints = []
    for chain_index in range(params.wots_len):
        secret = secret_element(params, sk_seed, pub_seed, leaf_index, chain_index)
        endpoints.append(
            chain(
                params,
                secret,
                0,
                params.w - 1,
                pub_seed,
                leaf_index,
                chain_index,
            )
        )
    return thash(params, b"wots-public-key", pub_seed, u32(leaf_index), *endpoints)


def sign(
    params: ToyParams,
    message_digest: bytes,
    sk_seed: bytes,
    pub_seed: bytes,
    leaf_index: int,
) -> tuple[bytes, ...]:
    signature: list[bytes] = []
    for chain_index, digit in enumerate(message_digits(params, message_digest)):
        secret = secret_element(params, sk_seed, pub_seed, leaf_index, chain_index)
        signature.append(
            chain(params, secret, 0, digit, pub_seed, leaf_index, chain_index)
        )
    return tuple(signature)


def public_key_from_signature(
    params: ToyParams,
    signature: Sequence[bytes],
    message_digest: bytes,
    pub_seed: bytes,
    leaf_index: int,
) -> bytes:
    if len(signature) != params.wots_len:
        raise ValueError("wrong number of WOTS+ signature elements")
    endpoints: list[bytes] = []
    for chain_index, (element, digit) in enumerate(
        zip(signature, message_digits(params, message_digest), strict=True)
    ):
        endpoints.append(
            chain(
                params,
                element,
                digit,
                params.w - 1 - digit,
                pub_seed,
                leaf_index,
                chain_index,
            )
        )
    return thash(params, b"wots-public-key", pub_seed, u32(leaf_index), *endpoints)
