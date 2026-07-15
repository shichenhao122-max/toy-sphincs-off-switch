from __future__ import annotations

import hashlib
from collections.abc import Iterable, Sequence

from .params import ToyParams


def u16(value: int) -> bytes:
    return value.to_bytes(2, "big")


def u32(value: int) -> bytes:
    return value.to_bytes(4, "big")


def u64(value: int) -> bytes:
    return value.to_bytes(8, "big")


def thash(params: ToyParams, domain: bytes, *parts: bytes) -> bytes:
    """Domain-separated SHA-256 truncated to n bytes.

    Length prefixes make concatenations unambiguous. Real SLH-DSA uses a
    standardized address structure and exact hash-function instantiations;
    this compact encoding is only an educational analogue.
    """

    if len(domain) > 255:
        raise ValueError("domain label is too long")
    h = hashlib.sha256()
    h.update(b"TOY-SPHINCS+\x00")
    h.update(bytes([len(domain)]))
    h.update(domain)
    for part in parts:
        h.update(u32(len(part)))
        h.update(part)
    return h.digest()[: params.n]


def extract_msb_fields(data: bytes, widths: Sequence[int]) -> list[int]:
    total = sum(widths)
    if total > len(data) * 8:
        raise ValueError("not enough digest bits")
    value = int.from_bytes(data, "big") >> (len(data) * 8 - total)
    fields: list[int] = []
    remaining = total
    for width in widths:
        remaining -= width
        fields.append((value >> remaining) & ((1 << width) - 1))
    return fields


def chunks(data: bytes, size: int) -> Iterable[bytes]:
    if size <= 0:
        raise ValueError("chunk size must be positive")
    for offset in range(0, len(data), size):
        yield data[offset : offset + size]


def is_power_of_two(value: int) -> bool:
    return value > 0 and not value & (value - 1)
