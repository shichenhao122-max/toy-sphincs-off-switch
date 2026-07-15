from __future__ import annotations

from collections.abc import Sequence

from .params import ToyParams
from .utils import is_power_of_two, thash, u32


def build_levels(params: ToyParams, leaves: Sequence[bytes], tree_tag: bytes) -> list[list[bytes]]:
    if not is_power_of_two(len(leaves)):
        raise ValueError("Merkle tree needs a non-empty power-of-two leaf count")
    if any(len(leaf) != params.n for leaf in leaves):
        raise ValueError("every leaf must be exactly n bytes")

    levels = [list(leaves)]
    level_number = 0
    while len(levels[-1]) > 1:
        current = levels[-1]
        parent = [
            thash(
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


def root(params: ToyParams, leaves: Sequence[bytes], tree_tag: bytes) -> bytes:
    return build_levels(params, leaves, tree_tag)[-1][0]


def auth_path(params: ToyParams, leaves: Sequence[bytes], index: int, tree_tag: bytes) -> tuple[bytes, ...]:
    levels = build_levels(params, leaves, tree_tag)
    if not 0 <= index < len(leaves):
        raise IndexError("leaf index out of range")
    path: list[bytes] = []
    node_index = index
    for level in levels[:-1]:
        path.append(level[node_index ^ 1])
        node_index >>= 1
    return tuple(path)


def root_from_path(
    params: ToyParams,
    leaf: bytes,
    index: int,
    path: Sequence[bytes],
    tree_tag: bytes,
) -> bytes:
    if len(leaf) != params.n or any(len(node) != params.n for node in path):
        raise ValueError("leaf and authentication nodes must be n bytes")
    node = leaf
    node_index = index
    for level_number, sibling in enumerate(path):
        left, right = (sibling, node) if node_index & 1 else (node, sibling)
        node = thash(
            params,
            b"merkle-node:" + tree_tag,
            u32(level_number),
            left,
            right,
        )
        node_index >>= 1
    return node
