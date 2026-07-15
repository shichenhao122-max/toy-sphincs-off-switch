from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class ToyParams:
    """Tiny parameters chosen for visibility and fast tests, not security."""

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
            raise ValueError("this toy requires log2(w) to divide 8")
        if self.required_digest_bits > self.n * 8:
            raise ValueError("digest is too short for FORS and XMSS indices")

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
        xmss_auth = self.xmss_height * self.n
        return randomizer + fors + wots + xmss_auth


DEFAULT_PARAMS = ToyParams()
