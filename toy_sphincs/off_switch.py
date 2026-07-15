from __future__ import annotations

from dataclasses import dataclass, field

from .aggregation import AggregateLicense, verify_aggregate_license
from .params import DEFAULT_PARAMS, ToyParams
from .sphincs import ToyPublicKey, ToySecretKey, ToySignature, sign, verify
from .utils import thash, u32, u64


@dataclass(frozen=True)
class DirectLicense:
    allowance: int
    signature: ToySignature


def direct_license_message(chip_id: bytes, nonce: bytes, allowance: int) -> bytes:
    return (
        b"OFF-SWITCH-DIRECT-V1\x00"
        + u32(len(chip_id))
        + chip_id
        + u32(len(nonce))
        + nonce
        + u64(allowance)
    )


def issue_direct_license(
    secret_key: ToySecretKey,
    chip_id: bytes,
    nonce: bytes,
    allowance: int,
    *,
    optrand: bytes | None = None,
    params: ToyParams = DEFAULT_PARAMS,
) -> DirectLicense:
    if not 0 < allowance < 1 << 64:
        raise ValueError("allowance must fit in an unsigned 64-bit integer")
    if len(nonce) != params.n:
        raise ValueError("nonce must be n bytes")
    message = direct_license_message(chip_id, nonce, allowance)
    return DirectLicense(
        allowance=allowance,
        signature=sign(secret_key, message, optrand=optrand, params=params),
    )


@dataclass
class OffSwitch:
    public_key: ToyPublicKey
    chip_id: bytes
    nonce_seed: bytes = b"deterministic-demo-nonce-seed"
    params: ToyParams = DEFAULT_PARAMS
    allowance: int = field(default=0, init=False)
    nonce: bytes = field(init=False)
    _nonce_counter: int = field(default=0, init=False, repr=False)

    def __post_init__(self) -> None:
        if not self.chip_id:
            raise ValueError("chip_id must not be empty")
        self.nonce = self._derive_nonce()

    @property
    def enabled(self) -> bool:
        return self.allowance > 0

    def _derive_nonce(self) -> bytes:
        return thash(
            self.params,
            b"device-nonce",
            self.nonce_seed,
            self.chip_id,
            u64(self._nonce_counter),
        )

    def _rotate_nonce(self) -> None:
        self._nonce_counter += 1
        self.nonce = self._derive_nonce()

    def _grant(self, amount: int) -> None:
        self.allowance = min((1 << 64) - 1, self.allowance + amount)
        self._rotate_nonce()

    def accept_direct_license(self, license: DirectLicense) -> bool:
        if not 0 < license.allowance < 1 << 64:
            return False
        message = direct_license_message(self.chip_id, self.nonce, license.allowance)
        if not verify(self.public_key, message, license.signature, self.params):
            return False
        self._grant(license.allowance)
        return True

    def accept_aggregate_license(self, license: AggregateLicense) -> bool:
        if not verify_aggregate_license(
            self.public_key,
            self.chip_id,
            self.nonce,
            license,
            self.params,
        ):
            return False
        self._grant(license.allowance)
        return True

    def tick(self, cycles: int = 1) -> None:
        if cycles < 0:
            raise ValueError("cycles must be non-negative")
        self.allowance = max(0, self.allowance - cycles)

    def work(self, a: int, b: int) -> int:
        """Toy gated unsigned 8-bit adder, matching the RTL demonstration."""

        result = (a + b) & 0xFF
        return result if self.enabled else 0
