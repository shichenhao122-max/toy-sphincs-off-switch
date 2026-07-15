"""Educational, deliberately insecure SPHINCS+-inspired building blocks."""

from .params import DEFAULT_PARAMS, ToyParams
from .sphincs import (
    ToyPublicKey,
    ToySecretKey,
    ToySignature,
    keygen,
    sign,
    verify,
)

__all__ = [
    "DEFAULT_PARAMS",
    "ToyParams",
    "ToyPublicKey",
    "ToySecretKey",
    "ToySignature",
    "keygen",
    "sign",
    "verify",
]
