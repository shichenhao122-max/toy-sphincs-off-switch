"""Benchmark real FIPS 205 SLH-DSA through liboqs-python.

This program deliberately stays separate from the educational Mini-SPHINCS+
implementation. It measures the real library API and converts signature sizes
into simple streaming-interface estimates for the Off-Switch architecture.
"""

from __future__ import annotations

import argparse
import json
import math
import os
import platform
import statistics
import sys
import time
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any, Callable


# Prefer the repository-local no-sudo build created by setup_no_sudo.sh. When
# it is absent, the wrapper can still try its normal automatic installation.
PROJECT_ROOT = Path(__file__).resolve().parents[1]
LOCAL_LIBOQS = PROJECT_ROOT / ".venv" / "liboqs"
if LOCAL_LIBOQS.is_dir():
    os.environ.setdefault("OQS_INSTALL_PATH", str(LOCAL_LIBOQS))

os.environ.setdefault("PYOQS_VERSION", "latest")

try:
    import oqs
except (ImportError, RuntimeError) as error:
    raise SystemExit(
        "Unable to import liboqs-python. Follow benchmarks/README.md to create "
        f"the isolated environment. Original error: {error}"
    ) from error


DEFAULT_ALGORITHMS = (
    "SLH_DSA_PURE_SHA2_128S",
    "SLH_DSA_PURE_SHA2_128F",
)


@dataclass(frozen=True)
class TimingSummary:
    mean_ms: float
    median_ms: float
    p95_ms: float
    minimum_ms: float
    maximum_ms: float
    samples: int


@dataclass(frozen=True)
class CorrectnessChecks:
    valid_signature_accepted: bool
    changed_message_rejected: bool
    changed_signature_rejected: bool
    wrong_public_key_rejected: bool
    repeated_signatures_differ: bool

    @property
    def all_passed(self) -> bool:
        return all(asdict(self).values())


def percentile(values: list[float], fraction: float) -> float:
    """Return a nearest-rank percentile for a non-empty sample."""

    if not values:
        raise ValueError("percentile requires at least one sample")
    ordered = sorted(values)
    rank = max(1, math.ceil(fraction * len(ordered)))
    return ordered[rank - 1]


def summarize(samples_ns: list[int]) -> TimingSummary:
    samples_ms = [sample / 1_000_000 for sample in samples_ns]
    return TimingSummary(
        mean_ms=statistics.fmean(samples_ms),
        median_ms=statistics.median(samples_ms),
        p95_ms=percentile(samples_ms, 0.95),
        minimum_ms=min(samples_ms),
        maximum_ms=max(samples_ms),
        samples=len(samples_ms),
    )


def measure(operation: Callable[[], Any], iterations: int) -> tuple[TimingSummary, Any]:
    samples: list[int] = []
    last_result: Any = None
    for _ in range(iterations):
        started = time.perf_counter_ns()
        last_result = operation()
        samples.append(time.perf_counter_ns() - started)
    return summarize(samples), last_result


def flip_first_bit(value: bytes) -> bytes:
    if not value:
        raise ValueError("cannot modify an empty byte string")
    return bytes([value[0] ^ 1]) + value[1:]


def stream_feedback(
    signature_bytes: int, bus_width_bits: int, clock_mhz: float
) -> dict[str, float | int]:
    bytes_per_word = bus_width_bits // 8
    words = math.ceil(signature_bytes / bytes_per_word)
    return {
        "bus_width_bits": bus_width_bits,
        "clock_mhz": clock_mhz,
        "stream_words": words,
        "input_cycles_at_one_word_per_cycle": words,
        "input_only_latency_us": words / clock_mhz,
    }


def benchmark_algorithm(
    algorithm: str,
    message: bytes,
    iterations: int,
    warmup: int,
    bus_width_bits: int,
    clock_mhz: float,
) -> dict[str, Any]:
    with oqs.Signature(algorithm) as signer, oqs.Signature(algorithm) as verifier:
        for _ in range(warmup):
            signer.generate_keypair()

        keygen_timing, public_key = measure(signer.generate_keypair, iterations)
        secret_key = signer.export_secret_key()

        for _ in range(warmup):
            signer.sign(message)

        sign_timing, signature = measure(lambda: signer.sign(message), iterations)

        for _ in range(warmup):
            verifier.verify(message, signature, public_key)

        verify_timing, verification_result = measure(
            lambda: verifier.verify(message, signature, public_key), iterations
        )

        second_signature = signer.sign(message)
        changed_message_rejected = not verifier.verify(
            message + b"!", signature, public_key
        )
        changed_signature_rejected = not verifier.verify(
            message, flip_first_bit(signature), public_key
        )

        with oqs.Signature(algorithm) as other_signer:
            wrong_public_key = other_signer.generate_keypair()
        wrong_public_key_rejected = not verifier.verify(
            message, signature, wrong_public_key
        )

        checks = CorrectnessChecks(
            valid_signature_accepted=bool(verification_result),
            changed_message_rejected=changed_message_rejected,
            changed_signature_rejected=changed_signature_rejected,
            wrong_public_key_rejected=wrong_public_key_rejected,
            repeated_signatures_differ=signature != second_signature,
        )

        details = dict(signer.details)
        actual_sizes = {
            "public_key_bytes": len(public_key),
            "secret_key_bytes": len(secret_key),
            "signature_bytes": len(signature),
        }
        advertised_sizes = {
            "public_key_bytes": details.get("length_public_key"),
            "secret_key_bytes": details.get("length_secret_key"),
            "signature_bytes": details.get("length_signature"),
        }
        size_matches_library_metadata = all(
            advertised_sizes[key] == actual_sizes[key] for key in actual_sizes
        )

        return {
            "algorithm": algorithm,
            "claimed_nist_level": details.get("claimed_nist_level"),
            "is_euf_cma": details.get("is_euf_cma"),
            "actual_sizes": actual_sizes,
            "advertised_sizes": advertised_sizes,
            "size_matches_library_metadata": size_matches_library_metadata,
            "timing": {
                "keygen": asdict(keygen_timing),
                "sign": asdict(sign_timing),
                "verify": asdict(verify_timing),
            },
            "correctness": {**asdict(checks), "all_passed": checks.all_passed},
            "stream_feedback": stream_feedback(
                len(signature), bus_width_bits, clock_mhz
            ),
        }


def print_timing(label: str, timing: dict[str, Any]) -> None:
    print(
        f"  {label:<7} median={timing['median_ms']:9.3f} ms  "
        f"mean={timing['mean_ms']:9.3f} ms  p95={timing['p95_ms']:9.3f} ms"
    )


def print_result(result: dict[str, Any]) -> None:
    sizes = result["actual_sizes"]
    timing = result["timing"]
    checks = result["correctness"]
    stream = result["stream_feedback"]

    print(f"\n=== {result['algorithm']} ===")
    print(
        "Sizes: "
        f"public key={sizes['public_key_bytes']} B, "
        f"secret key={sizes['secret_key_bytes']} B, "
        f"signature={sizes['signature_bytes']} B"
    )
    print_timing("keygen", timing["keygen"])
    print_timing("sign", timing["sign"])
    print_timing("verify", timing["verify"])
    print(
        "Correctness: "
        f"valid={checks['valid_signature_accepted']}, "
        f"message_tamper_rejected={checks['changed_message_rejected']}, "
        f"signature_tamper_rejected={checks['changed_signature_rejected']}, "
        f"wrong_key_rejected={checks['wrong_public_key_rejected']}, "
        f"randomized={checks['repeated_signatures_differ']}"
    )
    print(
        "Stream estimate: "
        f"{stream['stream_words']} x {stream['bus_width_bits']}-bit words, "
        f"{stream['input_only_latency_us']:.2f} us minimum at "
        f"{stream['clock_mhz']:.1f} MHz"
    )


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Benchmark real FIPS 205 SLH-DSA through liboqs-python."
    )
    parser.add_argument(
        "--algorithms",
        nargs="+",
        default=list(DEFAULT_ALGORITHMS),
        help="liboqs signature mechanism names",
    )
    parser.add_argument("--iterations", type=int, default=10)
    parser.add_argument("--warmup", type=int, default=1)
    parser.add_argument("--message-size", type=int, default=64)
    parser.add_argument("--bus-width-bits", type=int, default=32)
    parser.add_argument("--clock-mhz", type=float, default=100.0)
    parser.add_argument("--json", type=Path, help="optional JSON output path")
    return parser.parse_args()


def validate_args(args: argparse.Namespace) -> None:
    if args.iterations < 1:
        raise SystemExit("--iterations must be at least 1")
    if args.warmup < 0:
        raise SystemExit("--warmup must be non-negative")
    if args.message_size < 1:
        raise SystemExit("--message-size must be at least 1")
    if args.bus_width_bits < 8 or args.bus_width_bits % 8:
        raise SystemExit("--bus-width-bits must be a positive multiple of 8")
    if args.clock_mhz <= 0:
        raise SystemExit("--clock-mhz must be positive")


def main() -> int:
    args = parse_args()
    validate_args(args)

    enabled = set(oqs.get_enabled_sig_mechanisms())
    unavailable = [algorithm for algorithm in args.algorithms if algorithm not in enabled]
    if unavailable:
        print("Unavailable mechanisms: " + ", ".join(unavailable), file=sys.stderr)
        print(
            "Enabled SLH-DSA mechanisms: "
            + ", ".join(sorted(name for name in enabled if "SLH" in name)),
            file=sys.stderr,
        )
        return 2

    message = bytes(index % 251 for index in range(args.message_size))
    report = {
        "environment": {
            "python": sys.version.split()[0],
            "platform": platform.platform(),
            "liboqs_python": oqs.oqs_python_version(),
            "liboqs": oqs.oqs_version(),
        },
        "configuration": {
            "iterations": args.iterations,
            "warmup": args.warmup,
            "message_size": args.message_size,
            "bus_width_bits": args.bus_width_bits,
            "clock_mhz": args.clock_mhz,
        },
        "results": [],
    }

    print("Real SLH-DSA benchmark through liboqs-python")
    print(
        f"liboqs-python={report['environment']['liboqs_python']}, "
        f"liboqs={report['environment']['liboqs']}"
    )
    for algorithm in args.algorithms:
        result = benchmark_algorithm(
            algorithm,
            message,
            args.iterations,
            args.warmup,
            args.bus_width_bits,
            args.clock_mhz,
        )
        report["results"].append(result)
        print_result(result)

    if args.json:
        args.json.parent.mkdir(parents=True, exist_ok=True)
        args.json.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
        print(f"\nJSON report: {args.json}")

    return 0 if all(
        result["correctness"]["all_passed"]
        and result["size_matches_library_metadata"]
        for result in report["results"]
    ) else 1


if __name__ == "__main__":
    raise SystemExit(main())
