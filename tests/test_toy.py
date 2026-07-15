from __future__ import annotations

import unittest

from toy_sphincs.aggregation import (
    issue_aggregate_licenses,
    verify_aggregate_license,
)
from toy_sphincs.off_switch import OffSwitch, issue_direct_license
from toy_sphincs.params import DEFAULT_PARAMS
from toy_sphincs.sphincs import ToySignature, keygen, sign, verify


class ToySphincsTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.params = DEFAULT_PARAMS
        cls.secret_key, cls.public_key = keygen(
            b"unit-test master seed",
            cls.params,
        )

    def test_sign_verify_serialize_and_tamper(self) -> None:
        message = b"hello hash trees"
        signature = sign(
            self.secret_key,
            message,
            optrand=b"TEST",
            params=self.params,
        )
        self.assertTrue(verify(self.public_key, message, signature, self.params))
        encoded = signature.to_bytes(self.params)
        self.assertEqual(len(encoded), self.params.signature_bytes)
        decoded = ToySignature.from_bytes(encoded, self.params)
        self.assertEqual(signature, decoded)
        self.assertTrue(verify(self.public_key, message, decoded, self.params))

        tampered = bytearray(encoded)
        tampered[len(tampered) // 2] ^= 0x01
        bad_signature = ToySignature.from_bytes(bytes(tampered), self.params)
        self.assertFalse(verify(self.public_key, message, bad_signature, self.params))
        self.assertFalse(verify(self.public_key, message + b"!", signature, self.params))

    def test_signing_is_stateless(self) -> None:
        before = self.secret_key
        first = sign(
            self.secret_key,
            b"same message",
            optrand=b"ONE!",
            params=self.params,
        )
        second = sign(
            self.secret_key,
            b"same message",
            optrand=b"TWO!",
            params=self.params,
        )
        self.assertEqual(before, self.secret_key)
        self.assertNotEqual(first.randomizer, second.randomizer)
        self.assertTrue(verify(self.public_key, b"same message", first, self.params))
        self.assertTrue(verify(self.public_key, b"same message", second, self.params))

    def test_streaming_chunks_round_trip(self) -> None:
        signature = sign(
            self.secret_key,
            b"stream me",
            optrand=b"STRM",
            params=self.params,
        )
        encoded = signature.to_bytes(self.params)
        streamed = b"".join(signature.iter_chunks(7, self.params))
        self.assertEqual(encoded, streamed)

    def test_direct_off_switch_license_replay_and_chip_binding(self) -> None:
        device = OffSwitch(self.public_key, b"chip-A", params=self.params)
        self.assertFalse(device.enabled)
        self.assertEqual(device.work(50, 30), 0)
        original_nonce = device.nonce
        license = issue_direct_license(
            self.secret_key,
            device.chip_id,
            original_nonce,
            allowance=5,
            optrand=b"DIR!",
            params=self.params,
        )
        self.assertTrue(device.accept_direct_license(license))
        self.assertEqual(device.allowance, 5)
        self.assertEqual(device.work(50, 30), 80)
        self.assertNotEqual(device.nonce, original_nonce)
        self.assertFalse(device.accept_direct_license(license))

        other_device = OffSwitch(self.public_key, b"chip-B", params=self.params)
        self.assertFalse(other_device.accept_direct_license(license))
        device.tick(5)
        self.assertFalse(device.enabled)
        self.assertEqual(device.work(50, 30), 0)

    def test_aggregate_license_binds_id_nonce_and_position(self) -> None:
        fleet = [
            OffSwitch(self.public_key, f"chip-{index}".encode(), params=self.params)
            for index in range(4)
        ]
        batch = issue_aggregate_licenses(
            self.secret_key,
            [(device.chip_id, device.nonce) for device in fleet],
            allowance=9,
            optrand=b"AGG!",
            params=self.params,
        )
        self.assertTrue(
            all(
                license.signature is batch.licenses[0].signature
                for license in batch.licenses
            )
        )

        first = fleet[0]
        first_license = batch.licenses[0]
        wrong_nonce = bytes([first.nonce[0] ^ 1]) + first.nonce[1:]
        self.assertFalse(
            verify_aggregate_license(
                self.public_key,
                first.chip_id,
                wrong_nonce,
                first_license,
                self.params,
            )
        )
        self.assertFalse(
            verify_aggregate_license(
                self.public_key,
                b"wrong-chip",
                first.nonce,
                first_license,
                self.params,
            )
        )
        self.assertFalse(
            verify_aggregate_license(
                self.public_key,
                first.chip_id,
                first.nonce,
                batch.licenses[1],
                self.params,
            )
        )

        accepted = [
            device.accept_aggregate_license(license)
            for device, license in zip(fleet, batch.licenses, strict=True)
        ]
        self.assertEqual(accepted, [True, True, True, True])
        self.assertEqual([device.allowance for device in fleet], [9, 9, 9, 9])
        self.assertFalse(fleet[0].accept_aggregate_license(batch.licenses[0]))


if __name__ == "__main__":
    unittest.main()
