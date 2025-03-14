# accumulate-python-client\tests\test_models\test_address.py

import unittest
import hashlib
from accumulate.models.address import (
    Address,
    Unknown,
    PublicKeyHashAddress,
    PublicKey,
    PrivateKey,
    Lite,
    format_address,
    hash_public_key,
)

class TestAddress(unittest.TestCase):

    def test_unknown_address(self):
        value = b"\x00\x01\x02\x03"
        address = Unknown(value)
        self.assertEqual(address.get_type(), "Unknown")
        self.assertEqual(address.get_public_key_hash(), (None, False))
        self.assertEqual(address.get_public_key(), (None, False))
        self.assertEqual(address.get_private_key(), (None, False))
        self.assertEqual(str(address), value.hex())

        # Test with base58 encoding
        address = Unknown(value, encoding="base58")
        self.assertEqual(str(address), "1Ldp")

    def test_public_key_hash_address(self):
        signature_type = "ED25519"
        hash_value = hashlib.sha256(b"test").digest()
        address = PublicKeyHashAddress(signature_type, hash_value)

        self.assertEqual(address.get_type(), signature_type)
        self.assertEqual(address.get_public_key_hash(), (hash_value, True))
        self.assertEqual(address.get_public_key(), (None, False))
        self.assertEqual(address.get_private_key(), (None, False))
        self.assertEqual(str(address), format_address(signature_type, hash_value))

    def test_public_key_address(self):
        signature_type = "ED25519"
        public_key = b"\x01" * 32
        address = PublicKey(signature_type, public_key)

        self.assertEqual(address.get_type(), signature_type)
        self.assertEqual(address.get_public_key(), (public_key, True))

        hash_value, valid = address.get_public_key_hash()
        self.assertTrue(valid)
        self.assertIsNotNone(hash_value)
        self.assertEqual(hash_value, hashlib.sha256(public_key).digest())
        self.assertEqual(address.get_private_key(), (None, False))
        self.assertEqual(str(address), format_address(signature_type, hash_value))

    def test_private_key_address(self):
        signature_type = "ED25519"
        public_key = b"\x01" * 32
        private_key = b"\x02" * 32
        address = PrivateKey(signature_type, public_key, private_key)

        self.assertEqual(address.get_type(), signature_type)
        self.assertEqual(address.get_public_key(), (public_key, True))
        self.assertEqual(address.get_private_key(), (private_key, True))
        self.assertEqual(str(address), private_key.hex())

    def test_lite_address(self):
        url = "https://example.com"
        address_bytes = b"\x03" * 20
        address = Lite(url, address_bytes)

        self.assertEqual(address.get_type(), "Unknown")
        self.assertEqual(address.get_public_key_hash(), (None, False))
        self.assertEqual(address.get_public_key(), (None, False))
        self.assertEqual(address.get_private_key(), (None, False))
        self.assertEqual(str(address), url)

    def test_format_address(self):
        hash_value = b"\x01\x02\x03\x04"
        self.assertEqual(format_address("ED25519", hash_value), f"AC1-{hash_value.hex()}")
        self.assertEqual(format_address("RCD1", hash_value), f"FA-{hash_value.hex()}")
        self.assertEqual(format_address("BTC", hash_value), f"BTC-{hash_value.hex()}")
        self.assertEqual(format_address("ETH", hash_value), f"ETH-{hash_value.hex()}")
        self.assertEqual(format_address("EcdsaSha256", hash_value), f"AC2-{hash_value.hex()}")
        self.assertEqual(format_address("RsaSha256", hash_value), f"AC3-{hash_value.hex()}")
        self.assertEqual(format_address("UnknownType", hash_value), f"MH-{hash_value.hex()}")

    def test_hash_public_key(self):
        public_key = b"\x01" * 32
        hash_value, valid = hash_public_key(public_key, "ED25519")
        self.assertTrue(valid)
        self.assertEqual(hash_value, hashlib.sha256(public_key).digest())

        hash_value, valid = hash_public_key(public_key, "BTC")
        self.assertTrue(valid)
        self.assertEqual(hash_value, hashlib.sha256(public_key).digest())

        hash_value, valid = hash_public_key(public_key, "UnsupportedType")
        self.assertFalse(valid)
        self.assertIsNone(hash_value)

    def test_address_abstract_methods(self):
        address = Address()
        with self.assertRaises(NotImplementedError):
            address.get_type()
        with self.assertRaises(NotImplementedError):
            address.get_public_key_hash()
        with self.assertRaises(NotImplementedError):
            address.get_public_key()
        with self.assertRaises(NotImplementedError):
            address.get_private_key()
        with self.assertRaises(NotImplementedError):
            str(address)


if __name__ == "__main__":
    unittest.main()
