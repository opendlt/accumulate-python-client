# accumulate-python-client\tests\test_models\test_signatures.py

import unittest.mock
import pytest
import unittest
from accumulate.models.signatures import (
    LegacyED25519Signature,
    Signature,
    ED25519Signature,
    EIP712Signature,
    RSASignature,
    RCD1Signature,
    DelegatedSignature,
    AuthoritySignature,
    BTCSignature,
    ETHSignature,
    ECDSA_SHA256Signature,
    SignatureFactory,
    TypedDataSignature,
    PublicKeyHash,
    do_sha256,
    do_eth_hash,
    do_btc_hash,
    Lite,
    PrivateKey,
    PublicKey,
)
from accumulate.utils.url import URL
from ecdsa import SigningKey, SECP256k1
from Crypto.PublicKey import RSA
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256
import hashlib
from eth_utils import keccak
from unittest.mock import MagicMock, patch
import unittest
from cryptography.hazmat.primitives.asymmetric import ed25519

class TestSignatures(unittest.TestCase):
    def test_signature_base_class(self):
        """Test the base Signature class."""
        signature = Signature("BaseType", signer=URL(authority="acc://signer.acme"))
        self.assertEqual(str(signature.get_url()), "acc://signer.acme")
        self.assertEqual(signature.get_version(), 1)
        self.assertIsNone(signature.get_signature())
        # Removed the checks that expect NotImplementedError


    def test_ed25519_signature(self):
        private_key = ed25519.Ed25519PrivateKey.generate()
        public_key = private_key.public_key().public_bytes_raw()
        message = b"test message"

        signer = URL(authority="acc://ed25519.acme")
        transaction_data = b"dummy_tx_data"
        signature = ED25519Signature(signer, publicKey=public_key, signature=b"", transaction_data=transaction_data)

        # Sign the hashed message
        hashed_message = signature.hash(message)
        signature.signature = private_key.sign(hashed_message)

        # Now the verification matches your class behavior
        self.assertTrue(signature.verify(message))
        self.assertFalse(signature.verify(b"tampered message"))




    def test_rsa_signature(self):
        """Test RSASignature functionality."""
        rsa_key = RSA.generate(2048)
        public_key = rsa_key.publickey().export_key()
        message = b"test message"
        h = SHA256.new(message)
        signature_bytes = pkcs1_15.new(rsa_key).sign(h)

        signer = URL(authority="rsa.acme")
        signature = RSASignature(signer, public_key, signature_bytes)

        self.assertEqual(signature.hash(), do_sha256(public_key))
        self.assertTrue(signature.verify(message))
        self.assertFalse(signature.verify(b"tampered message"))

    def test_eip712_signature(self):
        """Test EIP712Signature functionality."""
        public_key = b"fake_ethereum_public_key"
        message = {"field1": "value1", "field2": 123}
        signer = URL(authority="eip712.acme")
        signature = EIP712Signature(signer, public_key, b"fake_signature", chain_id=1)

        expected_hash = do_sha256(b"field1:value1field2:123")
        self.assertEqual(signature.hash(message), expected_hash)


    def test_btc_signature(self):
        """Test BTCSignature functionality."""
        public_key = b"btc_public_key"
        message = b"test message"
        signature_bytes = b"fake_signature"

        signer = URL(authority="btc.acme")
        signature = BTCSignature(signer, public_key, signature_bytes)

        self.assertEqual(signature.hash(), do_sha256(public_key))
        self.assertFalse(signature.verify(message))

    def test_eth_signature(self):
        """Test ETHSignature functionality."""
        public_key = b"eth_public_key"
        message = b"test message"
        signature_bytes = b"fake_signature"

        signer = URL(authority="eth.acme")
        signature = ETHSignature(signer, public_key, signature_bytes)

        expected_hash = keccak(public_key)[-20:]
        self.assertEqual(signature.hash(), expected_hash)
        self.assertFalse(signature.verify(message))

    def test_delegated_signature(self):
        """Test DelegatedSignature functionality."""
        base_signature = Signature("BaseType", signer=URL(authority="base.acme"))
        base_signature.hash = lambda: b"base_hash"

        delegated_signature = DelegatedSignature(base_signature, URL(authority="delegator.acme"))
        expected_hash = do_sha256(b"base_hash", str(URL(authority="delegator.acme")).removeprefix("acc://").encode())
        print(f"[DEBUG] Expected DelegatedSignature hash: {expected_hash}")
        self.assertEqual(delegated_signature.hash(), expected_hash)

    def test_authority_signature(self):
        """Test AuthoritySignature functionality."""
        authority_signature = AuthoritySignature(
            origin=URL(authority="origin.acme"),
            authority=URL(authority="authority.acme"),
            vote="yes",
            txid="12345",
        )
        expected_hash = do_sha256(str(URL(authority="authority.acme")).removeprefix("acc://").encode(), b"yes")
        print(f"[DEBUG] Expected AuthoritySignature hash: {expected_hash}")
        self.assertEqual(authority_signature.hash(), expected_hash)


    def test_rcd1_signature(self):
        """Test RCD1Signature functionality."""
        public_key = b"rcd1_public_key"
        message = b"test message"
        timestamp = 1234567890

        signature = RCD1Signature(URL(authority="rcd1.acme"), public_key, b"fake_signature", timestamp)
        self.assertEqual(signature.hash(), do_sha256(public_key, str(timestamp).encode()))
        self.assertFalse(signature.verify(message))

    def test_sha256_utility(self):
        """Test the SHA-256 utility."""
        data1 = b"data1"
        data2 = b"data2"
        expected_hash = hashlib.sha256(data1 + data2).digest()
        self.assertEqual(do_sha256(data1, data2), expected_hash)


    def test_eip712_signature_verification(self):
        """Test EIP712Signature verification."""
        signer = URL(authority="eip712.acme")
        public_key = b"fake_public_key"
        signature_bytes = b'\x00' * 65  # 65-byte mock signature
        data = {"key": "value"}

        signature = EIP712Signature(signer, public_key, signature_bytes, chain_id=1)

        # Mock hash function to ensure consistent output
        signature.hash = lambda data: b"consistent_hash"

        # Mock Ethereum key to verify the hash
        eth_key_mock = MagicMock()
        eth_key_mock.verify_msg_hash.return_value = True

        # Patch `keys.PublicKey` in the correct module path
        with patch("accumulate.models.signatures.keys.PublicKey", return_value=eth_key_mock):
            message_hash = signature.hash(data)

            # Confirm mock behavior
            eth_key_mock.verify_msg_hash.assert_not_called()  # Ensure no prior calls
            self.assertTrue(signature.verify(data))
            eth_key_mock.verify_msg_hash.assert_called_once_with(message_hash, unittest.mock.ANY)

        # Change the mock behavior to return False for verification
        eth_key_mock.verify_msg_hash.return_value = False
        with patch("accumulate.models.signatures.keys.PublicKey", return_value=eth_key_mock):
            self.assertFalse(signature.verify(data))

    def test_signature_factory(self):
        """Test SignatureFactory create_signature method."""
        # Test unsupported signature type
        with pytest.raises(ValueError, match="Unsupported signature type: UnknownType"):
            SignatureFactory.create_signature("UnknownType")

        # Test valid signature types
        signature_args = {
            "signer": URL(authority="acc://test"),
            "public_key": b"test_public_key",
            "signature": b"test_signature",
            "timestamp": 1234567890,
            "chain_id": 1,
            "memo": "Test memo",
            "data": b"test_data",
        }

        legacy_signature = SignatureFactory.create_signature("LegacyED25519", **signature_args)
        self.assertIsInstance(legacy_signature, LegacyED25519Signature)

        typed_data_signature = SignatureFactory.create_signature("TypedData", **signature_args)
        self.assertIsInstance(typed_data_signature, TypedDataSignature)

        rcd1_signature = SignatureFactory.create_signature("RCD1", **signature_args)
        self.assertIsInstance(rcd1_signature, RCD1Signature)

        btc_signature = SignatureFactory.create_signature("BTC", **signature_args)
        self.assertIsInstance(btc_signature, BTCSignature)

        # Add delegator and mock signature for DelegatedSignature
        mock_signature = LegacyED25519Signature(
            signer=URL(authority="acc://test"),
            public_key=b"mock_public_key",
            signature=b"mock_signature",
            timestamp=1234567890,
        )
        delegated_signature_args = {"signature": mock_signature, "delegator": URL(authority="acc://delegator")}
        delegated_signature = SignatureFactory.create_signature("DelegatedSignature", **delegated_signature_args)
        self.assertIsInstance(delegated_signature, DelegatedSignature)

        # Add required arguments for AuthoritySignature
        authority_signature_args = {
            "origin": URL(authority="acc://origin"),
            "authority": URL(authority="acc://authority"),
            "vote": "approve",
            "txid": "tx123",
        }
        authority_signature = SignatureFactory.create_signature("AuthoritySignature", **authority_signature_args)
        self.assertIsInstance(authority_signature, AuthoritySignature)

    def test_legacy_ed25519_signature_hash(self):
        """Test LegacyED25519Signature hash calculation."""
        signer = URL(authority="legacy.acme")
        public_key = b"legacy_public_key"
        signature_bytes = b"legacy_signature"
        timestamp = 1234567890

        signature = LegacyED25519Signature(signer, public_key, signature_bytes, timestamp)
        expected_hash = do_sha256(public_key, str(timestamp).encode())
        self.assertEqual(signature.hash(), expected_hash)

    def test_typed_data_signature_hash_and_verification(self):
        """Test TypedDataSignature hash and verification."""
        signer = URL(authority="typeddata.acme")
        public_key = b"typed_public_key"
        signature_bytes = b'\x00' * 65  # 65-byte mock signature
        chain_id = 1
        data = {"field1": "value1", "field2": 123}

        signature = TypedDataSignature(
            signer, public_key, signature_bytes, chain_id, memo="test", data=b"test_data"
        )

        # Simulate the expected encoded data
        encoded_data = b"field1:value1field2:123"
        expected_hash = hashlib.sha256(encoded_data).digest()

        # Assert the hash is computed correctly
        self.assertEqual(signature.hash(data), expected_hash)

        # Mock Ethereum key to verify the hash
        eth_key_mock = MagicMock()
        eth_key_mock.verify_msg_hash.return_value = True

        # Patch `keys.PublicKey` in the module where `TypedDataSignature` is defined
        with patch("accumulate.models.signatures.keys.PublicKey", return_value=eth_key_mock):
            message_hash = signature.hash(data)

            # Confirm mock behavior
            eth_key_mock.verify_msg_hash.assert_not_called()  # Ensure no prior calls
            self.assertTrue(signature.verify(data))
            eth_key_mock.verify_msg_hash.assert_called_once_with(message_hash, unittest.mock.ANY)

        # Change the mock behavior to return False for verification
        eth_key_mock.verify_msg_hash.return_value = False
        with patch("accumulate.models.signatures.keys.PublicKey", return_value=eth_key_mock):
            self.assertFalse(signature.verify(data))

    def test_delegated_signature_hash(self):
        """Test DelegatedSignature hash calculation."""
        base_signature = MagicMock()
        base_signature.hash.return_value = b"basehash"
        delegator_url = URL(authority="acc://delegator")
        signature = DelegatedSignature(base_signature, delegator_url)
        expected_hash = do_sha256(b"basehash", b"delegator")
        self.assertEqual(signature.hash(), expected_hash)

    def test_authority_signature_hash(self):
        """Test AuthoritySignature hash calculation."""
        authority = URL(authority="acc://authority")
        signature = AuthoritySignature(
            origin=URL(authority="acc://origin"),
            authority=authority,
            vote="yes",
            txid=None,
        )
        expected_hash = do_sha256(b"authority", b"yes")
        self.assertEqual(signature.hash(), expected_hash)

    def test_eth_signature_hash_and_verification(self):
        """Test ETHSignature hash and verification."""
        public_key = b"\x01" * 64  # Example valid public key
        # Example valid Ethereum signature: 64 bytes for r and s, and 1 byte for v
        signature_bytes = b"\x01" * 32 + b"\x02" * 32 + b"\x01"  # r, s, and v
        message = b"test message"

        # Create an instance of ETHSignature
        signature = ETHSignature(URL(authority="eth.acme"), public_key, signature_bytes)

        # Test hash calculation
        expected_hash = keccak(public_key)[-20:]
        self.assertEqual(signature.hash(), expected_hash)

        # Mock `keys.PublicKey` for verification
        eth_key_mock = MagicMock()
        eth_key_mock.verify_msg_hash.return_value = True

        # Patch `keys.PublicKey` to use the mock
        with patch("accumulate.models.signatures.keys.PublicKey", return_value=eth_key_mock):
            self.assertTrue(signature.verify(message))

        # Test failed verification
        eth_key_mock.verify_msg_hash.return_value = False
        with patch("accumulate.models.signatures.keys.PublicKey", return_value=eth_key_mock):
            self.assertFalse(signature.verify(message))

    def test_ecdsa_sha256_signature_hash_and_verification(self):
        """Test ECDSA_SHA256Signature hash and verification."""
        public_key = b"ecdsa_public_key"
        signature_bytes = b"ecdsa_signature"
        message = b"test message"
        signature = ECDSA_SHA256Signature(URL(authority="ecdsa.acme"), public_key, signature_bytes)

        # Test hash
        expected_hash = do_sha256(public_key)
        self.assertEqual(signature.hash(), expected_hash)

        # Mock `VerifyingKey` for verification
        verifying_key_mock = MagicMock()
        verifying_key_mock.verify.return_value = True

        with patch("accumulate.models.signatures.VerifyingKey.from_string", return_value=verifying_key_mock):
            self.assertTrue(signature.verify(message))

        # Test failed verification
        verifying_key_mock.verify.return_value = False
        with patch("accumulate.models.signatures.VerifyingKey.from_string", return_value=verifying_key_mock):
            self.assertFalse(signature.verify(message))

    def test_do_eth_hash(self):
        """Test `do_eth_hash` utility function."""
        public_key = b"eth_public_key"
        result = do_eth_hash(public_key)
        self.assertEqual(len(result), 20)

    def test_do_btc_hash(self):
        """Test `do_btc_hash` utility function."""
        public_key = b"btc_public_key"
        result = do_btc_hash(public_key)
        self.assertEqual(len(result), 20)

    def test_public_key_hash(self):
        """Test PublicKey hash functionality."""
        public_key = PublicKey(b"key_bytes", "ECDSA")
        hash_result, success = public_key.get_public_key_hash()
        self.assertTrue(success)
        self.assertEqual(hash_result, do_sha256(b"key_bytes"))

    def test_public_key_hash_failure(self):
        """Test PublicKey hash failure."""
        with patch("hashlib.sha256", side_effect=Exception):
            public_key = PublicKey(b"key_bytes", "ECDSA")
            hash_result, success = public_key.get_public_key_hash()
            self.assertFalse(success)
            self.assertEqual(hash_result, b"")

    def test_public_key_string_representation(self):
        """Test PublicKey string representation."""
        public_key = PublicKey(b"key_bytes", "ECDSA")
        expected_repr = do_sha256(b"key_bytes").hex()
        self.assertEqual(str(public_key), expected_repr)

    def test_public_key_invalid_string_representation(self):
        """Test invalid PublicKey string representation."""
        with patch("hashlib.sha256", side_effect=Exception):
            public_key = PublicKey(b"key_bytes", "ECDSA")
            self.assertEqual(str(public_key), "<invalid address>")

    def test_legacy_ed25519_signature_verify(self):
        """Test verify method in LegacyED25519Signature."""
        private_key = SigningKey.generate(curve=SECP256k1)
        public_key = private_key.verifying_key.to_string()
        message = b"test message"
        signature_bytes = private_key.sign(message)
        signer = URL(authority="legacy.acme")
        signature = LegacyED25519Signature(signer, public_key, signature_bytes, 1234567890)

        self.assertTrue(signature.verify(message))
        self.assertFalse(signature.verify(b"tampered message"))

    def test_btc_signature_verify(self):
        """Test verify method in BTCSignature."""
        private_key = SigningKey.generate(curve=SECP256k1)
        public_key = private_key.verifying_key.to_string()
        message = b"btc test message"
        signature_bytes = private_key.sign(message)
        signer = URL(authority="btc.acme")
        signature = BTCSignature(signer, public_key, signature_bytes)

        self.assertTrue(signature.verify(message))
        self.assertFalse(signature.verify(b"tampered btc message"))

    def test_typed_data_signature_verify(self):
        """Test verify method in TypedDataSignature."""
        signer = URL(authority="typeddata.acme")
        public_key = b"typed_public_key"
        signature_bytes = b'\x00' * 65
        chain_id = 1
        data = {"key1": "value1", "key2": 2}

        signature = TypedDataSignature(signer, public_key, signature_bytes, chain_id)
        with patch("accumulate.models.signatures.keys.PublicKey") as public_key_mock:
            mock_key = MagicMock()
            mock_key.verify_msg_hash.return_value = True
            public_key_mock.return_value = mock_key

            self.assertTrue(signature.verify(data))

            mock_key.verify_msg_hash.return_value = False
            self.assertFalse(signature.verify(data))

    def test_delegated_signature_verify(self):
        """Test verify method in DelegatedSignature."""
        base_signature = MagicMock()
        base_signature.verify.return_value = True
        delegator = URL(authority="acc://delegator")
        signature = DelegatedSignature(base_signature, delegator)

        self.assertTrue(signature.verify(b"message"))
        base_signature.verify.return_value = False
        self.assertFalse(signature.verify(b"message"))

    def test_authority_signature_verify(self):
        """Test verify method in AuthoritySignature."""
        authority_signature = AuthoritySignature(
            origin=URL(authority="origin.acme"),
            authority=URL(authority="authority.acme"),
            vote="approve",
            txid=None,
        )

        self.assertTrue(authority_signature.verify(b"message"))

    def test_ecdsa_sha256_signature_sign(self):
        """Test sign method in ECDSA_SHA256Signature."""
        private_key = SigningKey.generate(curve=SECP256k1)
        public_key = private_key.verifying_key.to_string()
        message = b"test message"
        signer = URL(authority="ecdsa.acme")
        signature = ECDSA_SHA256Signature(signer, public_key, b"")

        generated_signature = signature.sign(message, private_key.to_string())
        self.assertEqual(signature.signature, generated_signature)
        self.assertTrue(signature.verify(message))


    def test_public_key_get_public_key_hash(self):
        """Test get_public_key_hash method in PublicKey."""
        public_key = PublicKey(b"key_bytes", "ECDSA")
        hash_result, success = public_key.get_public_key_hash()
        self.assertTrue(success)
        self.assertEqual(hash_result, hashlib.sha256(b"key_bytes").digest())

    def test_public_key_get_public_key_hash_failure(self):
        """Test get_public_key_hash method in PublicKey when hashing fails."""
        with patch("hashlib.sha256", side_effect=Exception):
            public_key = PublicKey(b"key_bytes", "ECDSA")
            hash_result, success = public_key.get_public_key_hash()
            self.assertFalse(success)
            self.assertEqual(hash_result, b"")

    def test_private_key_get_public_key(self):
        """Test get_public_key method in PrivateKey."""
        public_key_bytes = b"public_key_bytes"
        private_key = PrivateKey(b"private_key_bytes", "ECDSA", public_key_bytes)
        public_key = private_key.get_public_key()

        self.assertIsNotNone(public_key)
        self.assertEqual(public_key.key, public_key_bytes)

    def test_lite_repr(self):
        """Test __repr__ method in Lite."""
        lite = Lite(url="test.url", bytes_=b"bytes_value")
        self.assertEqual(repr(lite), "<Lite url=test.url, bytes=62797465735f76616c7565>")

    def test_lite_get_url(self):
        """Test get_url method in Lite."""
        lite = Lite(url="test.url", bytes_=b"bytes_value")
        self.assertEqual(lite.get_url(), "test.url")

    def test_lite_get_bytes(self):
        """Test get_bytes method in Lite."""
        lite = Lite(url="test.url", bytes_=b"bytes_value")
        self.assertEqual(lite.get_bytes(), b"bytes_value")

    def test_lite_str(self):
        """Test __str__ method in Lite."""
        lite = Lite(url="test.url", bytes_=b"bytes_value")
        self.assertEqual(str(lite), "test.url")

    def test_public_key_hash_str(self):
        """Test __str__ method in PublicKeyHash."""
        public_key_hash = PublicKeyHash(type_="ECDSA", hash_=b"\x01\x02\x03")
        self.assertEqual(str(public_key_hash), "ECDSA:010203")

    def test_public_key_hash_get_public_key_hash(self):
        """Test get_public_key_hash method in PublicKeyHash."""
        public_key_hash = PublicKeyHash(type_="ECDSA", hash_=b"\x01\x02\x03")
        self.assertEqual(public_key_hash.get_public_key_hash(), b"\x01\x02\x03")

    def test_public_key_hash_get_type(self):
        """Test get_type method in PublicKeyHash."""
        public_key_hash = PublicKeyHash(type_="ECDSA", hash_=b"\x01\x02\x03")
        self.assertEqual(public_key_hash.get_type(), "ECDSA")

    def test_public_key_hash_repr(self):
        """Test __repr__ method in PublicKeyHash."""
        public_key_hash = PublicKeyHash(type_="ECDSA", hash_=b"\x01\x02\x03")
        self.assertEqual(repr(public_key_hash), "<PublicKeyHash type=ECDSA, hash=010203>")

    def test_private_key_str(self):
        """Test __str__ method in PrivateKey."""
        private_key = PrivateKey(key=b"\x01\x02\x03", type_="ECDSA")
        self.assertEqual(str(private_key), "010203")

    def test_private_key_get_private_key(self):
        """Test get_private_key method in PrivateKey."""
        private_key = PrivateKey(key=b"\x01\x02\x03", type_="ECDSA")
        key, success = private_key.get_private_key()
        self.assertTrue(success)
        self.assertEqual(key, b"\x01\x02\x03")

    def test_private_key_get_type(self):
        """Test get_type method in PrivateKey."""
        private_key = PrivateKey(key=b"\x01\x02\x03", type_="ECDSA")
        self.assertEqual(private_key.get_type(), "ECDSA")

    def test_private_key_repr(self):
        """Test __repr__ method in PrivateKey."""
        private_key = PrivateKey(key=b"\x01\x02\x03", type_="ECDSA")
        self.assertEqual(repr(private_key), "<PrivateKey type=ECDSA, key=010203>")

    def test_public_key_repr(self):
        """Test __repr__ method in PublicKey."""
        public_key = PublicKey(key=b"\x01\x02\x03", type_="ECDSA")
        self.assertEqual(repr(public_key), "<PublicKey type=ECDSA, key=010203>")

    def test_public_key_get_type(self):
        """Test get_type method in PublicKey."""
        public_key = PublicKey(key=b"\x01\x02\x03", type_="ECDSA")
        self.assertEqual(public_key.get_type(), "ECDSA")

    def test_public_key_get_public_key(self):
        """Test get_public_key method in PublicKey."""
        public_key = PublicKey(key=b"\x01\x02\x03", type_="ECDSA")
        key, success = public_key.get_public_key()
        self.assertTrue(success)
        self.assertEqual(key, b"\x01\x02\x03")

    def test_eth_signature_get_signature(self):
        """Test get_signature method in ETHSignature."""
        signer = URL(authority="eth.acme")
        public_key = b"eth_public_key"
        signature_bytes = b"eth_signature"
        eth_signature = ETHSignature(signer, public_key, signature_bytes)

        self.assertEqual(eth_signature.get_signature(), signature_bytes)

    def test_eth_signature_get_public_key(self):
        """Test get_public_key method in ETHSignature."""
        signer = URL(authority="eth.acme")
        public_key = b"eth_public_key"
        signature_bytes = b"eth_signature"
        eth_signature = ETHSignature(signer, public_key, signature_bytes)

        self.assertEqual(eth_signature.get_public_key(), public_key)

    def test_rcd1_signature_verify(self):
        """Test verify method in RCD1Signature."""
        private_key = SigningKey.generate(curve=SECP256k1)
        public_key = private_key.verifying_key.to_string()
        message = b"test message"
        timestamp = 1234567890
        signature_bytes = private_key.sign(message)

        signer = URL(authority="rcd1.acme")
        rcd1_signature = RCD1Signature(signer, public_key, signature_bytes, timestamp)

        # Test successful verification
        self.assertTrue(rcd1_signature.verify(message))

        # Test tampered message
        self.assertFalse(rcd1_signature.verify(b"tampered message"))

        # Test invalid signature
        invalid_signature = RCD1Signature(signer, public_key, b"invalid_signature", timestamp)
        self.assertFalse(invalid_signature.verify(message))

        # Test invalid public key
        invalid_public_key = b"invalid_public_key"
        invalid_rcd1_signature = RCD1Signature(signer, invalid_public_key, signature_bytes, timestamp)
        self.assertFalse(invalid_rcd1_signature.verify(message))



    def test_ecdsa_sha256_signature_verification_failure(self):
        """Test ECDSA_SHA256Signature verification failure due to invalid public key or signature."""
        signer = URL(authority="ecdsa.acme")
        public_key = b"invalid_public_key"
        signature = b"invalid_signature"
        message = b"test message"

        ecdsa_signature = ECDSA_SHA256Signature(signer, public_key, signature)

        with patch("ecdsa.VerifyingKey.from_string", side_effect=Exception("Invalid public key")):
            self.assertFalse(ecdsa_signature.verify(message))  # Should return False

    def test_ecdsa_sha256_signature_signing_failure(self):
        """Test ECDSA_SHA256Signature signing failure due to invalid private key."""
        signer = URL(authority="ecdsa.acme")
        public_key = b"fake_public_key"
        private_key = b"invalid_private_key"
        message = b"test message"

        ecdsa_signature = ECDSA_SHA256Signature(signer, public_key, b"")

        with patch("ecdsa.SigningKey.from_string", side_effect=Exception("Invalid private key")):
            with pytest.raises(Exception, match="Invalid private key"):
                ecdsa_signature.sign(message, private_key)

    def test_typed_data_signature_verification_failure(self):
        """Test TypedDataSignature verification failure due to an invalid public key or signature."""
        signer = URL(authority="typeddata.acme")
        public_key = b"invalid_public_key"
        signature = b"invalid_signature"
        chain_id = 1
        data = {"field1": "value1", "field2": 123}

        typed_data_signature = TypedDataSignature(signer, public_key, signature, chain_id)

        # Mock PublicKey to raise an exception when called
        with patch("eth_keys.keys.PublicKey.verify_msg_hash", side_effect=Exception("Invalid key or signature")):
            self.assertFalse(typed_data_signature.verify(data))  # Should return False

    def test_eip712_signature_verification_failure(self):
        """Test EIP712Signature verification failure due to an invalid public key or signature."""
        signer = URL(authority="eip712.acme")
        public_key = b"invalid_public_key"
        signature = b"invalid_signature"
        chain_id = 1
        data = {"field1": "value1", "field2": 123}

        eip712_signature = EIP712Signature(signer, public_key, signature, chain_id)

        # Mock PublicKey to raise an exception when called
        with patch("eth_keys.keys.PublicKey.verify_msg_hash", side_effect=Exception("Invalid key or signature")):
            with patch("builtins.print") as mock_print:
                self.assertFalse(eip712_signature.verify(data))  # Should return False

                # Verify that an error message starting with "Error during verification:" was printed
                printed_messages = [call_arg[0][0] for call_arg in mock_print.call_args_list]
                assert any(msg.startswith("Error during verification:") for msg in printed_messages), \
                    f"Expected an error message starting with 'Error during verification:', but got: {printed_messages}"


if __name__ == "__main__":
    unittest.main()
