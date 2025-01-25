# C:\Accumulate_Stuff\accumulate-python-client\tests\test_models\test_signatures.py

import unittest
from accumulate.models.signatures import (
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
    LiteSigner,
    SignerManager,
    do_sha256,
)
from accumulate.utils.url import URL
from ecdsa import SigningKey, SECP256k1
from Crypto.PublicKey import RSA
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256
import hashlib
from eth_utils import keccak

class TestSignatures(unittest.TestCase):
    def test_signature_base_class(self):
        """Test the base Signature class."""
        # Explicitly include the 'acc://' prefix in the URL authority
        signature = Signature("BaseType", signer=URL(authority="acc://signer.acme"))
        self.assertEqual(str(signature.get_url()), "signer.acme")  # Adjusted comparison
        self.assertEqual(signature.get_version(), 1)
        self.assertIsNone(signature.get_signature())
        with self.assertRaises(NotImplementedError):
            signature.hash()
        with self.assertRaises(NotImplementedError):
            signature.verify(b"message")

    def test_ed25519_signature(self):
        """Test ED25519Signature functionality."""
        private_key = SigningKey.generate(curve=SECP256k1)
        public_key = private_key.get_verifying_key().to_string()
        message = b"test message"
        signature_bytes = private_key.sign(message)

        # Explicitly include the 'acc://' prefix in the URL authority
        signer = URL(authority="acc://ed25519.acme")
        signature = ED25519Signature(signer, public_key, signature_bytes)

        self.assertEqual(signature.hash(), do_sha256(public_key))
        self.assertEqual(str(signer), "ed25519.acme")  # Adjusted comparison
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

    def test_signer_manager(self):
        """Test SignerManager functionality."""
        manager = SignerManager()
        signer1 = LiteSigner(URL(authority="signer1.acme"), version=1)
        signer2 = LiteSigner(URL(authority="signer2.acme"), version=2)

        manager.add_signer(signer1)
        manager.add_signer(signer2)

        self.assertEqual(len(manager.signers), 2)
        self.assertEqual(manager.get_signer(URL(authority="signer1.acme")), signer1)
        self.assertEqual(manager.get_signer(URL(authority="signer2.acme")), signer2)

        manager.add_signer(LiteSigner(URL(authority="signer1.acme"), version=3))
        self.assertEqual(manager.get_signer(URL(authority="signer1.acme")).get_version(), 3)


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


if __name__ == "__main__":
    unittest.main()
