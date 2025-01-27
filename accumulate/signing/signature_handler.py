# accumulate-python-client\accumulate\signing\signature_handler.py

import hashlib
from typing import Optional, Union
from cryptography.hazmat.primitives.asymmetric import ed25519, rsa, ec
from cryptography.hazmat.primitives.hashes import SHA256, Hash
from cryptography.hazmat.primitives.asymmetric.utils import Prehashed
from cryptography.hazmat.primitives.asymmetric import padding
from eth_keys import keys as eth_keys
from eth_keys.exceptions import BadSignature
from cryptography.hazmat.backends import default_backend
from accumulate.models.signature_types import SignatureType
from cryptography.hazmat.primitives import serialization
from base58 import b58encode
from eth_utils import keccak
from accumulate.utils.url import URL
from accumulate.models.signatures import Signature
from eth_utils.exceptions import ValidationError
from accumulate.utils.hash_functions import (
    btc_address,
    eth_address,
    public_key_hash,
)
from cryptography.hazmat.primitives.asymmetric.padding import PKCS1v15

class SignatureHandler:
    """Handles signing and verification operations for various signature types."""

    # ========== BTC Address Utility ==========
    @staticmethod
    def btc_address(public_key: bytes) -> str:
        """Generate a BTC address from a public key."""
        return btc_address(public_key) #

    # ========== ETH Address Utility ==========
    @staticmethod
    def eth_address(public_key: bytes) -> str:
        """Generate an ETH address from a public key."""
        return eth_address(public_key) #

    # ========== Merkle Hash Validation ==========
    @staticmethod
    def verify_merkle_hash(metadata_hash: bytes, txn_hash: bytes, signature: Signature) -> bool:
        """Verify if a Merkle hash is valid."""
        try: #
            calculated_merkle_hash = hashlib.sha256(metadata_hash + txn_hash).digest() #
            return calculated_merkle_hash == signature.transaction_hash #
        except Exception: #
            return False #

    # ========== Authority Signature ==========

    @staticmethod
    def create_authority_signature(origin: URL, authority: URL, vote: Optional[str], txid: Optional[str]) -> bytes:
        """Create a signature for an authority."""
        data = str(origin).encode() + str(authority).encode()  # Use str() instead of to_string
        if vote:
            data += vote.encode()
        if txid:
            data += txid.encode()
        return hashlib.sha256(data).digest()

    @staticmethod
    def sign_authority_signature(origin: URL, authority: URL, vote: Optional[str], txid: Optional[str]) -> bytes:
        """Create a signature for an authority."""
        data = str(origin).encode() + str(authority).encode()  # Use str() instead of to_string
        if vote:
            data += vote.encode()
        if txid:
            data += txid.encode()
        return hashlib.sha256(data).digest()

    @staticmethod
    def verify_authority_signature(authority_signature: bytes, origin: URL, authority: URL, vote: Optional[str], txid: Optional[str]) -> bool:
        """Verify an authority signature."""
        expected_hash = SignatureHandler.sign_authority_signature(origin, authority, vote, txid)
        return expected_hash == authority_signature

    # ========== LegacyED25519 ==========
    @staticmethod
    def sign_legacy_ed25519(private_key: bytes, message: bytes) -> bytes:
        private_key_obj = ed25519.Ed25519PrivateKey.from_private_bytes(private_key)
        return private_key_obj.sign(message)

    @staticmethod
    def verify_legacy_ed25519(public_key: bytes, message: bytes, signature: bytes) -> bool:
        try:
            public_key_obj = ed25519.Ed25519PublicKey.from_public_bytes(public_key)
            public_key_obj.verify(signature, message)
            return True
        except Exception:
            return False

    # ========== ED25519 ==========
    @staticmethod
    def sign_ed25519(private_key: bytes, message: bytes) -> bytes:
        return SignatureHandler.sign_legacy_ed25519(private_key, message)

    @staticmethod
    def verify_ed25519(public_key: bytes, message: bytes, signature: bytes) -> bool:
        return SignatureHandler.verify_legacy_ed25519(public_key, message, signature)

    # ========== BTC (ECDSA SECP256k1) ==========
    @staticmethod
    def sign_btc(private_key: bytes, message: bytes) -> bytes:
        private_key_obj = ec.derive_private_key(int.from_bytes(private_key, "big"), ec.SECP256K1()) #
        return private_key_obj.sign(message, ec.ECDSA(SHA256())) #

    @staticmethod
    def verify_btc(public_key: bytes, message: bytes, signature: bytes) -> bool:
        try: #
            public_key_obj = ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256K1(), public_key) #
            public_key_obj.verify(signature, message, ec.ECDSA(SHA256())) #
            return True #
        except Exception: #
            return False #

    # ========== ETH (EIP-712) ==========
    @staticmethod
    def sign_eth(private_key: bytes, message_hash: bytes) -> bytes:
        try:
            eth_key = eth_keys.PrivateKey(private_key)
            eth_signature = eth_key.sign_msg_hash(message_hash)
            return eth_signature.to_bytes()
        except Exception: #
            raise ValueError("Failed to sign Ethereum message") #

    @staticmethod
    def verify_eth(public_key: bytes, message_hash: bytes, signature: bytes) -> bool:
        try:
            eth_key = eth_keys.PublicKey(public_key)
            eth_signature = eth_keys.Signature(signature)
            return eth_key.verify_msg_hash(message_hash, eth_signature)
        except ValidationError as e:
            # Handle invalid signature length or other validation issues
            print(f"Validation error: {e}")
            return False
        except BadSignature: #
            # Handle invalid signature content #
            return False #

    # ========== RSA SHA256 ==========
    @staticmethod
    def sign_rsa_sha256(private_key: bytes, message: bytes) -> bytes:
        """Sign a message with RSA SHA-256."""
        private_key_obj = serialization.load_pem_private_key(
            private_key, password=None, backend=default_backend()
        )
        return private_key_obj.sign(
            message,
            PKCS1v15(),
            SHA256(),
        )

    @staticmethod
    def verify_rsa_sha256(public_key: bytes, message: bytes, signature: bytes) -> bool:
        """Verify an RSA SHA-256 signature."""
        try:
            public_key_obj = serialization.load_pem_public_key(
                public_key, backend=default_backend()
            )
            public_key_obj.verify(
                signature,
                message,
                PKCS1v15(),
                SHA256(),
            )
            return True
        except Exception:
            return False

    # ========== ECDSA SHA256 ==========
    @staticmethod
    def sign_ecdsa_sha256(private_key: bytes, message: bytes) -> bytes:
        private_key_obj = ec.derive_private_key(int.from_bytes(private_key, "big"), ec.SECP256K1()) #
        return private_key_obj.sign(message, ec.ECDSA(SHA256())) #

    @staticmethod
    def verify_ecdsa_sha256(public_key: bytes, message: bytes, signature: bytes) -> bool:
        try: #
            public_key_obj = ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256K1(), public_key) #
            public_key_obj.verify(signature, message, ec.ECDSA(SHA256())) #
            return True #
        except Exception: #
            return False #

    # ========== TypedData (EIP-712 Compliant) ==========
    @staticmethod
    def sign_typed_data(private_key: bytes, message_hash: bytes) -> bytes:
        return SignatureHandler.sign_eth(private_key, message_hash) #

    @staticmethod
    def verify_typed_data(public_key: bytes, message_hash: bytes, signature: bytes) -> bool:
        return SignatureHandler.verify_eth(public_key, message_hash, signature) #

    # ========== Delegated Signature ==========
    @staticmethod
    def sign_delegated_signature(inner_signature: bytes, delegator: URL) -> bytes:
        """Create a delegated signature."""
        return hashlib.sha256(inner_signature + str(delegator).encode()).digest()  # Use str() instead of to_string

    @staticmethod
    def verify_delegated_signature(delegated_signature: bytes, inner_signature: bytes, delegator: URL) -> bool:
        """Verify a delegated signature."""
        expected_hash = hashlib.sha256(inner_signature + str(delegator).encode()).digest()  # Use str() instead of to_string
        return expected_hash == delegated_signature
