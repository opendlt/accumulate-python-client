# accumulate-python-client\accumulate\signing\signature_handler.py

import hashlib
from typing import Optional
from cryptography.hazmat.primitives.asymmetric import ed25519, rsa, ec
from cryptography.hazmat.primitives.hashes import SHA256
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
from accumulate.utils.hash_functions import btc_address, eth_address, public_key_hash
from cryptography.hazmat.primitives.asymmetric.padding import PKCS1v15
from accumulate.signing.timestamp import TimestampFromVariable
import logging

logger = logging.getLogger(__name__)
timestamp_generator = TimestampFromVariable()

class SignatureHandler:
    @staticmethod
    def btc_address(public_key: bytes) -> str:
        """Generate a BTC address from a public key"""
        return btc_address(public_key)

    @staticmethod
    def eth_address(public_key: bytes) -> str:
        """Generate an ETH address from a public key"""
        return eth_address(public_key)

    @staticmethod
    def verify_merkle_hash(metadata_hash: bytes, txn_hash: bytes, signature: Signature) -> bool:
        """Verify if a Merkle hash is valid."""
        try:
            calculated_merkle_hash = hashlib.sha256(metadata_hash + txn_hash).digest()
            return calculated_merkle_hash == signature.transactionHash
        except Exception:
            return False

    @staticmethod
    def create_authority_signature(origin: URL, authority: URL, vote: Optional[str], txid: Optional[str]) -> bytes:
        """Create a signature for an authority."""
        data = str(origin).encode() + str(authority).encode()
        if vote:
            data += vote.encode()
        if txid:
            data += txid.encode()
        return hashlib.sha256(data).digest()

    @staticmethod
    def verify_authority_signature(authority_signature: bytes, origin: URL, authority: URL, vote: Optional[str], txid: Optional[str]) -> bool:
        """Verify an authority signature."""
        expected_hash = SignatureHandler.create_authority_signature(origin, authority, vote, txid)
        return expected_hash == authority_signature

    # ========== ED25519 ==========
    @staticmethod
    def sign_ed25519(private_key: bytes, message: bytes) -> bytes:
        """Sign a message using ED25519."""
        private_key_obj = ed25519.Ed25519PrivateKey.from_private_bytes(private_key)
        return private_key_obj.sign(message)

    @staticmethod
    def verify_ed25519(public_key: bytes, message: bytes, signature: bytes) -> bool:
        """Verify an ED25519 signature."""
        try:
            vk = ed25519.Ed25519PublicKey.from_public_bytes(public_key)
            vk.verify(signature, message)
            return True
        except Exception:
            return False

    # ========== BTC (ECDSA SECP256k1) ==========
    @staticmethod
    def sign_btc(private_key: bytes, message: bytes) -> bytes:
        """Sign a message using Bitcoin ECDSA SECP256k1"""
        private_key_obj = ec.derive_private_key(int.from_bytes(private_key, "big"), ec.SECP256K1())
        return private_key_obj.sign(message, ec.ECDSA(SHA256()))

    @staticmethod
    def verify_btc(public_key: bytes, message: bytes, signature: bytes) -> bool:
        """Verify a BTC (ECDSA SECP256k1) signature"""
        try:
            vk = ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256K1(), public_key)
            vk.verify(signature, message, ec.ECDSA(SHA256()))
            return True
        except Exception:
            return False

    # ========== ETH (EIP-712) ==========
    @staticmethod
    def sign_eth(private_key: bytes, message_hash: bytes) -> bytes:
        """Sign an Ethereum message"""
        try:
            eth_key = eth_keys.PrivateKey(private_key)
            return eth_key.sign_msg_hash(message_hash).to_bytes()
        except Exception:
            raise ValueError("Failed to sign Ethereum message")

    @staticmethod
    def verify_eth(public_key: bytes, message_hash: bytes, signature: bytes) -> bool:
        """Verify an Ethereum (EIP-712) signature"""
        try:
            eth_key = eth_keys.PublicKey(public_key)
            eth_signature = eth_keys.Signature(signature)
            return eth_key.verify_msg_hash(message_hash, eth_signature)
        except (ValidationError, BadSignature):
            return False

    # ========== RSA SHA256 ==========
    @staticmethod
    def sign_rsa_sha256(private_key: bytes, message: bytes) -> bytes:
        """Sign a message with RSA SHA-256"""
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
        """Verify an RSA SHA-256 signature"""
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
        """Sign a message using ECDSA SHA256"""
        private_key_obj = ec.derive_private_key(int.from_bytes(private_key, "big"), ec.SECP256K1())
        return private_key_obj.sign(message, ec.ECDSA(SHA256()))

    @staticmethod
    def verify_ecdsa_sha256(public_key: bytes, message: bytes, signature: bytes) -> bool:
        """Verify an ECDSA SHA256 signature"""
        try:
            public_key_obj = ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256K1(), public_key)
            public_key_obj.verify(signature, message, ec.ECDSA(SHA256()))
            return True
        except Exception:
            return False

    # ========== TypedData (EIP-712 Compliant) ==========
    @staticmethod
    def sign_typed_data(private_key: bytes, message_hash: bytes) -> bytes:
        """Sign an Ethereum message using EIP-712 Typed Data"""
        return SignatureHandler.sign_eth(private_key, message_hash)

    # ========== Delegated Signature ==========
    @staticmethod
    def sign_delegated_signature(inner_signature: bytes, delegator: URL) -> bytes:
        """Create a delegated signature"""
        return hashlib.sha256(inner_signature + str(delegator).encode()).digest()

    @staticmethod
    def verify_delegated_signature(delegated_signature: bytes, inner_signature: bytes, delegator: URL) -> bool:
        """Verify a delegated signature."""
        expected_hash = hashlib.sha256(inner_signature + str(delegator).encode()).digest()
        return expected_hash == delegated_signature

    # ========== General Signature Verification ==========
    @staticmethod
    def verify_signature_with_timestamp(public_key: bytes, message: bytes, signature: Signature, sig_type: SignatureType) -> bool:
        verification_methods = {
            SignatureType.ED25519: SignatureHandler.verify_ed25519,
            SignatureType.ECDSA_SHA256: SignatureHandler.verify_ecdsa_sha256,
            SignatureType.BTC: SignatureHandler.verify_btc,
            SignatureType.ETH: SignatureHandler.verify_eth,
            SignatureType.RSA_SHA256: SignatureHandler.verify_rsa_sha256,
        }

        verify_func = verification_methods.get(sig_type)
        if verify_func:
            return verify_func(public_key, message, signature.signature)
        else:
            raise ValueError(f"Unsupported signature type: {sig_type}")
