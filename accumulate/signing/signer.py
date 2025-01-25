# C:\Accumulate_Stuff\accumulate-python-client\accumulate\signing\signer.py 

import hashlib
from typing import Optional, Dict, Callable, Union
from cryptography.hazmat.primitives.asymmetric import rsa, ec, ed25519
from cryptography.hazmat.primitives.asymmetric.utils import Prehashed
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.serialization import load_pem_private_key
from cryptography.hazmat.backends import default_backend
from eth_keys import keys as eth_keys
from eth_keys.exceptions import BadSignature
from accumulate.utils.url import URL
from accumulate.models.signature_types import SignatureType
import base58
from eth_utils import keccak
from accumulate.utils.hash_functions import (
    btc_address,
    eth_address,
    public_key_hash,
)

class Signer:
    """Handles signing operations for various signature types."""

    def set_public_key(self, signature: Dict, private_key: bytes) -> None:
        """Set the public key for the given signature type."""
        signature_type = signature.get("type")

        if signature_type in [SignatureType.LEGACY_ED25519, SignatureType.ED25519, SignatureType.RCD1]:
            private_key_obj = ed25519.Ed25519PrivateKey.from_private_bytes(private_key)
            signature["public_key"] = private_key_obj.public_key().public_bytes(
                encoding=serialization.Encoding.Raw,
                format=serialization.PublicFormat.Raw
            )

        elif signature_type in [SignatureType.BTC, SignatureType.BTCLegacy]:
            priv_key = ec.derive_private_key(int.from_bytes(private_key, "big"), ec.SECP256K1())
            signature["public_key"] = priv_key.public_key().public_bytes(
                encoding="compressed" if signature_type == SignatureType.BTC else "uncompressed"
            )

        elif signature_type == SignatureType.ETH:
            eth_key = eth_keys.PrivateKey(private_key)
            signature["public_key"] = eth_key.public_key.to_bytes()

        elif signature_type == SignatureType.RSA_SHA256:
            private_key_obj = load_pem_private_key(private_key, password=None, backend=default_backend())
            if isinstance(private_key_obj, rsa.RSAPrivateKey):
                signature["public_key"] = private_key_obj.public_key().public_bytes()

        elif signature_type == SignatureType.ECDSA_SHA256:
            priv_key = ec.derive_private_key(int.from_bytes(private_key, "big"), ec.SECP256K1())
            signature["public_key"] = priv_key.public_key().public_bytes()

        else:
            raise ValueError(f"Cannot set the public key for {signature_type}")

    def sign_transaction(self, signature_type: SignatureType, private_key: bytes, message: bytes) -> Dict:
        """Sign a transaction with the appropriate signature type."""
        if signature_type in [SignatureType.LEGACY_ED25519, SignatureType.ED25519]:
            private_key_obj = ed25519.Ed25519PrivateKey.from_private_bytes(private_key)
            signature = private_key_obj.sign(message)
            return {"signature": signature}

        elif signature_type == SignatureType.BTC:
            priv_key = ec.derive_private_key(int.from_bytes(private_key, "big"), ec.SECP256K1())
            signature = priv_key.sign(message, ec.ECDSA(hashes.SHA256()))
            return {"signature": signature}

        elif signature_type == SignatureType.ETH:
            eth_key = eth_keys.PrivateKey(private_key)
            sig = eth_key.sign_msg_hash(hashlib.sha256(message).digest())
            return {"signature": sig.to_bytes()}

        elif signature_type == SignatureType.RSA_SHA256:
            private_key_obj = load_pem_private_key(private_key, password=None, backend=default_backend())
            if isinstance(private_key_obj, rsa.RSAPrivateKey):
                signature = private_key_obj.sign(message, padding=rsa.PKCS1v15(), algorithm=Prehashed(hashes.SHA256()))
                return {"signature": signature}

        elif signature_type == SignatureType.ECDSA_SHA256:
            priv_key = ec.derive_private_key(int.from_bytes(private_key, "big"), ec.SECP256K1())
            signature = priv_key.sign(message, ec.ECDSA(hashes.SHA256()))
            return {"signature": signature}

        else:
            raise ValueError(f"Unsupported signature type: {signature_type}")

    def btc_address(self, public_key: bytes) -> str:
        """Calculate a BTC address from the public key."""
        return btc_address(public_key)

    def eth_address(self, public_key: bytes) -> str:
        """Calculate an ETH address from the public key."""
        return eth_address(public_key)

    def sign_rcd1(self, private_key: bytes, message: bytes) -> Dict:
        """Sign a message using RCD1 signature."""
        private_key_obj = ed25519.Ed25519PrivateKey.from_private_bytes(private_key)
        hashed_message = hashlib.sha256(message).digest()
        signature = private_key_obj.sign(hashed_message)
        return {"signature": signature}

    def verify_rcd1(self, public_key: bytes, signature: bytes, message: bytes) -> bool:
        """Verify an RCD1 signature."""
        try:
            vk = ed25519.Ed25519PublicKey.from_public_bytes(public_key)
            hashed_message = hashlib.sha256(message).digest()
            vk.verify(signature, hashed_message)
            return True
        except Exception:
            return False

    @staticmethod
    def sha256_concat(*data: bytes) -> bytes:
        """Concatenate and hash data using SHA-256."""
        combined = b"".join(data)
        return hashlib.sha256(combined).digest()

    @staticmethod
    def calculate_metadata_hash(public_key: bytes, timestamp: int, signer: str, version: int) -> bytes:
        """Calculate metadata hash."""
        components = [
            public_key,
            signer.encode(),
            version.to_bytes(8, 'big'),
            timestamp.to_bytes(8, 'big'),
        ]
        return hashlib.sha256(b''.join(components)).digest()

    @staticmethod
    def calculate_signature_hash(signature) -> bytes:
        """Calculate the SHA-256 hash of a signature."""
        data = signature.marshal_binary()
        return Signer.sha256_concat(data)

