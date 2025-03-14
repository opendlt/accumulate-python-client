# accumulate-python-client\accumulate\models\signatures.py 

import hashlib
from typing import List, Dict, Any, Optional, Tuple
from eth_keys import keys
from eth_utils import decode_hex, keccak
from ecdsa import VerifyingKey, SECP256k1, SigningKey
from cryptography.hazmat.primitives.asymmetric import ed25519
from Crypto.PublicKey import RSA
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256
from accumulate.utils.url import URL
from accumulate.models.types import Message
import binascii
import time
from accumulate.utils.import_helpers import get_signer 

class Signature:
    """Base class for managing all signature types."""
    def __init__(self, signature_type: str, signer: Optional[URL] = None, version: int = 1):
        self.signature_type = signature_type
        self.signer = signer
        self.version = version
        self.signature = None

    def get_url(self) -> Optional[URL]:
        return self.signer

    def get_version(self) -> int:
        return self.version

    def get_signature(self) -> Optional[bytes]:
        return self.signature

    def hash(self, message: bytes) -> bytes:
        """Follow JS hashing structure: First hash signature metadata, then concatenate and hash with message."""
        sig_md_hash = hashlib.sha256(self.encode()).digest()
        final_hash = hashlib.sha256(sig_md_hash + message).digest()
        return final_hash

    def encode(self) -> bytes:
        """Serialize signature metadata for consistent hashing."""
        signer_bytes = str(self.signer).encode() if self.signer else b""
        return self.signature_type.encode() + signer_bytes + str(self.version).encode()


    def verify(self, msg: bytes) -> bool:
        raise NotImplementedError("Subclasses should implement this method.")


# ========== ED25519 Signature ==========

class ED25519Signature(Signature):
    
    def __init__(self, signer: URL, publicKey: bytes, signature: bytes, transaction_data: bytes):
        super().__init__('ed25519', signer, 1)
        self.publicKey = publicKey
        self.signature = signature
        self.timestamp = int(time.time() * 1e6)
        from accumulate.utils.hash_functions import hash_data
        self.transactionHash = hash_data(transaction_data).hex()

    def hash(self, message: bytes) -> bytes:
        """Follow JS hashing structure for ED25519."""
        sig_md_hash = hashlib.sha256(self.encode()).digest()
        final_hash = hashlib.sha256(sig_md_hash + message).digest()
        return final_hash

    def verify(self, msg: bytes) -> bool:
        try:
            vk = ed25519.Ed25519PublicKey.from_public_bytes(self.publicKey)
            final_hash = self.hash(msg)  # Ensure message is hashed before verification
            vk.verify(self.signature, final_hash)
            return True
        except Exception:
            return False

    def to_dict(self) -> dict:
        """Convert ED25519 signature to a dictionary."""
        return {
            "type": self.signature_type.lower(),
            "publicKey": self.publicKey.hex(),
            "signature": self.signature.hex(),
            "signer": str(self.signer),
            "signerVersion": self.version,
            "timestamp": self.timestamp,
            "transactionHash": self.transactionHash,
        }

# ========== EIP-712 Typed Data Signature ==========

class EIP712Signature(Signature):
    def __init__(self, signer: URL, public_key: bytes, signature: bytes, chain_id: int):
        super().__init__('EIP712', signer, 1)
        self.public_key = public_key
        self.signature = signature
        self.chain_id = chain_id

    def hash(self, data: Dict[str, Any]) -> bytes:
        """Generate EIP-712 compliant hash."""
        encoded_data = self._encode_typed_data(data)
        return hashlib.sha256(encoded_data).digest()

    def verify(self, data: Dict[str, Any]) -> bool:
        try:
            message_hash = self.hash(data)
            print(f"Debug: Verifying message_hash={message_hash.hex()}, signature={self.signature.hex()}")
            
            eth_key = keys.PublicKey(self.public_key)
            print(f"Debug: Using public_key={self.public_key.hex()}")

            # Perform verification
            result = eth_key.verify_msg_hash(message_hash, keys.Signature(self.signature))
            print(f"Debug: Verification result={result}")
            return result
        except Exception as e: #
            print(f"Error during verification: {e}") #
            return False #

    @staticmethod
    def _encode_typed_data(data: Dict[str, Any]) -> bytes:
        """Encode EIP-712 typed data."""
        return b"".join(f"{key}:{value}".encode() for key, value in data.items())


# ========== RSA Signature ==========

class RSASignature(Signature):
    def __init__(self, signer: URL, public_key: bytes, signature: bytes):
        super().__init__('RSA', signer, 1)
        self.public_key = public_key
        self.signature = signature

    def hash(self) -> bytes:
        return do_sha256(self.public_key)

    def verify(self, msg: bytes) -> bool:
        try:
            rsa_key = RSA.import_key(self.public_key)
            h = SHA256.new(msg)
            pkcs1_15.new(rsa_key).verify(h, self.signature)
            return True
        except Exception:
            return False


# ========== Signature Factory ==========

class SignatureFactory:
    """Factory to create signatures based on type."""
    @staticmethod
    def create_signature(sig_type: str, **kwargs) -> Optional[Signature]:
        if sig_type == "LegacyED25519":
            # Pass only the required arguments
            required_args = {k: kwargs[k] for k in ["signer", "public_key", "signature", "timestamp"] if k in kwargs}
            return LegacyED25519Signature(**required_args)
        elif sig_type == "TypedData":
            required_args = {k: kwargs[k] for k in ["signer", "public_key", "signature", "chain_id", "memo", "data"] if k in kwargs}
            return TypedDataSignature(**required_args)
        elif sig_type == "RCD1":
            required_args = {k: kwargs[k] for k in ["signer", "public_key", "signature", "timestamp"] if k in kwargs}
            return RCD1Signature(**required_args)
        elif sig_type == "BTC":
            required_args = {k: kwargs[k] for k in ["signer", "public_key", "signature"] if k in kwargs}
            return BTCSignature(**required_args)
        elif sig_type == "DelegatedSignature":
            required_args = {k: kwargs[k] for k in ["signature", "delegator"] if k in kwargs}
            return DelegatedSignature(**required_args)
        elif sig_type == "AuthoritySignature":
            required_args = {k: kwargs[k] for k in ["origin", "authority", "vote", "txid"] if k in kwargs}
            return AuthoritySignature(**required_args)
        else:
            raise ValueError(f"Unsupported signature type: {sig_type}")

# ========== Individual Signature Types ==========

class LegacyED25519Signature(Signature):
    def __init__(self, signer: Optional[URL], public_key: bytes, signature: bytes, timestamp: int):
        super().__init__('LegacyED25519', signer)
        self.public_key = public_key
        self.signature = signature
        self.timestamp = timestamp

    def hash(self) -> bytes:
        return do_sha256(self.public_key, str(self.timestamp).encode())

    def verify(self, msg: bytes) -> bool:
        try: #
            vk = VerifyingKey.from_string(self.public_key, curve=SECP256k1)
            return vk.verify(self.signature, msg)
        except Exception:
            return False


class BTCSignature(Signature):
    def __init__(self, signer: Optional[URL], public_key: bytes, signature: bytes):
        super().__init__('BTC', signer)
        self.public_key = public_key
        self.signature = signature

    def hash(self) -> bytes:
        return do_sha256(self.public_key)

    def verify(self, msg: bytes) -> bool:
        try:
            vk = VerifyingKey.from_string(self.public_key, curve=SECP256k1)
            return vk.verify(self.signature, msg) #
        except Exception:
            return False


class TypedDataSignature(Signature):
    def __init__(
        self,
        signer: Optional[URL],
        public_key: bytes,
        signature: bytes,
        chain_id: int,
        memo: Optional[str] = None,
        data: Optional[bytes] = None,
    ):
        super().__init__('TypedData', signer)
        self.public_key = public_key
        self.signature = signature
        self.chain_id = chain_id
        self.memo = memo
        self.data = data

    def hash(self, data: Dict[str, Any]) -> bytes:
        """Generate EIP-712 compliant hash."""
        encoded_data = self._encode_typed_data(data)
        return hashlib.sha256(encoded_data).digest()

    def verify(self, data: Dict[str, Any]) -> bool:
        try: #
            message_hash = self.hash(data)
            eth_key = keys.PublicKey(self.public_key)
            return eth_key.verify_msg_hash(message_hash, keys.Signature(self.signature))
        except Exception:
            return False

    @staticmethod
    def _encode_typed_data(data: Dict[str, Any]) -> bytes:
        """Encode EIP-712 typed data."""
        return b"".join(f"{key}:{value}".encode() for key, value in data.items())


# ========== Delegated and Authority Signatures ==========

class DelegatedSignature(Signature):
    def __init__(self, signature: Signature, delegator: URL):
        super().__init__('DelegatedSignature', signature.get_url())
        self.signature = signature
        self.delegator = delegator

    def hash(self) -> bytes:
        """Calculate hash for DelegatedSignature."""
        delegator_str = str(self.delegator).removeprefix("acc://")
        base_hash = self.signature.hash()
        delegator_bytes = delegator_str.encode()

        combined = base_hash + delegator_bytes

        result_hash = do_sha256(combined)
        return result_hash


    def verify(self, msg: bytes) -> bool:
        return self.signature.verify(msg)


class AuthoritySignature(Signature):
    def __init__(self, origin: URL, authority: URL, vote: Optional[str], txid: Optional[str]):
        super().__init__('AuthoritySignature', origin)
        self.authority = authority
        self.vote = vote
        self.txid = txid

    def hash(self) -> bytes:
        """Calculate hash for AuthoritySignature."""
        authority_str = str(self.authority).removeprefix("acc://")
        authority_bytes = authority_str.encode()
        vote_bytes = str(self.vote).encode() if self.vote else b""

        combined = authority_bytes + vote_bytes

        result_hash = do_sha256(combined)
        return result_hash

    def verify(self, msg: bytes) -> bool:
        # TODO: Implement authority-specific verification
        return True

# ========== RCD1 Signature ==========

class RCD1Signature(Signature):
    def __init__(self, signer: URL, public_key: bytes, signature: bytes, timestamp: int):
        super().__init__('RCD1', signer)
        self.public_key = public_key
        self.signature = signature
        self.timestamp = timestamp

    def hash(self) -> bytes:
        """Calculate RCD1-specific hash."""
        return do_sha256(self.public_key, str(self.timestamp).encode())

    def verify(self, msg: bytes) -> bool:
        """Verify the signature using ED25519."""
        try:
            vk = VerifyingKey.from_string(self.public_key, curve=SECP256k1)
            return vk.verify(self.signature, msg)
        except Exception:
            return False

# ========== Utilities for Hashing ==========

def do_sha256(*data: bytes) -> bytes:
    combined = b''.join(data)
    result = hashlib.sha256(combined).digest()
    return result

def do_eth_hash(pub_key: bytes) -> bytes:
    """Calculate the Ethereum address hash."""
    from eth_utils import keccak
    return keccak(pub_key)[-20:]

def do_btc_hash(pub_key: bytes) -> bytes:
    """Calculate the Bitcoin hash (RIPEMD160(SHA256(pub_key)))."""
    sha256_hash = hashlib.sha256(pub_key).digest()
    ripemd160 = hashlib.new('ripemd160')
    ripemd160.update(sha256_hash)
    return ripemd160.digest() 


# ========== EthSignatures ==========

class ETHSignature(Signature):
    """Represents an Ethereum signature."""
    def __init__(self, signer: URL, public_key: bytes, signature: bytes):
        super().__init__('ETH', signer)
        self.public_key = public_key
        self.signature = signature

    def hash(self) -> bytes:
        """Calculate the Ethereum-specific hash of the public key."""
        return keccak(self.public_key)[-20:]  # Return the last 20 bytes

    def verify(self, message: bytes) -> bool:
        """Verify the Ethereum signature."""
        try:
            # Hash the message using Ethereum's EIP-191 specification
            message_hash = keccak(b"\x19Ethereum Signed Message:\n" + str(len(message)).encode() + message)
            eth_key = keys.PublicKey(self.public_key)

            # Create a Signature object
            sig_obj = keys.Signature(self.signature[:64] + bytes([self.signature[64] % 2]))  # Ensure v is 0 or 1

            # Verify the signature
            return eth_key.verify_msg_hash(message_hash, sig_obj)
        except Exception as e:
            print(f"Error during ETH signature verification: {e}")
            return False

    def get_signature(self) -> bytes:
        """Return the raw signature bytes."""
        return self.signature

    def get_public_key(self) -> bytes:
        """Return the public key bytes."""
        return self.public_key

# ========== ECDSA_SHA256 ==========

class ECDSA_SHA256Signature(Signature):
    """
    Represents an ECDSA SHA-256 signature.
    """

    def __init__(self, signer: URL, public_key: bytes, signature: bytes):
        super().__init__('ECDSA_SHA256', signer)
        self.public_key = public_key
        self.signature = signature

    def hash(self) -> bytes:
        """
        Calculate the SHA-256 hash of the public key.
        """
        return hashlib.sha256(self.public_key).digest()

    def verify(self, msg: bytes) -> bool:
        """
        Verify the ECDSA SHA-256 signature for the provided message.
        """
        try:
            verifying_key = VerifyingKey.from_string(self.public_key, curve=SECP256k1)
            # Use hashlib.sha256 directly as the hash function
            return verifying_key.verify(self.signature, msg, hashfunc=hashlib.sha256)
        except Exception as e:
            print(f"Verification failed: {e}")
            return False

    def sign(self, msg: bytes, private_key: bytes) -> bytes:
        """
        Sign a message using ECDSA SHA-256 with the provided private key.
        """
        try:
            signing_key = SigningKey.from_string(private_key, curve=SECP256k1)
            signature = signing_key.sign(msg, hashfunc=hashlib.sha256)
            self.signature = signature
            return signature
        except Exception as e:
            print(f"Signing failed: {e}")
            raise

# ========== Key definitions ==========

class PublicKey:
    """
    Represents a public key and provides methods for its operations.
    """
    def __init__(self, key: bytes, type_: str):
        """
        Initialize a PublicKey instance.

        :param key: The public key bytes.
        :param type_: The type of the public key (e.g., ED25519, ECDSA).
        """
        self.key = key
        self.type = type_

    def __repr__(self):
        return f"<PublicKey type={self.type}, key={self.key.hex()}>"

    def get_type(self) -> str:
        """
        Get the type of the public key.
        """
        return self.type

    def get_public_key(self) -> Tuple[bytes, bool]:
        """
        Get the raw public key bytes.

        :return: A tuple containing the public key bytes and a boolean indicating success.
        """
        return self.key, True

    def get_public_key_hash(self) -> Tuple[bytes, bool]:
        """
        Get the hash of the public key.

        :return: A tuple containing the hashed public key bytes and a boolean indicating success.
        """
        try:
            return hashlib.sha256(self.key).digest(), True
        except Exception:
            return b"", False

    def __str__(self):
        """
        Format the public key as a string.
        """
        pub_key_hash, success = self.get_public_key_hash()
        return binascii.hexlify(pub_key_hash).decode() if success else "<invalid address>"


class PrivateKey:
    """
    Represents a private key and its associated public key.
    """
    def __init__(self, key: bytes, type_: str, public_key: Optional[bytes] = None):
        """
        Initialize a PrivateKey instance.

        :param key: The private key bytes.
        :param type_: The type of the private key (e.g., ED25519, ECDSA).
        :param public_key: The optional public key bytes.
        """
        self.key = key
        self.type = type_
        self.public_key = PublicKey(public_key, type_) if public_key else None

    def __repr__(self):
        return f"<PrivateKey type={self.type}, key={self.key.hex()}>"

    def to_dict(self) -> dict:
        return {
            "type": self.type,
            "key": self.key.hex(),
            "public_key": self.public_key.to_dict() if self.public_key else None,
        }

    def get_type(self) -> str:
        """
        Get the type of the private key.
        """
        return self.type

    def get_private_key(self) -> Tuple[bytes, bool]:
        """
        Get the raw private key bytes.

        :return: A tuple containing the private key bytes and a boolean indicating success.
        """
        return self.key, True

    def get_public_key(self) -> Optional[PublicKey]:
        """
        Get the associated public key.

        :return: The associated PublicKey instance or None if not set.
        """
        return self.public_key

    def __str__(self):
        """
        Format the private key as a string representation.
        """
        return binascii.hexlify(self.key).decode()


class PublicKeyHash:
    """
    Represents a hash derived from a public key.
    """

    def __init__(self, type_: str, hash_: bytes):
        self.type = type_
        self.hash = hash_

    def to_dict(self) -> dict:
        return {"type": self.type, "hash": self.hash.hex()}

    def __repr__(self):
        return f"<PublicKeyHash type={self.type}, hash={self.hash.hex()}>"

    def get_type(self) -> str:
        """Return the type of the public key hash."""
        return self.type

    def get_public_key_hash(self) -> bytes:
        """Return the hash of the public key."""
        return self.hash

    def __str__(self):
        """String representation of the address."""
        return f"{self.type}:{self.hash.hex()}"



class Lite:
    """
    Represents a lite account URL and associated data.
    """

    def __init__(self, url: str, bytes_: bytes):
        self.url = url
        self.bytes = bytes_

    def __repr__(self):
        return f"<Lite url={self.url}, bytes={self.bytes.hex()}>"

    def get_url(self) -> str:
        """Return the URL of the lite account."""
        return self.url

    def get_bytes(self) -> bytes:
        """Return the raw bytes of the lite account."""
        return self.bytes

    def __str__(self):
        """String representation of the lite account."""
        return self.url