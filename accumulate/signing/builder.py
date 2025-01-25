# C:\Accumulate_Stuff\accumulate-python-client\accumulate\signing\builder.py

from datetime import datetime, timezone
from typing import List, Optional
from accumulate.models.signatures import (
    Signature,
    ED25519Signature,
    RCD1Signature,
    BTCSignature,
    ETHSignature,
    RSASignature,
    DelegatedSignature,
    LegacyED25519Signature,
    ECDSA_SHA256Signature,
)
from accumulate.models.signature_types import SignatureType
from accumulate.signing.signer import Signer
from accumulate.models.transactions import Transaction
from accumulate.utils.hash_functions import (
    btc_address,
    eth_address,
    hash_data,
)
from accumulate.utils.validation import validate_accumulate_url, is_reserved_url
from accumulate.utils.url import URL
import hashlib
import base58
from eth_utils import keccak


class InitHashMode:
    INIT_WITH_SIMPLE_HASH = "simple_hash"
    INIT_WITH_MERKLE_HASH = "merkle_hash"


class Builder:
    def __init__(self):
        self.init_mode: str = InitHashMode.INIT_WITH_SIMPLE_HASH
        self.type: SignatureType = SignatureType.UNKNOWN
        self.url: Optional[URL] = None
        self.delegators: List[URL] = []
        self.signer: Optional[Signer] = None
        self.version: int = 0
        self.timestamp: Optional[int] = None
        self.memo: str = ""
        self.data: bytes = b""
        self.ignore_64_byte: bool = False

    def set_type(self, signature_type: SignatureType) -> "Builder":
        """Set the signature type."""
        self.type = signature_type
        return self

    def set_url(self, url: URL) -> "Builder":
        """Set the signer's URL."""
        if is_reserved_url(url):
            raise ValueError("Reserved URL cannot be used as a signer URL")
        if not validate_accumulate_url(url):
            raise ValueError("Invalid Accumulate URL")
        self.url = url
        return self


    def set_signer(self, signer: Signer) -> "Builder":
        """Set the signer object."""
        self.signer = signer
        return self

    def set_version(self, version: int) -> "Builder":
        """Set the signer's version."""
        self.version = version
        return self

    def set_timestamp(self, timestamp: int) -> "Builder":
        """Set a custom timestamp."""
        self.timestamp = timestamp
        return self

    def set_timestamp_to_now(self) -> "Builder":
        """Set the timestamp to the current UTC time."""
        self.timestamp = int(datetime.now(timezone.utc).timestamp() * 1000)
        return self

    def set_memo(self, memo: str) -> "Builder":
        """Set a memo for the signature."""
        self.memo = memo
        return self

    def set_data(self, data: bytes) -> "Builder":
        """Attach data to the signature."""
        self.data = data
        return self

    def add_delegator(self, delegator: URL) -> "Builder":
        """Add a delegator URL."""
        if not validate_accumulate_url(delegator):
            raise ValueError("Invalid delegator URL")
        self.delegators.append(delegator)
        return self

    def _validate_signature_requirements(self, init: bool):
        """Validate required fields for signature preparation."""
        if not self.url:
            raise ValueError("Missing signer URL")
        if not self.signer:
            raise ValueError("Missing signer")
        if init and not self.version:
            raise ValueError("Missing version")
        if init and self.timestamp is None:
            raise ValueError("Missing timestamp")

    def _create_signature(self) -> Signature:
        """Create a signature object based on the specified type."""
        signature_map = {
            SignatureType.ED25519: ED25519Signature,
            SignatureType.LEGACY_ED25519: LegacyED25519Signature,
            SignatureType.RCD1: RCD1Signature,
            SignatureType.BTC: BTCSignature,
            SignatureType.ETH: ETHSignature,
            SignatureType.RSA_SHA256: RSASignature,
            SignatureType.ECDSA_SHA256: ECDSA_SHA256Signature,
        }
        sig_class = signature_map.get(self.type)
        if not sig_class:
            raise ValueError(f"Unsupported signature type: {self.type}")

        # Pass required arguments to the signature constructor
        signature = sig_class(
            signer=self.url,
            public_key=self.signer.get_public_key() if self.signer else None,
            signature=None  # Placeholder; to be set after signing
        )
        signature.signer_version = self.version
        signature.timestamp = self.timestamp
        signature.memo = self.memo
        signature.data = self.data
        return signature

    def prepare(self, init: bool) -> Signature:
        """Prepare a signature with required fields."""
        self._validate_signature_requirements(init)
        if self.type == SignatureType.UNKNOWN:
            self.type = SignatureType.ED25519

        signature = self._create_signature()
        self.signer.set_public_key(signature)
        return signature

    def sign(self, message: bytes) -> Signature:
        """Sign the provided message."""
        signature = self.prepare(init=False)
        for delegator in self.delegators:
            signature = DelegatedSignature(
                delegator=delegator,
                metadata_hash=None,
                signature=signature,
            )

        signature.transaction_hash = hash_data(message)
        self.signer.sign(signature, None, message)
        return signature

    def initiate(self, txn: Transaction) -> Signature:
        """Initiate a transaction and prepare the signature."""
        signature = self.prepare(init=True)
        for delegator in self.delegators:
            signature = DelegatedSignature(
                delegator=delegator,
                metadata_hash=None,
                signature=signature,
            )

        txn_hash = txn.get_hash()
        if self.init_mode == InitHashMode.INIT_WITH_SIMPLE_HASH:
            txn.header.initiator = txn_hash
        else:
            txn.header.initiator = self.calculate_merkle_hash(txn_hash)

        signature.transaction_hash = txn_hash
        self.signer.sign(signature, None, txn_hash)
        return signature

    def btc_address(self, public_key: bytes) -> str:
        """Generate a BTC address from a public key."""
        return btc_address(public_key)

    def eth_address(self, public_key: bytes) -> str:
        """Generate an ETH address from a public key."""
        return eth_address(public_key)