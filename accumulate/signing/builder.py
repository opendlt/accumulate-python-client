# accumulate-python-client\accumulate\signing\builder.py

import logging
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
from accumulate.utils.import_helpers import get_signer
from accumulate.models.transactions import Transaction
from accumulate.utils.hash_functions import btc_address, eth_address, hash_data
from accumulate.utils.validation import validate_accumulate_url, is_reserved_url
from accumulate.utils.url import URL
from accumulate.signing.timestamp import TimestampFromVariable
import hashlib

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Global timestamp generator
timestamp_generator = TimestampFromVariable()

class InitHashMode:
    INIT_WITH_SIMPLE_HASH = "simple_hash"
    INIT_WITH_MERKLE_HASH = "merkle_hash"

class Builder:
    def __init__(self):
        self.init_mode: str = InitHashMode.INIT_WITH_SIMPLE_HASH
        self.type: SignatureType = SignatureType.UNKNOWN
        self.url: Optional[URL] = None
        self.delegators: List[URL] = []
        self.signer: Optional[object] = None
        self.version: int = 1  # Set signer version to 1 by default
        self.timestamp = timestamp_generator.get()
        self.memo: str = ""
        self.data: bytes = b""
        self.ignore_64_byte: bool = False

    def set_type(self, signature_type: SignatureType) -> "Builder":
        self.type = signature_type
        return self

    def get_type(self) -> str:
        return self.type.to_rpc_format()
    
    def set_url(self, url: URL) -> "Builder":
        if is_reserved_url(url):
            raise ValueError("Reserved URL cannot be used as a signer URL")
        if not validate_accumulate_url(url):
            raise ValueError("Invalid Accumulate URL")
        self.url = url
        return self

    def set_signer(self, signer: Optional[object]) -> "Builder":
        """Sets the signer and assigns it to the builder."""
        Signer = get_signer()  # Dynamically import Signer
        if not isinstance(signer, Signer):
            raise TypeError("Expected an instance of Signer")
        
        self.signer = signer
        return self

    def set_version(self, version: int) -> "Builder":
        self.version = version
        return self

    def set_timestamp(self, timestamp: int) -> "Builder":
        self.timestamp = timestamp
        return self

    def set_timestamp_to_now(self) -> "Builder":
        self.timestamp = timestamp_generator.get()  # Ensure consistent timestamping
        return self

    def set_memo(self, memo: str) -> "Builder":
        self.memo = memo
        return self

    def set_data(self, data: bytes) -> "Builder":
        self.data = data
        return self

    def add_delegator(self, delegator: URL) -> "Builder":
        if not validate_accumulate_url(delegator):
            raise ValueError("Invalid delegator URL")
        self.delegators.append(delegator)
        return self

    def _validate_signature_requirements(self, init: bool):
        if not self.url:
            raise ValueError("Missing signer URL")
        if not self.signer:
            raise ValueError("Missing signer")
        if init and not self.version:
            raise ValueError("Missing version")
        if init and self.timestamp is None:
            raise ValueError("Missing timestamp")

    def _create_signature(self, transaction_data: bytes) -> Signature:
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

        signature = sig_class(
            signer=self.url,
            publicKey=self.signer.get_public_key() if self.signer else None, 
            signature=None,  # Placeholder; set after signing
            transaction_data=transaction_data
        )
        signature.memo = self.memo
        signature.data = self.data
        signature.type = self.get_type().lower()  # Ensure lowercase
        signature.timestamp = self.timestamp
        signature.signerVersion = self.version
        return signature

    def prepare(self, init: bool, transaction_data: bytes) -> Signature:
        """Prepare a signature ensuring transaction data is included."""
        self._validate_signature_requirements(init)
        if self.type == SignatureType.UNKNOWN:
            self.type = SignatureType.ED25519
        return self._create_signature(transaction_data)

    async def sign(self, message: bytes) -> dict:
        """Sign the provided message and return a dictionary."""
        transaction_data = message  # Use the message as transaction data
        signature = self.prepare(init=False, transaction_data=transaction_data)

        for delegator in self.delegators:
            signature = DelegatedSignature(
                delegator=delegator,
                metadata_hash=None,
                signature=signature,
            )

        # Use consistent camelCase for the field name
        signature.transactionHash = hash_data(transaction_data).hex()
        signature_data = await self.signer.sign_transaction(self.type, transaction_data)

        if isinstance(signature_data["signature"], bytes):
            signature_data["signature"] = signature_data["signature"].hex()

        logger.info(f"Debug: Signature Created - {signature_data['signature']}")

        return dict(signature_data)

    async def initiate(self, txn: Transaction) -> Signature:
        """Initiate a transaction and prepare the signature."""
        txn_hash = txn.get_hash()
        logger.info(f"Transaction Hash from txn.get_hash(): {txn_hash.hex()}")

        # Prepare the signature using the txn_hash as the signing data
        signature = self.prepare(init=True, transaction_data=txn_hash)
        
        for delegator in self.delegators:
            signature = DelegatedSignature(
                delegator=delegator,
                metadata_hash=None,
                signature=signature,
            )

        if self.init_mode == InitHashMode.INIT_WITH_SIMPLE_HASH:
            txn.header.initiator = txn_hash
        else:
            txn.header.initiator = self.calculate_merkle_hash(txn_hash)

        signature.transactionHash = txn_hash

        # Log the value of txn_hash being passed to the signer
        logger.info(f"Passing Transaction Hash to signer.sign_transaction(): {txn_hash.hex()}")

        signature_data = await self.signer.sign_transaction(self.type, txn_hash)
        signature.signature = signature_data["signature"]
        signature.signerVersion = signature_data["signerVersion"]

        return signature
