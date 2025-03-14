# accumulate-python-client\accumulate\signing\signer.py 

import logging
import hashlib
import struct
import json
from typing import TYPE_CHECKING, List, Optional, Dict
from cryptography.hazmat.primitives.asymmetric import rsa, ec, ed25519
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.backends import default_backend
from accumulate.models.base_transactions import TransactionHeader
from accumulate.models.transactions import RemoteTransaction, Transaction
from accumulate.utils.encoding import encode_uvarint
from accumulate.utils.url import URL
from eth_keys import keys as eth_keys
from eth_keys.exceptions import BadSignature
from accumulate.utils.hash_functions import btc_address, eth_address
from cryptography.hazmat.primitives.asymmetric.padding import PKCS1v15
from accumulate.signing.timestamp import TimestampFromVariable
from accumulate.models.signature_types import SignatureType
from accumulate.utils.import_helpers import query_signer_version

logger = logging.getLogger(__name__)
timestamp_provider = TimestampFromVariable()

class MetadataEncodingError(Exception):
    pass

if TYPE_CHECKING:
    from accumulate.api.client import AccumulateClient

class Signer:
    _signer_version = 1
    _signature_type: Optional[SignatureType] = None  #  Store signature type

    def __init__(self, url: Optional[URL] = None, signer_version: int = 1, signature_type: Optional[SignatureType] = None):
        self._private_key = None
        self._public_key = None
        self.url = url
        self._signer_version = signer_version
        self._signature_type = signature_type

    @staticmethod
    async def select_signer(account_url: URL, private_key: bytes, client: Optional["AccumulateClient"] = None) -> "Signer":
        if client is None:
            from accumulate.api.client import AccumulateClient  
            from accumulate.config import get_accumulate_rpc_url  
            client = AccumulateClient(get_accumulate_rpc_url())

        from accumulate.utils.validation import process_signer_url  
        logger.info(f"Checking signer type and version for {account_url}...")

        signer_info = await process_signer_url(account_url, client)

        processed_url = signer_info["url"]
        signer_version = signer_info["signer_version"]
        signer_type = signer_info["signer_type"]

        #  Convert the fetched signer_type string to a SignatureType Enum
        signature_type_enum = SignatureType[signer_type] if signer_type in SignatureType.__members__ else SignatureType.ED25519

        logger.info(f"Using {processed_url} as signer ({signer_type}), Version: {signer_version}")

        signer = Signer(URL.parse(processed_url), signer_version, signature_type_enum)
        signer.set_keys(private_key)

        return signer

    async def get_signature_type(self) -> SignatureType:
        """
        Fetch the appropriate signature type dynamically.

        - If already cached, return it.
        - Otherwise, determine it dynamically.
        """
        if self._signature_type:
            return self._signature_type  #  Use cached signature type if available

        #  Implement logic to fetch the actual signature type from signer metadata
        # Currently defaulting to ED25519, but should be dynamically set
        self._signature_type = SignatureType.ED25519  # Replace with dynamic lookup if needed
        
        logger.info(f" Determined Signature Type: {self._signature_type.name}")
        return self._signature_type

    def set_keys(self, private_key: bytes) -> None:
        if len(private_key) == 64:
            private_scalar = private_key[:32]
            derived_public_key = private_key[32:]
        elif len(private_key) == 32:
            private_scalar = private_key
            derived_public_key = None

        self._private_key = ed25519.Ed25519PrivateKey.from_private_bytes(private_scalar)
        computed_public_key = self._private_key.public_key().public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw
        )

        if derived_public_key and computed_public_key != derived_public_key:
            raise ValueError("Derived public key does not match computed public key!")

        self._public_key = computed_public_key
        logger.info(f"Public Key Correctly Set: {self._public_key.hex()}")

    def get_public_key(self) -> bytes:
        if not self._public_key:
            logger.warning("Public key missing. Regenerating from private key.")
            if self._private_key:
                self._public_key = self._private_key.public_key().public_bytes(
                    encoding=serialization.Encoding.Raw,
                    format=serialization.PublicFormat.Raw
                )
            else:
                raise ValueError("Public key has not been set. Call set_keys() first.")
        return self._public_key

    def get_private_key(self) -> bytes:
        if not self._private_key:
            raise ValueError("Private key has not been set. Call set_keys() first.")
        return self._private_key.private_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PrivateFormat.Raw,
            encryption_algorithm=serialization.NoEncryption()
        )

    async def get_signer_version(self) -> int:
        if self.url is None:
            raise ValueError("Signer URL is missing, cannot determine version.")
        return self._signer_version

    def set_signer_version(self, version: int):
        self._signer_version = version


#    async def sign_transaction(self, signature_type: SignatureType, message: bytes, signer_version: Optional[int] = None) -> dict:
    async def sign_transaction(
        self, 
        signature_type: SignatureType, 
        message: bytes, 
        txn_header: TransactionHeader,  # Use the TransactionHeader object to access timestamp
        signer_version: Optional[int] = None
    ) -> dict:
        """
        Signs the transaction using the timestamp from the TransactionHeader.

        :param signature_type: The signature type (e.g., ED25519, BTC, etc.).
        :param message: The transaction hash to sign.
        :param txn_header: The TransactionHeader instance, containing the timestamp.
        :param signer_version: The signer's version (if None, uses the default).
        :return: A signed transaction dictionary.
        """
        if not self._private_key:
            raise ValueError("Private key not set. Call set_keys() first.")
        if not self._public_key:
            raise ValueError("Public key not set. Call set_keys() properly.")

        if signer_version is None:
            signer_version = self._signer_version

        #  Use timestamp from the TransactionHeader
        timestamp = txn_header.timestamp
        if timestamp is None:
            raise ValueError("Transaction header does not have a timestamp!")

        logger.info(f" Signer Using TransactionHeader Timestamp: {timestamp}")

        # Compute metadata (initiator) hash using uvarint encoding.
        metadata_hash = Signer.calculate_metadata_hash(
            self.get_public_key(), timestamp, str(self.url), signer_version, signature_type.value
        )

        logger.info(f" FROM SIGNER - Metadata (Public key) Hash: {self.get_public_key().hex()}")
        logger.info(f" FROM SIGNER - Metadata (timestamp) Hash: {timestamp}")
        logger.info(f" FROM SIGNER - Metadata (signer) Hash: {str(self.url)}")
        logger.info(f" FROM SIGNER - Metadata (signer_version) Hash: {signer_version}")
        logger.info(f" FROM SIGNER - Metadata (signature_type.vale) Hash: {signature_type.value}")

        logger.info(f" FROM SIGNER - Metadata (initiator) Hash: {metadata_hash.hex()}")

        # Here, 'message' is expected to be the final transaction hash as computed in your transaction marshalling
        logger.info(f"Message passed for signing (transaction hash): {message.hex()}")

        # Compute the final signing hash as sha256(metadata_hash + message)
        final_hash = hashlib.sha256(metadata_hash + message).digest()
        logger.info(f"Final Hash for Signing (sha256(metadata_hash + message)): {final_hash.hex()}")

        # Sign using the appropriate algorithm.
        if signature_type == SignatureType.ED25519:
            signature = self._private_key.sign(final_hash)
        elif signature_type == SignatureType.BTC:
            priv_key = ec.derive_private_key(int.from_bytes(self.get_private_key(), "big"), ec.SECP256K1())
            signature = priv_key.sign(final_hash, ec.ECDSA(hashes.SHA256()))
        elif signature_type == SignatureType.ETH:
            eth_key = eth_keys.PrivateKey(self.get_private_key())
            signature = eth_key.sign_msg_hash(final_hash).to_bytes()
        elif signature_type == SignatureType.RSA_SHA256:
            private_key_obj = serialization.load_pem_private_key(self.get_private_key(), password=None, backend=default_backend())
            if isinstance(private_key_obj, rsa.RSAPrivateKey):
                signature = private_key_obj.sign(
                    final_hash,
                    PKCS1v15(),
                    hashes.SHA256(),
                )
            else:
                raise ValueError("Invalid RSA private key")
        elif signature_type == SignatureType.ECDSA_SHA256:
            priv_key = ec.derive_private_key(int.from_bytes(self.get_private_key(), "big"), ec.SECP256K1())
            signature = priv_key.sign(final_hash, ec.ECDSA(hashes.SHA256()))
        else:
            raise ValueError(f"Unsupported signature type: {signature_type}")

        logger.info("sign_transaction() called successfully!")
        logger.info(f"Signature Generated: {signature.hex()}")

        signed_transaction = {
            "type": signature_type.name.lower(),
            "publicKey": self.get_public_key().hex(),
            "signature": signature.hex(),
            "signer": str(self.url),
            "signerVersion": signer_version,
            "timestamp": timestamp,
            "transactionHash": message.hex()  # The original transaction hash passed in
        }

        logger.info(f"Signed Transaction Data - {signed_transaction}")

        return signed_transaction

    async def sign(self, message: bytes, opts: dict) -> dict:
        signature_type = opts.get("signatureType", SignatureType.ED25519)
        signer_version = opts.get("signerVersion", self._signer_version)
        return await self.sign_transaction(signature_type, message, signer_version)

    @staticmethod
    def for_lite(signer: "Signer") -> "Signer":
        if signer._public_key is None or signer._private_key is None:
            raise ValueError("Signer must have keys set before calling for_lite().")
        
        key_str = hashlib.sha256(signer.get_public_key()).digest()[:20]
        check_sum = hashlib.sha256(key_str).digest()[-4:]
        lite_url = URL.parse(f"acc://{key_str.hex()}{check_sum.hex()}")

        logger.info(f"Created Lite Signer: {lite_url}")

        lite_signer = Signer(lite_url, signer_version=1)
        lite_signer._public_key = signer._public_key
        lite_signer._private_key = signer._private_key

        return lite_signer

    def set_public_key(self, signature: Dict, private_key: bytes) -> None:
        signature_type = signature.get("type")
        if signature_type in [SignatureType.LEGACY_ED25519, SignatureType.ED25519, SignatureType.RCD1]:
            private_key_obj = ed25519.Ed25519PrivateKey.from_private_bytes(private_key)
            self._public_key = private_key_obj.public_key().public_bytes(
                encoding=serialization.Encoding.Raw,
                format=serialization.PublicFormat.Raw
            )  
            signature["publicKey"] = self._public_key.hex()
        elif signature_type in [SignatureType.BTC]:
            priv_key = ec.derive_private_key(int.from_bytes(private_key, "big"), ec.SECP256K1())
            public_key = priv_key.public_key().public_bytes(
                encoding=serialization.Encoding.X962,
                format=serialization.PublicFormat.CompressedPoint
            )
            signature["publicKey"] = public_key.hex()
            signature["btc_address"] = btc_address(public_key)
        elif signature_type == SignatureType.ETH:
            eth_key = eth_keys.PrivateKey(private_key)
            public_key = eth_key.public_key.to_bytes()
            signature["eth_address"] = eth_address(public_key)
        elif signature_type == SignatureType.RSA_SHA256:
            private_key_obj = serialization.load_pem_private_key(private_key, password=None, backend=default_backend())
            if isinstance(private_key_obj, rsa.RSAPrivateKey):
                signature["publicKey"] = private_key_obj.public_key().public_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PublicFormat.SubjectPublicKeyInfo
                ).hex()
        elif signature_type == SignatureType.ECDSA_SHA256:
            priv_key = ec.derive_private_key(int.from_bytes(private_key, "big"), ec.SECP256K1())
            signature["publicKey"] = priv_key.public_key().public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            ).hex()
        else:
            raise ValueError(f"Cannot set the public key for {signature_type}")

    def sign_rcd1(self, private_key: bytes, message: bytes) -> dict:
        private_key_obj = ed25519.Ed25519PrivateKey.from_private_bytes(private_key)
        hashed_message = hashlib.sha256(message).digest()
        signature = private_key_obj.sign(hashed_message)
        return {"signature": signature.hex()}

    def verify_rcd1(self, public_key: bytes, signature: bytes, message: bytes) -> bool:
        try:
            vk = ed25519.Ed25519PublicKey.from_public_bytes(public_key)
            hashed_message = hashlib.sha256(message).digest()
            vk.verify(signature, hashed_message)
            return True
        except Exception:
            return False

    @staticmethod
    def sha256_concat(*data: bytes) -> bytes:
        return hashlib.sha256(b"".join(data)).digest()

    @staticmethod
    def encode_varint(value: int) -> bytes:
        if value < 0:
            raise ValueError("Varint encoding requires a non-negative integer.")
        encoded_bytes = bytearray()
        while value >= 0x80:
            encoded_bytes.append((value & 0x7F) | 0x80)
            value >>= 7
        encoded_bytes.append(value)
        return bytes(encoded_bytes)

    @staticmethod
    def calculate_metadata_hash(public_key: bytes, timestamp: int, signer: str, version: int, signature_type: int) -> bytes:
        """
        Compute Accumulate's signature metadata (initiator) hash using uvarint encoding for all fields.
        This exactly mirrors the Dart implementation.
        
        Fields:
        - Field 1: Signature type (varint-encoded)
        - Field 2: Public key (varint-encoded length + raw bytes)
        - Field 4: Signer URL (UTF-8 encoded, with varint length prefix)
        - Field 5: Signer version (varint-encoded)
        - Field 6: Timestamp (varint-encoded)
        """
        from accumulate.utils.encoding import encode_uvarint

        logger.debug(f" calculate_metadata_hash: {public_key.hex()}")
        logger.debug(f" calculate_metadata_hash: {timestamp}")
        logger.debug(f" calculate_metadata_hash: {signer}")
        logger.debug(f" calculate_metadata_hash: {version}")
        logger.debug(f" calculate_metadata_hash: {signature_type}")

        # Encode the signer URL into bytes.
        signer_bytes = signer.encode("utf-8")

        # Build the metadata binary by concatenating each field in order.
        metadata = b"".join([
            b"\x01" + encode_uvarint(signature_type),                   # Field 1: Signature type
            b"\x02" + encode_uvarint(len(public_key)) + public_key,         # Field 2: Public key
            b"\x04" + encode_uvarint(len(signer_bytes)) + signer_bytes,       # Field 4: Signer URL
            b"\x05" + encode_uvarint(version),                              # Field 5: Signer version
            b"\x06" + encode_uvarint(timestamp)                             # Field 6: Timestamp
        ])
        
        logger.debug(f" Final Metadata Encoding (hex): {metadata.hex()}")

        # Compute the SHA-256 hash of the concatenated metadata.
        metadata_hash = hashlib.sha256(metadata).digest()
        logger.debug(f"Metadata Hash (SHA-256, hex): {metadata_hash.hex()}")
        return metadata_hash


    @staticmethod
    def calculate_signature_hash(signature) -> bytes:
        data = signature.marshal_binary()
        return Signer.sha256_concat(data)

    @staticmethod
    def is_parent_of(parent: URL, child: URL) -> bool:
        return str(child).startswith(str(parent))


    async def sign_and_submit_transaction(
        self, client: "AccumulateClient", txn: Transaction, signature_type: SignatureType, debug: bool = False
    ) -> dict:
        """
        Signs the transaction, constructs the envelope, and submits it.

        :param client: AccumulateClient instance
        :param txn: Transaction object
        :param signature_type: Type of signature (e.g., ED25519)
        :param debug: If True, print the exact JSON request without sending it.
        :return: Response from the Accumulate network or printed JSON in debug mode.
        """
        #  Step 1: Check if this is a Remote Transaction
        if isinstance(txn.body, RemoteTransaction):
            logger.info(" RemoteTransaction detected, checking multisignature conditions...")

            #  If it does NOT support multisignature, prevent signing
            if not txn.body.allows_multisig():
                raise ValueError("Cannot sign a RemoteTransaction that does not allow multisignatures.")

            #  Otherwise, allow signing but ensure it's an additional signature
            existing_signatures = txn.body.get_existing_signatures()
            if self.get_public_key() in existing_signatures:
                raise ValueError("This signer has already signed this RemoteTransaction.")

            logger.info(f" Proceeding with multisignature signing for RemoteTransaction.")

        #  Step 2: Check if the signer has keys set
        if not self._private_key or not self._public_key:
            raise ValueError("Signer keys not set. Call set_keys() first.")

        logger.info(" Computing transaction hash...")
        txn_hash = txn.get_hash()

        logger.info(f" Signing transaction (hash: {txn_hash.hex()})...")
        signature_data = await self.sign_transaction(signature_type, txn_hash, txn.header)

        logger.info(f" Constructing envelope...")
        envelope = {
            "signatures": [signature_data],
            "transaction": [txn.to_dict()]
        }

        if debug:
            formatted_json = json.dumps(envelope, indent=4)
            logger.info(f" RPC Request (Not Sent):\n{formatted_json}")
            return envelope  # Return the request without sending

        logger.info(f" Submitting transaction to the Accumulate network...")
        try:
            json_envelope = json.dumps(envelope)
            response = await client.submit(json.loads(json_envelope))
            logger.info(f" Transaction Submitted Successfully! Response: {response}")
            return response
        except Exception as e:
            logger.error(f" Transaction Submission Failed: {e}")
            raise

