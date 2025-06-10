# \accumulate\models\transactions.py

import base64
from dataclasses import dataclass
import io
import hashlib
import re
import json
from typing import Dict, List, Optional, Union, Any
from accumulate.models.accounts import Account
from accumulate.models.key_management import KeySpecParams

from accumulate.models.transaction_results import TransactionResult
#from accumulate.signing.signer import "Signer"
from accumulate.utils.url import URL
from accumulate.models.txid import TxID
from accumulate.api.exceptions import AccumulateError
import hashlib
from accumulate.models.errors import AccumulateError, ErrorCode
from typing import Optional, List, Union, Tuple
from accumulate.models.data_entries import AccumulateDataEntry, DataEntry, DoubleHashDataEntry
from accumulate.models.enums import AccountAuthOperationType, QueryType, TransactionType, KeyPageOperationType
from accumulate.models.key_management import KeySpec
from accumulate.models.general import CreditRecipient, TokenRecipient
from accumulate.models.base_transactions import TransactionBodyBase, TransactionBodyFactory, TransactionHeader, ExpireOptions, HoldUntilOptions
from unittest.mock import MagicMock
import logging
from accumulate.utils.encoding import (
    big_number_marshal_binary,
    boolean_marshal_binary,
    hash_marshal_binary,
    string_marshal_binary,
    bytes_marshal_binary,
    encode_uvarint,
    decode_uvarint,
    unmarshal_bytes,
    unmarshal_string,
    encode_compact_int,
    field_marshal_binary,
    read_uvarint,
)

from accumulate.models.key_signature import KeySignature
import asyncio
from accumulate.models.queries import DataQuery
from accumulate.models.options import RangeOptions
from accumulate.utils.import_helpers import get_signer  #  Import from helper module

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from accumulate.signing.signer import Signer

logger = logging.getLogger(__name__)



# Helper to normalize operation type strings
def normalize_operation_type(op_type: str) -> str:
    s1 = re.sub(r'(?<=[a-z0-9])([A-Z])', r'_\1', op_type)
    return s1.upper()


class Transaction:
    def __init__(self, header: "TransactionHeader", body: Optional["TransactionBodyBase"] = None):
        self.header = header
        self.body = body
        self.hash: Optional[bytes] = None
        self.signers: List["Signer"] = []


    def is_remote(self) -> bool:
        """Check if this transaction is a RemoteTransaction."""
        return isinstance(self.body, RemoteTransaction)

    @classmethod
    async def create(cls, client, signer: "Signer", transaction_type: TransactionType, *args, **kwargs) -> "Transaction":
        """
        Fully constructs a transaction, including the header and body.

        :param client: AccumulateClient instance
        :param signer: Signer instance
        :param transaction_type: The type of transaction to create
        :param args: Additional arguments passed to the transaction body
        :param kwargs: Additional keyword arguments for the transaction body
        :return: A fully constructed Transaction instance
        """
        # Extract public key from signer
        public_key = signer.get_public_key()
        recipient = kwargs.get("recipient")

        #  Create Transaction Header (handles initiator hash internally)
        tx_header = await TransactionHeader.create(recipient, public_key, signer)

        #  Create Transaction Body using the Factory
        tx_body = await TransactionBodyFactory.create(client, transaction_type, *args, **kwargs)

        return cls(header=tx_header, body=tx_body)


    def add_signer(self, url: "URL", version: int) -> None:
        """Add a signer dynamically."""
        signer = get_signer()(url, version)
        self.signers.append(signer)

    def get_signer(self, url: "URL") -> Optional["Signer"]:
        """Retrieve a signer dynamically."""
        return next((signer for signer in self.signers if signer.get_url() == url), None)

    def is_user(self) -> bool:
        """Check if the transaction is initiated by a user."""
        return self.body is not None and self.body.type().is_user()


    def get_hash(self) -> bytes:
        """Compute transaction hash ensuring Accumulate's hashing order."""
        
        #  If it's a Remote Transaction, return its referenced hash
        if isinstance(self.body, RemoteTransaction):
            logger.debug(" Using referenced hash for RemoteTransaction")
            return self.body.hash  # Remote transactions use the referenced hash directly

        #  Compute transaction hash if not already cached
        if not self.hash:
            logger.debug(" Computing transaction hash...")

            #  Step 1: Hash the header
            header_bytes = self.header.marshal_binary()
            header_hash = hashlib.sha256(header_bytes).digest()
            logger.info(f" Hashed Header: {header_hash.hex()}")  # Log Header Hash

            #  Step 2: Special handling for WriteData transactions
            if isinstance(self.body, WriteData):
                logger.debug(" Special WriteData hashing logic applied")

                #  Hash body WITHOUT the entry
                body_without_entry = self.body.marshal_without_entry()
                body_hash = hashlib.sha256(body_without_entry).digest()
                logger.info(f" Hashed Body (without entry): {body_hash.hex()}")  # Log Body Hash (without entry)

                #  Hash entry separately
                entry_hash = self.body.hash_tree()
                logger.info(f" Hashed Entry (Merkle + SHA-256): {entry_hash.hex()}")  # Log Entry Hash

                #  Step 3: Combine and hash again
                final_body_hash = hashlib.sha256(body_hash + entry_hash).digest()
                logger.info(f" Final Hashed Body: {final_body_hash.hex()}")  # Log Final Body Hash
            else:
                #  Standard transactions
                body_bytes = self.body.marshal() if self.body else b""
                final_body_hash = hashlib.sha256(body_bytes).digest()
                logger.info(f" Standard Hashed Body: {final_body_hash.hex()}")  # Log Body Hash

            #  Final hash: H(H(header) + H(body))
            self.hash = hashlib.sha256(header_hash + final_body_hash).digest()
            logger.info(f" FINAL Transaction Hash: {self.hash.hex()}")  # Log Final Transaction Hash

        return self.hash


    def to_dict(self) -> dict:
        """Convert a Transaction into a dictionary format suitable for submission."""
        if not self.header or not self.body:
            raise ValueError("Transaction must have both header and body set.")

        return {
            "header": self.header.to_dict(),
            "body": self.body.to_dict() if self.body else None,
        }

    def get_id(self) -> TxID:
        """Get the transaction ID based on its hash and principal URL."""
        url = URL.parse(self.header.principal) if self.header.principal else URL(authority="unknown", path="")
        return TxID(url=url, tx_hash=self.get_hash())

    def marshal(self) -> bytes:
        """
        Serialize the transaction to bytes.
        Format:
          [header length (varint)] + [header bytes]
          [body length (varint)] + [body bytes]
        """
        header_data = self.header.marshal_binary()
        header_length = encode_uvarint(len(header_data))

        body_data = self.body.marshal() if self.body else b""
        body_length = encode_uvarint(len(body_data))

        return header_length + header_data + body_length + body_data

    @staticmethod
    def unmarshal(data: bytes) -> "Transaction":
        """
        Deserialize a Transaction from bytes.
        Format:
          [header length (varint)] + [header bytes]
          [body length (varint)] + [body bytes]
        """
        reader = io.BytesIO(data)

        # Read header length
        header_length = read_uvarint(reader)
        header_data = reader.read(header_length)
        header = TransactionHeader.unmarshal(header_data)

        # Read body length
        body_length = read_uvarint(reader)
        body_data = reader.read(body_length) if body_length > 0 else b""
        body = TransactionBodyBase.unmarshal(body_data) if body_data else None

        return Transaction(header, body)

    def get_body_hash(self) -> bytes:
        """Compute the hash of the transaction body separately for debugging."""
        if not self.body:
            return hashlib.sha256(b"").digest()

        body_bytes = self.body.marshal()
        return hashlib.sha256(body_bytes).digest()

class TransactionStatus:
    def __init__(
        self,
        tx_id: Optional[str] = None,
        code: int = 0,
        error: Optional["AccumulateError"] = None,
        result: Optional["TransactionResult"] = None,
        received: Optional[int] = None,
        initiator: Optional["URL"] = None,
    ):
        self.tx_id = tx_id
        self.code = code
        self.error = error
        self.result = result
        self.received = received
        self.initiator = initiator
        self.signers: List["Signer"] = []

    def type(self) -> TransactionType:
        return TransactionType.TRANSACTION_STATUS

    def to_dict(self) -> dict:
        """Serialize the TransactionStatus to a dictionary."""
        return {
            "tx_id": self.tx_id,
            "code": self.code,
            "error": str(self.error) if self.error else None,
            "result": self.result.to_dict() if self.result else None,
            "received": self.received,
            "initiator": str(self.initiator) if self.initiator else None,
            "signers": [signer.to_dict() for signer in self.signers] if self.signers else [],
        }

    def marshal(self) -> bytes:
        """Serialize TransactionStatus to bytes using Accumulate encoding."""
        print("DEBUG: Marshaling TransactionStatus")

        # Serialize tx_id (string with length prefix)
        tx_id_data = string_marshal_binary(self.tx_id) if self.tx_id else b""

        # Serialize code (varint)
        code_data = encode_uvarint(self.code)

        # Serialize error (string with length prefix)
        error_data = string_marshal_binary(str(self.error)) if self.error else b""

        # Serialize result (JSON-like structure)
        result_data = bytes_marshal_binary(json.dumps(self.result.to_dict()).encode()) if self.result else b""

        # Serialize received timestamp (varint)
        received_data = encode_uvarint(self.received) if self.received else b""

        # Serialize initiator (URL as string)
        initiator_data = string_marshal_binary(str(self.initiator)) if self.initiator else b""

        # Serialize signers (list of signers)
        signers_data = b"".join([signer.marshal() for signer in self.signers])
        signers_length = encode_uvarint(len(self.signers))  # Prefix with number of signers

        # Combine all components
        serialized = (
            tx_id_data + code_data + error_data + result_data +
            received_data + initiator_data + signers_length + signers_data
        )

        print(f"DEBUG: Marshaled TransactionStatus: {serialized.hex()}")
        return serialized

    @staticmethod
    def unmarshal(data: bytes) -> "TransactionStatus":
        """Deserialize TransactionStatus from bytes."""
        print("DEBUG: Unmarshaling TransactionStatus")
        reader = io.BytesIO(data)

        # Read tx_id
        tx_id = unmarshal_string(reader.read())

        # Read code (varint)
        code, _ = decode_uvarint(reader.read())

        # Read error
        error_str = unmarshal_string(reader.read())
        error = AccumulateError(error_str) if error_str else None

        # Read result
        result_data = unmarshal_bytes(reader.read())
        result = TransactionResult(json.loads(result_data.decode())) if result_data else None

        # Read received timestamp
        received, _ = decode_uvarint(reader.read())

        # Read initiator
        initiator_str = unmarshal_string(reader.read())
        initiator = URL.parse(initiator_str) if initiator_str else None

        # Read signers
        signers_count, _ = decode_uvarint(reader.read())
        signers = []
        for _ in range(signers_count):
            signer = "Signer".unmarshal(reader.read())
            signers.append(signer)

        print(f"DEBUG: Parsed TransactionStatus: tx_id={tx_id}, code={code}, error={error}, "
              f"result={result}, received={received}, initiator={initiator}, signers={signers}")

        return TransactionStatus(
            tx_id=tx_id, code=code, error=error, result=result,
            received=received, initiator=initiator, signers=signers
        )

    def delivered(self) -> bool:
        return self.code == ErrorCode.OK.value

    def remote(self) -> bool:
        return self.code == ErrorCode.FAILED.value

    def pending(self) -> bool:
        return self.code == ErrorCode.DID_PANIC.value

    def failed(self) -> bool:
        return self.code != ErrorCode.OK.value

    def set(self, error: Optional[AccumulateError]) -> None:
        """Set the error and update the status code based on the provided error."""
        self.error = error
        if error and error.code:
            self.code = error.code.value
        else:
            self.code = ErrorCode.UNKNOWN_ERROR.value

    def as_error(self) -> Optional[Exception]:
        return self.error if self.error else None

    def add_signer(self, url: "URL", version: int) -> None:
        """Add a signer dynamically."""
        signer = get_signer()(url, version)
        existing = next((s for s in self.signers if s.get_url() == signer.get_url()), None)
        if not existing or signer.get_version() > existing.get_version():
            self.signers.append(signer)

    def get_signer(self, url: "URL") -> Optional["Signer"]:
        """Retrieve a signer dynamically"""
        for signer in self.signers:
            if signer.get_url() == url:
                return signer
        return None


class CreateIdentity(TransactionBodyBase):
    """
    Represents a CreateIdentity transaction, where the key hash is automatically derived.
    """

    def __init__(self, url: URL, signer_public_key: bytes, key_book_url: Optional[URL] = None):
        """
        :param url: The URL of the new identity.
        :param signer_public_key: The public key of the principal (used to derive the key hash).
        :param key_book_url: The key book URL (optional).
        """
        if not isinstance(url, URL):
            raise TypeError("url must be an instance of URL.")
        if not isinstance(signer_public_key, bytes) or len(signer_public_key) != 32:
            raise TypeError("signer_public_key must be a 32-byte public key.")
        if key_book_url and not isinstance(key_book_url, URL):
            raise TypeError("keyBookUrl must be an instance of URL if provided.")

        self.url = url
        self.key_hash = hashlib.sha256(signer_public_key).digest()  #  Compute key hash from the public key
        self.key_book_url = key_book_url

    def type(self) -> TransactionType:
        """Return the transaction type in Accumulate's expected format."""
        return TransactionType.CREATE_IDENTITY

    def fields_to_encode(self):
        """Returns the fields to be marshaled in Accumulate format."""
        fields = [
            (1, self.type().value, encode_uvarint),  # Type field (0x01 = CreateIdentity)
            (2, string_marshal_binary(str(self.url)), lambda x: x),  # URL (0x02)
            (3, self.key_hash, bytes_marshal_binary),  # returns (field_num, value, encode_func)
        ]

        if self.key_book_url:
            fields.append((4, string_marshal_binary(str(self.key_book_url)), lambda x: x))  # KeyBookUrl (0x04)

        return fields

    def marshal(self) -> bytes:
        """Encodes the transaction into bytes for submission."""
        serialized = b""
        for field_num, value, encode_func in self.fields_to_encode():
            encoded_value = encode_func(value)
            serialized += field_marshal_binary(field_num, encoded_value)

        return serialized

    def to_dict(self) -> dict:
        """Convert CreateIdentity transaction to a dictionary."""
        return {
            "type": "createIdentity",  #  lowerCamelCase format
            "url": str(self.url),
            "keyHash": self.key_hash.hex(),  #  encode as hex
            "keyBookUrl": str(self.key_book_url) if self.key_book_url else None,
        }

    @classmethod
    def unmarshal(cls, data: bytes) -> "CreateIdentity":
        """Deserialize a CreateIdentity transaction from bytes."""
        reader = io.BytesIO(data)

        # Field 1: Type
        field_id = reader.read(1)
        if field_id != b'\x01':
            raise ValueError("Expected field id 1 for type")
        tx_type = int.from_bytes(reader.read(1), "big")
        if tx_type != TransactionType.CREATE_IDENTITY.value:
            raise ValueError("Invalid transaction type for CreateIdentity")

        # Field 2: URL
        field_id = reader.read(1)
        if field_id != b'\x02':
            raise ValueError("Expected field id 2 for URL")
        url = unmarshal_string(reader)

        # Field 3: Key Hash (Public Key Hash)
        field_id = reader.read(1)
        if field_id != b'\x03':
            raise ValueError("Expected field id 3 for key_hash")
        key_hash = reader.read(32)  #  Read 32-byte key hash

        # Field 4: Key Book URL (Optional)
        key_book_url = None
        if reader.peek(1)[:1] == b'\x04':  #  Peek to check if KeyBookUrl field exists
            reader.read(1)  # Consume field identifier
            key_book_url = unmarshal_string(reader)

        return cls(URL.parse(url), key_hash, URL.parse(key_book_url) if key_book_url else None)

class AddCredits(TransactionBodyBase):
    """
    Represents an AddCredits transaction.
    """

    def __init__(self, client, recipient: Union[str, "URL"], amount: int):
        """
        :param client: Instance of AccumulateClient (can be None when unmarshaling)
        :param recipient: The URL of the account receiving the credits.
        :param amount: The amount of credits to add (in whole credits; this will be multiplied by 1e6).
        """
        self.client = client
        self.oracle = None  # Oracle price will be fetched asynchronously
        self.recipient = self._normalize_recipient(str(recipient))
        self.amount = amount * 2_000_000  # Store amount in microcredits

    async def initialize_oracle(self):
        """Fetch and set the oracle price asynchronously from network status."""
        try:
            status = await self.client.network_status()
            self.oracle = int(status.get("oracle", {}).get("price", 5000))
        except Exception as e:
            logger.error(f"Failed to fetch oracle price: {e}")
            self.oracle = 5000 

    def type(self) -> TransactionType:
        return TransactionType.ADD_CREDITS

    def fields_to_encode(self):
        """Returns the fields to be marshaled."""
        return [
            (1, b'\x0E', lambda x: x),  # Type marker
            (2, self.recipient.encode("utf-8"), lambda x: encode_uvarint(len(x)) + x),  # Recipient
            (3, self.amount, encode_compact_int),  # Amount
            (4, self.oracle if self.oracle is not None else 0, encode_uvarint),  # Oracle price
        ]

    def to_dict(self) -> dict:
        """Convert AddCredits transaction to a dictionary."""
        return {
            **super().to_dict(),
            "recipient": self.recipient,
            "amount": str(self.amount),
            "oracle": self.oracle if self.oracle is not None else 0
        }

    @classmethod
    def unmarshal(cls, data: bytes) -> "AddCredits":
        """Deserialize an AddCredits transaction from bytes."""
        reader = io.BytesIO(data)

        # Field 1: Type marker
        field_id = reader.read(1)
        if field_id != b'\x01':
            raise ValueError("Expected field id 1 for type marker")
        type_marker = reader.read(1)
        if type_marker != b'\x0E':
            raise ValueError("Invalid type marker for AddCredits")

        # Field 2: Recipient
        field_id = reader.read(1)
        if field_id != b'\x02':
            raise ValueError("Expected field id 2 for recipient")
        rec_length = read_uvarint(reader)
        recipient_bytes = reader.read(rec_length)
        recipient = recipient_bytes.decode("utf-8")

        # Field 3: Amount (compact int)
        field_id = reader.read(1)
        if field_id != b'\x03':
            raise ValueError("Expected field id 3 for amount")
        num_bytes_raw = reader.read(1)
        if not num_bytes_raw:
            raise ValueError("Missing compact int length for amount")
        num_bytes = num_bytes_raw[0]
        amount_bytes = reader.read(num_bytes)
        amount = int.from_bytes(amount_bytes, byteorder='big')

        # Field 4: Oracle
        field_id = reader.read(1)
        if field_id != b'\x04':
            raise ValueError("Expected field id 4 for oracle")
        oracle_adjusted = read_uvarint(reader)
        oracle = oracle_adjusted // 100

        # Create instance; note that original amount was multiplied by 2e6
        obj = cls(None, recipient, amount // 2_000_000)
        obj.oracle = oracle
        return obj

    @staticmethod
    def _normalize_recipient(recipient: str) -> str:
        """
        Ensure the recipient is formatted correctly.
        It must start with "acc://", not include ".MAIN", and end with "/acme" (all lowercase).
        """
        recipient = recipient.lower().strip("/")
        if recipient.startswith("acc://"):
            recipient = recipient[6:]
        if not recipient.endswith("/acme"):
            recipient += "/acme"
        return f"acc://{recipient}"
    

class SendTokens(TransactionBodyBase):
    """
    Represents a SendTokens transaction, supporting multiple recipients.
    """

    MICRO_UNITS_PER_ACME = 10**8  # 1 ACME = 100,000,000 micro-units

    def __init__(self, recipients: Optional[List[TokenRecipient]] = None):
        self.recipients = recipients or []

    def add_recipient(self, to: URL, amount: int) -> None:
        """Add a recipient to the transaction, converting ACME to micro-units."""
        if amount <= 0:
            raise ValueError("Amount must be greater than zero")

        #  Convert ACME to micro-units before storing
        micro_units = amount * self.MICRO_UNITS_PER_ACME  

        recipient = TokenRecipient(to, micro_units)
        self.recipients.append(recipient)

    def type(self) -> TransactionType:
        """Return the transaction type."""
        return TransactionType.SEND_TOKENS

    def fields_to_encode(self):
        return [
            (1, self.type().value, encode_uvarint),  # Type field
            (4, self._marshal_recipients(), lambda x: x),  # "to" field (will be wrapped by the generic marshal loop)
        ]

    def _marshal_recipients(self) -> bytes:
        """Encodes the list of TokenRecipients without an extra field wrapper.
        
        Returns a varint length prefix followed by the concatenated recipient fields.
        """
        recipients_encoded = b"".join([
            field_marshal_binary(1, string_marshal_binary(str(recipient.url))) +
            field_marshal_binary(2, big_number_marshal_binary(recipient.amount))  # Now stores micro-units
            for recipient in self.recipients
        ])
        length_prefix = encode_uvarint(len(recipients_encoded))
        return length_prefix + recipients_encoded

    def to_dict(self) -> dict:
        """Convert SendTokens transaction to a dictionary."""
        return {
            **super().to_dict(),
            "to": [recipient.to_dict() for recipient in self.recipients]
        }

    @classmethod
    def unmarshal(cls, data: bytes) -> "SendTokens":
        """Deserialize a SendTokens transaction from bytes."""
        reader = io.BytesIO(data)
        recipients = []

        # Field 1: Type (should be "sendTokens")
        field_id = reader.read(1)
        if field_id != b'\x01':
            raise ValueError("Expected field id 1 for type")
        type_value = unmarshal_string(reader)
        if type_value != "sendTokens":
            raise ValueError("Invalid type marker for SendTokens")

        # Field 4: Recipients
        while reader.read(1) == b'\x04':  # Check if the next field is 'to'
            # Field 1: URL
            field_id = reader.read(1)
            if field_id != b'\x01':
                raise ValueError("Expected field id 1 for recipient URL")
            recipient_url = unmarshal_string(reader)

            # Field 2: Amount (micro-units)
            field_id = reader.read(1)
            if field_id != b'\x02':
                raise ValueError("Expected field id 2 for recipient amount")
            recipient_amount = int.from_bytes(unmarshal_bytes(reader), byteorder='big')

            recipients.append(TokenRecipient(URL.parse(recipient_url), recipient_amount))

        return cls(recipients)
    

class CreateDataAccount(TransactionBodyBase):
    """
    Represents a Create Data Account transaction.
    """

    def __init__(self, url: URL, authorities: Optional[List[URL]] = None, metadata: Optional[bytes] = None):
        """
        :param url: The URL of the data account.
        :param authorities: List of authority URLs (optional).
        :param metadata: Optional metadata as bytes (optional).
        """
        if not isinstance(url, URL):
            raise TypeError("url must be an instance of URL.")
        if not url.authority or not url.path:
            raise ValueError(f"Invalid URL: {url}")

        #  Only set authorities if they exist
        self.authorities = authorities if authorities else None  
        self.url = url
        self.metadata = metadata if metadata else None  #  Only set metadata if provided

    def type(self) -> TransactionType:
        """Return transaction type."""
        return TransactionType.CREATE_DATA_ACCOUNT

    def fields_to_encode(self):
        """
        Returns the fields to encode as a list of (field_id, value, encoding_function).
        """
        fields = [
            #  encode type field first
            (1, encode_uvarint(self.type().value), lambda x: x),  

            #  encode URL without double length prefix
            (2, string_marshal_binary(str(self.url)), lambda x: x),  
        ]

        #  Include authorities **only if they exist**
        if self.authorities:
            authorities_encoded = b"".join([
                string_marshal_binary(str(auth))
                for auth in self.authorities
            ])
            fields.append((3, encode_uvarint(len(self.authorities)) + authorities_encoded, lambda x: x))  

        #  Include metadata **only if it exists**
        if self.metadata:
            fields.append((4, bytes_marshal_binary(self.metadata), lambda x: x))  

        return fields

    @classmethod
    def unmarshal(cls, data: bytes) -> "CreateDataAccount":
        """Deserialize CreateDataAccount transaction from bytes."""
        print(f"DEBUG: Unmarshaling CreateDataAccount")

        reader = io.BytesIO(data)

        #  Step 1: Parse Type Field
        type_value = read_uvarint(reader)

        #  Step 2: Parse URL (Read as a string)
        url = unmarshal_string(reader)

        #  Step 3: Parse Authorities (If present)
        authorities = []
        if reader.peek(1)[:1] == b'\x03':  # Check if Authorities field exists
            reader.read(1)  # Consume field identifier
            authorities_count = read_uvarint(reader)
            for _ in range(authorities_count):
                auth_str = unmarshal_string(reader)
                authorities.append(URL.parse(auth_str))

        #  Step 4: Parse Metadata (If present)
        metadata = None
        if reader.peek(1)[:1] == b'\x04':  # Check if Metadata field exists
            reader.read(1)  # Consume field identifier
            metadata = unmarshal_bytes(reader)

        print(f"DEBUG: Parsed CreateDataAccount: Type={type_value}, URL={url}, Authorities={authorities}, Metadata={metadata}")
        return cls(URL.parse(url), authorities if authorities else None, metadata)

    def to_dict(self) -> dict:
        """Convert CreateDataAccount transaction to a dictionary."""
        tx_dict = {
            **super().to_dict(),
            "url": str(self.url),
        }

        #  **Only add authorities if they exist**
        if self.authorities:
            tx_dict["authorities"] = [str(auth) for auth in self.authorities]

        #  **Only add metadata if it exists**
        if self.metadata:
            tx_dict["metadata"] = self.metadata.hex()

        return tx_dict
    

class CreateTokenAccount(TransactionBodyBase):
    """
    Represents a Create Token Account transaction.
    """

    def __init__(self, url: URL, token_url: URL, authorities: Optional[List[URL]] = None):
        """
        :param url: The URL of the token account.
        :param token_url: The URL of the token issuer.
        :param authorities: List of authorities for the token account (optional).
        """
        if not isinstance(url, URL):
            raise TypeError("url must be an instance of URL.")
        if not isinstance(token_url, URL):
            raise TypeError("token_url must be an instance of URL.")

        self.url = url
        self.token_url = token_url
        self.authorities = authorities if authorities else None  # Set to None if empty

    def type(self) -> TransactionType:
        """Return transaction type."""
        return TransactionType.CREATE_TOKEN_ACCOUNT

    def fields_to_encode(self):
        """
        Returns the fields to encode as a list of (field_id, value, encoding_function).
        """
        fields = [
            #  **encode Type Field (Field 1)**
            (1, encode_uvarint(self.type().value), lambda x: x),  # Type (0x01)

            #  **field order (URL first, then Token URL)**
            (2, string_marshal_binary(str(self.url)), lambda x: x),  # URL (0x02)
            (3, string_marshal_binary(str(self.token_url)), lambda x: x),  # Token URL (0x03)
        ]

        #  Only include authorities if provided
        if self.authorities:
            authorities_encoded = b"".join([
                string_marshal_binary(str(auth)) for auth in self.authorities
            ])
            fields.append((4, encode_uvarint(len(self.authorities)) + authorities_encoded, lambda x: x))  # Authorities (0x04)

        return fields

    @classmethod
    def unmarshal(cls, data: bytes) -> "CreateTokenAccount":
        """Deserialize CreateTokenAccount transaction from bytes."""
        reader = io.BytesIO(data)

        #  Step 1: Parse Type Field (Required)
        type_value = read_uvarint(reader)  # Read type value

        #  Step 2: Parse URL
        url_str = unmarshal_string(reader)
        url = URL.parse(url_str)

        #  Step 3: Parse Token URL
        token_url_str = unmarshal_string(reader)
        token_url = URL.parse(token_url_str)

        #  Step 4: Parse Authorities (if present)
        authorities = []
        if reader.peek(1)[:1] == b'\x04':  # Check if Authorities field exists
            reader.read(1)  # Consume field identifier
            authorities_count = read_uvarint(reader)  # Read count
            for _ in range(authorities_count):
                auth_str = unmarshal_string(reader)
                authorities.append(URL.parse(auth_str))

        return cls(url, token_url, authorities if authorities else None)  # Set to None if empty

    def to_dict(self) -> dict:
        """Convert CreateTokenAccount transaction to a dictionary."""
        tx_dict = {
            **super().to_dict(),
            "url": str(self.url),
            "tokenUrl": str(self.token_url),
        }

        #  Only include authorities in dict if it's not empty
        if self.authorities:
            tx_dict["authorities"] = [str(auth) for auth in self.authorities]

        return tx_dict


class WriteData(TransactionBodyBase):
    """
    Represents a Write Data transaction.
    """

    def __init__(self, entry: DataEntry, scratch: Optional[bool] = None, write_to_state: Optional[bool] = None):
        """
        :param entry: The data entry (must be `AccumulateDataEntry` or `DoubleHashDataEntry`).
        :param scratch: Flag indicating whether it's a scratch write.
        :param write_to_state: Flag indicating whether it writes to state.
        """
        if not isinstance(entry, (AccumulateDataEntry, DoubleHashDataEntry)):  #  Support multiple types
            raise TypeError("entry must be an instance of AccumulateDataEntry or DoubleHashDataEntry.")

        self.entry = entry
        self.scratch = scratch if scratch is not None else False
        self.write_to_state = write_to_state if write_to_state is not None else False

    def type(self) -> TransactionType:
        """Return transaction type."""
        return TransactionType.WRITE_DATA


    def fields_to_encode(self):
        #  Step 1: Marshal the entry as a length-prefixed structure
        entry_marshal = self.entry.marshal()

        #   Prefix the entry with total length (no extra `+ 1`)
        entry_length = encode_uvarint(len(entry_marshal))  #  length prefix
        entry_encoded = entry_length + entry_marshal  #  No extra nested field

        fields = [
            (1, encode_uvarint(self.type().value), lambda x: x),  #  Transaction Type
            (2, entry_encoded, lambda x: x),  #  Marshal entire entry properly
        ]

        #  Only include scratch if True
        if self.scratch:
            fields.append((3, boolean_marshal_binary(self.scratch), lambda x: x))

        #  Only include writeToState if False
        if not self.write_to_state:
            fields.append((4, boolean_marshal_binary(self.write_to_state), lambda x: x))

        return fields


    def marshal_without_entry(self) -> bytes:
        """
        Marshal WriteData without the `entry` field.
        Needed to match Go SDK hashing logic.
        """
        logger.debug(" Marshaling WriteData WITHOUT Entry Field")

        serialized = b""
        fields = [
            (1, encode_uvarint(self.type().value), lambda x: x),  #  Type field
        ]

        if self.scratch:
            fields.append((3, boolean_marshal_binary(self.scratch), lambda x: x))

        if not self.write_to_state:
            fields.append((4, boolean_marshal_binary(self.write_to_state), lambda x: x))

        #  Debugging: Log each field separately
        for field_num, value, encode_func in fields:
            encoded_value = encode_func(value)
            logger.debug(f" Encoding Field {field_num}: {encoded_value.hex() if isinstance(encoded_value, bytes) else encoded_value}")
            serialized += field_marshal_binary(field_num, encoded_value)

        logger.debug(f" FINAL Marshaled WriteData WITHOUT Entry (HEX): {serialized.hex()}")

        return serialized


    @classmethod
    def unmarshal(cls, data: bytes) -> "WriteData":
        """Deserialize WriteData transaction from bytes."""
        logger.debug(f" Unmarshaling WriteData")

        reader = io.BytesIO(data)

        #  Step 1: Read Type Field
        type_value = read_uvarint(reader)

        #  Step 2: Read and Unmarshal Data Entry
        entry_data = unmarshal_bytes(reader)
        entry = DataEntry.unmarshal(entry_data)  #  Use DataEntry unmarshal to detect type

        #  Step 3: Read Boolean Flags
        scratch_flag = bool(reader.read(1)[0])  # Read single byte for scratch flag
        state_flag = bool(reader.read(1)[0])  # Read single byte for write_to_state flag

        logger.debug(f" Parsed WriteData: type={type_value}, scratch={scratch_flag}, write_to_state={state_flag}, entry={entry}")
        return cls(entry, scratch_flag, state_flag)

    def to_dict(self) -> dict:
        """
         Convert WriteData transaction to a dictionary, ensuring that default values (scratch=False, writeToState=True) are omitted.
        """
        data = {
            **super().to_dict(),
            "entry": self.entry.to_dict(),
        }

        #  Only include `scratch` if True
        if self.scratch:
            data["scratch"] = self.scratch

        #  Only include `writeToState` if False
        if not self.write_to_state:
            data["writeToState"] = self.write_to_state

        return data


    def hash_tree(self) -> bytes:
        """
        Compute the Merkle tree hash of the data entry.
        Go SDK uses `sha256(sha256(MerkleRoot(entry_data)))`
        """
        logger.debug(" Computing Merkle Tree Hash for Entry Data")
        
        #  Compute initial SHA-256 hashes of each chunk
        data_hashes = [hashlib.sha256(chunk).digest() for chunk in self.entry.get_data()]
        
        #  Compute the Merkle root
        if len(data_hashes) == 1:
            merkle_root = data_hashes[0]
        else:
            while len(data_hashes) > 1:
                temp_hashes = []
                for i in range(0, len(data_hashes), 2):
                    if i + 1 < len(data_hashes):
                        combined = data_hashes[i] + data_hashes[i + 1]
                    else:
                        combined = data_hashes[i]  # Handle odd number of elements
                    temp_hashes.append(hashlib.sha256(combined).digest())
                data_hashes = temp_hashes
            merkle_root = data_hashes[0]

        #  Double-hash the Merkle root for `DoubleHashDataEntry`
        final_hash = hashlib.sha256(merkle_root).digest()
        logger.debug(f" Merkle Root SHA-256 Hash: {merkle_root.hex()}")
        logger.debug(f" FINAL Double Hash (SHA-256): {final_hash.hex()}")

        return final_hash


@dataclass
class CreateKeyPage(TransactionBodyBase):
    """
    Represents a Create Key Page transaction.
    """
    keys: List[KeySpecParams]

    def type(self) -> TransactionType:
        return TransactionType.CREATE_KEY_PAGE

    def fields_to_encode(self):
        """
        Define the fields to encode, following structured encoding.
        """
        # Marshal each key (each key's marshal() already adds its own field prefix)
        encoded_keys = b"".join([key.marshal() for key in self.keys])
        logger.debug(f"Encoded keys (hex): {encoded_keys.hex()}")
        logger.debug(f"Encoded keys length: {len(encoded_keys)} bytes")
        
        # Manually prepend the varint-encoded length of the concatenated keys
        keys_value = encode_uvarint(len(encoded_keys)) + encoded_keys
        
        # The generic marshal will wrap each value with its field number.
        fields = [
            (1, encode_uvarint(self.type().value), lambda x: x),  # Field 1: Transaction Type
            (2, keys_value, lambda x: x),                         # Field 2: Keys (with length prefix)
        ]
        return fields

    def to_dict(self) -> dict:
        """Convert transaction to a dictionary with correct type formatting, including keys."""
        return {
            "type": self._format_transaction_type(self.type().name),
            "keys": [{"keyHash": key.key_hash.hex()} for key in self.keys]
        }

    @classmethod
    def unmarshal(cls, data: bytes) -> "CreateKeyPage":
        logger.debug(f" Unmarshaling CreateKeyPage")
        reader = io.BytesIO(data)
        # Read the keys field: first, the varint length, then the concatenated key bytes
        keys_length = read_uvarint(reader)
        keys_data = reader.read(keys_length)
        
        # To extract individual keys, we assume they were marshaled sequentially
        # (If multiple keys were present, you might need to loop until keys_data is exhausted)
        # For this example, we assume a single key or that you have a known count
        # Here, we assume the count equals the number of keys concatenated
        # (For a robust implementation, include a count field)
        keys = []
        sub_reader = io.BytesIO(keys_data)
        while sub_reader.tell() < len(keys_data):
            key_bytes = unmarshal_bytes(sub_reader)
            keys.append(KeySpecParams.unmarshal(key_bytes))
        
        logger.debug(f" Parsed CreateKeyPage: keys={keys}")
        return cls(keys)


@dataclass
class CreateKeyBook(TransactionBodyBase):
    """
    Represents a Create Key Book transaction.
    """
    url: URL
    public_key_hash: bytes  # Must be exactly 32 bytes
    authorities: Optional[List[URL]] = None

    def type(self) -> TransactionType:
        return TransactionType.CREATE_KEY_BOOK

    def fields_to_encode(self):
        """
        Build the fields as follows:
          Field 1: Transaction type (as a varint)
          Field 2: URL (with a length prefix added by string_marshal_binary)
          Field 3: publicKeyHash (with a length prefix, which should be 0x20)
          Optionally, if authorities are provided, include them as fields 4 and 5
        """
        fields = [
            # Field 1: Transaction type (e.g. 0x0d)
            (1, encode_uvarint(self.type().value), lambda x: x),
            # Field 2: URL – string_marshal_binary automatically prepends the length
            (2, string_marshal_binary(str(self.url)), lambda x: x),
            # Field 3: publicKeyHash – hash_marshal_binary checks length (must be 32)
            (3, bytes_marshal_binary(self.public_key_hash), lambda x: x),
        ]
        if self.authorities:
            # Authorities count
            authorities_count = encode_uvarint(len(self.authorities))
            # Encode each authority URL.
            encoded_auths = b"".join([string_marshal_binary(str(auth)) for auth in self.authorities])
            fields.append((4, authorities_count, lambda x: x))
            fields.append((5, encoded_auths, lambda x: x))
        return fields

    def to_dict(self) -> dict:
        """Convert transaction body to a JSON‑serializable dictionary"""
        tx_dict = {
            "type": self._format_transaction_type(self.type().name),
            "url": str(self.url),
            "publicKeyHash": self.public_key_hash.hex(),
        }
        if self.authorities:
            tx_dict["authorities"] = [str(auth) for auth in self.authorities]
        return tx_dict

    @classmethod
    def unmarshal(cls, data: bytes) -> "CreateKeyBook":
        logger.debug(" Unmarshaling CreateKeyBook")
        reader = io.BytesIO(data)
        # Read URL field (field 2)
        url = URL.parse(unmarshal_bytes(reader).decode("utf-8"))
        # Read publicKeyHash field (field 3)
        public_key_hash = reader.read(32)
        if len(public_key_hash) != 32:
            raise ValueError("Invalid public key hash length (must be 32 bytes)")
        authorities = []
        if reader.tell() < len(data):
            authorities_count = read_uvarint(reader)
            for _ in range(authorities_count):
                auth_url = unmarshal_bytes(reader).decode("utf-8")
                authorities.append(URL.parse(auth_url))
        logger.debug(f" Parsed CreateKeyBook: URL={url}, PublicKeyHash={public_key_hash.hex()}, Authorities={authorities}")
        return cls(url, public_key_hash, authorities)

@dataclass
class UpdateKeyPage(TransactionBodyBase):
    """
    Represents an Update Key Page transaction.
    """
    url: URL
    operations: List[Dict[str, Dict[str, bytes]]]  #  encodes `entry` inside `operation`

    def type(self) -> TransactionType:
        return TransactionType.UPDATE_KEY_PAGE

    def fields_to_encode(self):
        """
        Define the fields to encode for the transaction.
        """
        fields = [
            # Field 1: Transaction type (updateKeyPage) – encoded as a varint
            (1, encode_uvarint(self.type().value), lambda x: x),
            # Field 2: Operations – marshaled as a length-prefixed list
            (2, self._marshal_operations(), lambda x: x),
        ]
        return fields

    def _marshal_operations(self) -> bytes:
        ops = [self._marshal_operation(op) for op in self.operations]
        operations_data = b"".join(ops)
        operations_length = encode_uvarint(len(operations_data))
        return operations_length + operations_data

    @staticmethod
    def _marshal_operation(operation: Dict[str, Any]) -> bytes:
        """
        Serialize an operation dictionary into bytes.
        Handles standard operations (with keyHash or delegate), threshold operations 
        (setThreshold, setRejectThreshold, setResponseThreshold) and update operations.
        """
        op_type_lower = operation["type"].lower()
        
        if op_type_lower in ["setthreshold", "setrejectthreshold", "setresponsethreshold"]:
            # For threshold operations, return only the inner payload
            numeric_value = operation.get("threshold")
            if numeric_value is None:
                raise ValueError("Missing threshold value for threshold operation.")
            # payload: Tag 0x01, fixed length 0x04, then Tag 0x02 followed by encode_uvarint(numeric_value)
            # For example, for numeric_value = 2 (and if encode_uvarint(2) returns b'\x02')
            # this produces: b'\x01' + b'\x04' + b'\x02' + b'\x02' → hex: 01 04 02 02
            return b'\x01' + b'\x04' + b'\x02' + encode_uvarint(numeric_value)
        
        elif op_type_lower == "update":
            # Handle update operations normally.
            op_type = b'\x01' + encode_uvarint(KeyPageOperationType["UPDATE"].value)
            old_entry = operation.get("oldEntry")
            new_entry = operation.get("newEntry")
            if not old_entry or not new_entry or "keyHash" not in old_entry or "keyHash" not in new_entry:
                raise ValueError("Invalid update operation: must contain both 'oldEntry' and 'newEntry' with a 'keyHash'.")
            old_data = b'\x01' + encode_uvarint(32) + old_entry["keyHash"]
            new_data = b'\x01' + encode_uvarint(32) + new_entry["keyHash"]
            old_field = b'\x02' + encode_uvarint(len(old_data)) + old_data
            new_field = b'\x03' + encode_uvarint(len(new_data)) + new_data
            return op_type + old_field + new_field
        
        else:
            # For standard operations.
            op_type = b'\x01' + encode_uvarint(KeyPageOperationType[operation["type"].upper()].value)
            entry = operation.get("entry", {})
            if "keyHash" in entry:
                key_data = b'\x01' + encode_uvarint(32) + entry["keyHash"]
            elif "delegate" in entry:
                delegate_data = string_marshal_binary(entry["delegate"])
                key_data = b'\x02' + delegate_data
            else:
                raise ValueError("Invalid operation entry: must contain either 'keyHash' or 'delegate'.")
            entry_field = b'\x02' + encode_uvarint(len(key_data)) + key_data
            return op_type + entry_field





    def to_dict(self) -> dict:
        """Convert transaction body to a JSON‑serializable dictionary."""
        op_list = []
        for operation in self.operations:
            op_type = operation["type"].lower()
            if op_type == "update":
                op_list.append({
                    "type": "update",
                    "oldEntry": {"keyHash": operation["oldEntry"]["keyHash"].hex()},
                    "newEntry": {"keyHash": operation["newEntry"]["keyHash"].hex()}
                })
            elif op_type in ["setthreshold", "setrejectthreshold", "setresponsethreshold"]:
                # For threshold operations, check top-level threshold.
                numeric_value = operation.get("threshold")
                if numeric_value is None:
                    numeric_value = operation.get("entry", {}).get("threshold")
                if numeric_value is None:
                    raise ValueError("Missing threshold value in operation.")
                if op_type == "setthreshold":
                    op_name = "setThreshold"
                elif op_type == "setrejectthreshold":
                    op_name = "setRejectThreshold"
                elif op_type == "setresponsethreshold":
                    op_name = "setResponseThreshold"
                op_list.append({
                    "type": op_name,
                    "threshold": numeric_value
                })
            else:
                op_list.append({
                    "type": operation["type"],
                    "entry": (
                        {"keyHash": operation["entry"]["keyHash"].hex()}
                        if "keyHash" in operation["entry"]
                        else {"delegate": operation["entry"]["delegate"]}
                    ),
                })
        return {
            "type": self._format_transaction_type(self.type().name),
            "operation": op_list,
        }




    @classmethod
    def unmarshal(cls, data: bytes) -> "UpdateKeyPage":
        """Deserialize UpdateKeyPage transaction from bytes."""
        logger.debug(f" Unmarshaling UpdateKeyPage: {data.hex()}")

        reader = io.BytesIO(data)

        # Step 1: Read URL
        url = URL.parse(unmarshal_bytes(reader).decode("utf-8"))

        # Step 2: Read Operations
        operations_length, _ = read_uvarint(reader)  # Read length prefix
        operations_data = reader.read(operations_length)  # Read operations
        operations = cls._unmarshal_operations(operations_data)

        logger.debug(f" Parsed UpdateKeyPage: URL={url}, Operations={operations}")
        return cls(url, operations)


    @staticmethod
    def _unmarshal_operations(data: bytes) -> List[Dict[str, Dict[str, bytes]]]:
        """Deserialize operations from a byte stream."""
        operations = []
        reader = io.BytesIO(data)

        while reader.tell() < len(data):
            # Extract operation type (as an int)
            operation_type, _ = read_uvarint(reader)

            # Extract entry
            entry = {}
            # Peek at the next byte to determine the entry type
            entry_type_byte, _ = read_uvarint(reader)
            if entry_type_byte == 1:  # KeyHash
                key_hash = reader.read(32)
                if len(key_hash) != 32:
                    raise ValueError("Invalid keyHash length (must be 32 bytes).")
                entry["keyHash"] = key_hash
            elif entry_type_byte == 2:  # Delegate
                delegate_url = unmarshal_bytes(reader).decode("utf-8")
                entry["delegate"] = delegate_url
            elif entry_type_byte == 3:  # Numeric value (e.g., threshold)
                # Decode numeric value (assuming uvarint)
                numeric_value, _ = read_uvarint(reader)
                # You will need to decide which numeric key to use based on the operation type
                # For simplicity, we'll set "threshold". In a complete implementation, check operation type
                entry["threshold"] = numeric_value
            else:
                raise ValueError("Unknown entry type in UpdateKeyPage.")
            
            # Wrap the operation in a dictionary; here we assume non-update operations
            # For update operations, you’d handle them separately
            operations.append({
                "type": KeyPageOperationType(operation_type).name.lower(),
                "entry": entry
            })

        return operations

@dataclass
class UpdateAccountAuth(TransactionBodyBase):
    """
    Represents an Update Account Auth transaction.
    """
    account_url: URL
    operations: List[Dict[str, str]]  # Each dict must have keys "type" and "authority"

    def type(self) -> TransactionType:
        return TransactionType.UPDATE_ACCOUNT_AUTH

    def fields_to_encode(self):
        """
        Field 1: Transaction type as a varint.
        Field 2: Operations as a length-prefixed list.
        """
        fields = [
            # Field 1: Transaction type (updateAccountAuth) encoded as a varint
            (1, encode_uvarint(self.type().value), lambda x: x),
            # Field 2: Operations
            (2, self._marshal_operations(), lambda x: x) if self.operations else None,
        ]
        return [field for field in fields if field is not None]

    def _marshal_operations(self) -> bytes:
        """Serialize operations as a length-prefixed binary format."""
        if not self.operations:
            return b""
        operations_data = b"".join([self._marshal_operation(op) for op in self.operations])
        operations_length = encode_uvarint(len(operations_data))
        return operations_length + operations_data

    @staticmethod
    def _marshal_operation(operation: Dict[str, str]) -> bytes:
        """
        Serialize a single operation into bytes.
        Expected structure for addAuthority:
          - Nested field 1 (tag 0x01): Operation type (varint).
          - Nested field 2 (tag 0x02): Authority (length-prefixed string).
        """
        if "type" not in operation or "authority" not in operation:
            raise ValueError(f"Invalid operation entry: missing 'type' or 'authority' field in {operation}")

        # Normalize and lookup the enum value.
        normalized_type = normalize_operation_type(operation["type"])
        try:
            operation_type_enum = AccountAuthOperationType[normalized_type]
        except KeyError as e:
            raise ValueError(f"Operation type '{operation.get('type')}' is not valid: {e}")

        # Nested field 1: Operation type (tag 0x01)
        op_type_field = b'\x01' + encode_uvarint(operation_type_enum.value)
        # Nested field 2: Authority (tag 0x02, using string_marshal_binary for proper length prefix)
        auth_field = b'\x02' + string_marshal_binary(operation["authority"])
        return op_type_field + auth_field

    def to_dict(self) -> dict:
        """Convert transaction body to a JSON‑serializable dictionary."""
        return {
            "type": self._format_transaction_type(self.type().name),
            "operations": [
                {
                    "type": operation["type"],
                    "authority": operation["authority"]
                }
                for operation in self.operations
            ],
        }

    @classmethod
    def unmarshal(cls, data: bytes) -> "UpdateAccountAuth":
        """Deserialize UpdateAccountAuth transaction from bytes."""
        logger.debug(f" Unmarshaling UpdateAccountAuth: {data.hex()}")
        reader = io.BytesIO(data)

        # Field 1: Transaction type (we ignore the value here)
        _ = decode_uvarint(unmarshal_bytes(reader))
        # Field 2: Operations
        operations_length, _ = decode_uvarint(reader.read())
        operations_data = reader.read(operations_length)
        operations = cls._unmarshal_operations(operations_data)
        logger.debug(f" Parsed UpdateAccountAuth: Operations={operations}")
        # The account_url is not encoded in the body, it is typically set in the header
        return cls(account_url=None, operations=operations)  # account_url may be set elsewhere

    @staticmethod
    def _unmarshal_operations(data: bytes) -> List[Dict[str, str]]:
        """Deserialize operations from a byte stream."""
        operations = []
        reader = io.BytesIO(data)
        while reader.tell() < len(data):
            # Nested field 1: Operation type
            op_type = decode_uvarint(reader.read())[0]
            op_type_str = AccountAuthOperationType(op_type).name.lower()
            # Nested field 2: Authority
            authority = unmarshal_bytes(reader).decode("utf-8")
            operations.append({"type": op_type_str, "authority": authority})
        return operations

class CreateToken(TransactionBodyBase):
    """
    Represents a Create Token transaction.
    """

    def __init__(self, url: URL, symbol: str, precision: int, supply_limit: Optional[int] = None, authorities: Optional[List[URL]] = None):
        if not isinstance(url, URL):
            raise TypeError("url must be an instance of URL.")
        if not isinstance(symbol, str) or not symbol:
            raise ValueError("symbol must be a non-empty string.")
        if not isinstance(precision, int) or not (0 <= precision <= 18):
            raise ValueError("precision must be an integer between 0 and 18.")
        if supply_limit is not None and not isinstance(supply_limit, int):
            raise ValueError("supplyLimit must be an integer or None.")

        self.url = url
        self.symbol = symbol
        self.precision = precision
        self.supply_limit = supply_limit  # Original (provided-readable) supply limit
        # Dynamically adjust the supplyLimit: multiply by 10^precision
        self.adjusted_supply_limit = supply_limit * (10 ** precision) if supply_limit is not None else None
        self.authorities = authorities or []

    def type(self) -> TransactionType:
        return TransactionType.CREATE_TOKEN

    def _encode_supply_limit(self) -> bytes:
        """
        Encode the adjusted supply limit using a variable-length encoding.
        First, compute the minimal number of bytes needed to represent the adjusted value,
        then prefix that with its length encoded as a varint.
        """
        value = self.adjusted_supply_limit
        # Determine the minimum number of bytes (at least 1)
        num_bytes = (value.bit_length() + 7) // 8 or 1
        supply_bytes = value.to_bytes(num_bytes, byteorder="big")
        return encode_uvarint(num_bytes) + supply_bytes

    def fields_to_encode(self):
        """
        Expected official encoding:
          Field 1: Transaction Type (CREATE_TOKEN) -> 01 08
          Field 2: Token URL -> 02 + length + url bytes
          Field 4: Symbol -> 04 + length + symbol bytes
          Field 5: Precision -> 05 + varint(precision)
          Field 7: Supply Limit -> 07 + (length varint + supply limit bytes) [variable length]
          Field 9: Authorities -> if provided.
        """
        fields = [
            (1, encode_uvarint(self.type().value), lambda x: x),  # Transaction Type
            (2, string_marshal_binary(str(self.url)), lambda x: x),  # Token URL
            (4, string_marshal_binary(self.symbol), lambda x: x),  # Symbol
            (5, encode_uvarint(self.precision), lambda x: x),  # Precision
            (7, self._encode_supply_limit(), lambda x: x) if self.adjusted_supply_limit is not None else None,
            (9, b"".join([string_marshal_binary(str(auth)) for auth in self.authorities]), lambda x: x) if self.authorities else None,
        ]
        return [field for field in fields if field is not None]

    def to_dict(self) -> dict:
        """
        Convert the transaction into a JSON-compatible dictionary.
        Outputs the dynamically adjusted supply limit (the on-chain value).
        """
        data = {
            "type": self._format_transaction_type(self.type().name),
            "url": str(self.url),
            "symbol": self.symbol,
            "precision": self.precision
        }
        if self.adjusted_supply_limit is not None:
            data["supplyLimit"] = str(self.adjusted_supply_limit)
        if self.authorities:
            data["authorities"] = [str(auth) for auth in self.authorities]
        return data

    @classmethod
    def unmarshal(cls, data: bytes) -> "CreateToken":
        """
        Deserialize CreateToken transaction from bytes.
        """
        reader = io.BytesIO(data)

        # Step 1: Parse Transaction Type (should be CREATE_TOKEN)
        transaction_type, _ = decode_uvarint(reader.read())
        if transaction_type != TransactionType.CREATE_TOKEN.value:
            raise ValueError(f"Unexpected transaction type: {transaction_type}")

        # Step 2: Parse Token URL
        token_url = URL.parse(unmarshal_bytes(reader).decode("utf-8"))

        # Step 3: Parse Symbol
        symbol = unmarshal_bytes(reader).decode("utf-8")

        # Step 4: Parse Precision
        precision, _ = decode_uvarint(reader.read())

        # Step 5: Parse Supply Limit (if available)
        supply_limit = None
        if reader.tell() < len(data):
            length, _ = decode_uvarint(reader.read())
            # Read 'length' bytes for the adjusted supply limit
            supply_bytes = reader.read(length)
            adjusted_supply_limit = int.from_bytes(supply_bytes, byteorder="big")
            # Convert back to the original supply limit by dividing by 10^precision
            supply_limit = adjusted_supply_limit // (10 ** precision)

        # Step 6: Parse Authorities (if available)
        authorities = []
        while reader.tell() < len(data):
            authorities.append(URL.parse(unmarshal_bytes(reader).decode("utf-8")))

        return cls(token_url, symbol, precision, supply_limit, authorities)

class IssueTokens(TransactionBodyBase):
    """
    Represents an Issue Tokens transaction.
    This version includes only a list of token recipients.
    """

    def __init__(self, recipients: List["TokenRecipient"]):
        """
        :param recipients: A list of TokenRecipient instances.
        """
        if not isinstance(recipients, list) or not all(isinstance(recipient, TokenRecipient) for recipient in recipients):
            raise TypeError("recipients must be a list of TokenRecipient instances.")
        self.recipients = recipients

    def type(self) -> TransactionType:
        return TransactionType.ISSUE_TOKENS

    def fields_to_encode(self):
        """
        Fields for IssueTokens:
          Field 1: Transaction type (encoded as varint).
          Field 4: Recipients (as a length-prefixed list of recipient fields).
        """
        fields = [
            (1, encode_uvarint(self.type().value), lambda x: x),
            (4, self._marshal_recipients(), lambda x: x),
        ]
        return fields

    def _marshal_recipients(self) -> bytes:
        """
        Serialize recipients as a length-prefixed list.
        Each recipient is encoded as:
          - Field 1: URL (as a length-prefixed string)
          - Field 2: Amount (as a big-number, using big_number_marshal_binary)
        The recipient fields are concatenated (without an extra length wrapper per recipient)
        and the entire recipients block is prefixed with a varint length.
        """
        # Encode each recipient without extra wrapping:
        recipient_entries = []
        for recipient in self.recipients:
            # Encode field 1: recipient URL
            url_field = field_marshal_binary(1, string_marshal_binary(str(recipient.url)))
            # Encode field 2: recipient amount
            amount_field = field_marshal_binary(2, big_number_marshal_binary(recipient.amount))
            recipient_entries.append(url_field + amount_field)
        recipients_data = b"".join(recipient_entries)
        length_prefix = encode_uvarint(len(recipients_data))
        return length_prefix + recipients_data

    @classmethod
    def unmarshal(cls, data: bytes) -> "IssueTokens":
        """
        Deserialize IssueTokens transaction from bytes.
        """
        reader = io.BytesIO(data)
        # Field 1: Transaction type
        transaction_type, _ = decode_uvarint(reader.read())
        if transaction_type != TransactionType.ISSUE_TOKENS.value:
            raise ValueError("Unexpected transaction type")
        # Field 4: Recipients list
        recipients_length, _ = decode_uvarint(reader.read())
        recipients_data = reader.read(recipients_length)
        recipients = cls._unmarshal_recipients(recipients_data)
        return cls(recipients)

    @staticmethod
    def _unmarshal_recipients(data: bytes) -> List["TokenRecipient"]:
        """
        Deserialize the recipients list from a byte stream.
        Each recipient is encoded as:
          - Field 1: URL (length-prefixed string)
          - Field 2: Amount (big-number bytes)
        """
        recipients = []
        reader = io.BytesIO(data)
        while reader.tell() < len(data):
            # Expect field id 1 for URL.
            field_id = reader.read(1)
            if field_id != b'\x01':
                raise ValueError("Expected field id 1 for recipient URL")
            recipient_url = unmarshal_string(reader)
            # Expect field id 2 for amount.
            field_id = reader.read(1)
            if field_id != b'\x02':
                raise ValueError("Expected field id 2 for recipient amount")
            recipient_amount = int.from_bytes(unmarshal_bytes(reader), byteorder='big')
            recipients.append(TokenRecipient(URL.parse(recipient_url), recipient_amount))
        return recipients

    def to_dict(self) -> dict:
        """
        Convert the IssueTokens transaction to a JSON‑serializable dictionary.
        The recipients are output under the key "to".
        """
        return {
            "type": self._format_transaction_type(self.type().name),
            "to": [recipient.to_dict() for recipient in self.recipients],
        }

class BurnTokens(TransactionBodyBase):
    """
    Represents a Burn Tokens transaction.
    This class accepts a provided-readable burn amount and then dynamically queries
    the blockchain to obtain the token's precision. It then calculates the final
    on-chain amount to burn.

    The token account URL is provided, and from it the token issuer URL is obtained.
    """

    def __init__(self, token_account_url: URL, provided_amount: int):
        """
        :param token_account_url: The URL of the token account (e.g., acc://.../CTACUST).
        :param provided_amount: The provided-readable number of tokens to burn.
        """
        if not isinstance(token_account_url, URL):
            raise TypeError("token_account_url must be an instance of URL.")
        if not isinstance(provided_amount, int) or provided_amount <= 0:
            raise ValueError("provided_amount must be a positive integer.")
        self.token_account_url = token_account_url
        self.provided_amount = provided_amount
        # These will be set dynamically via initialize()
        self.precision = None  
        self.amount = None  # Final on-chain amount = provided_amount * (10 ** precision)

    def type(self) -> TransactionType:
        return TransactionType.BURN_TOKENS

    async def initialize(self, client):
        """
        Dynamically query the token account and token issuer to obtain the token's precision,
        then calculate the final on-chain burn amount.
        """
        # Use the Query object as in your working example.
        from accumulate.models.queries import Query
        from accumulate.models.enums import QueryType
        query = Query(query_type=QueryType.DEFAULT)

        # Query the token account to get the token issuer URL.
        token_account_response = await client.query(str(self.token_account_url), query)
        token_issuer_url_str = token_account_response.account.get("tokenUrl")
        if not token_issuer_url_str:
            raise ValueError("Token account did not return a tokenUrl")
        token_issuer_url = URL.parse(token_issuer_url_str)

        # Query the token issuer to obtain the token's precision.
        token_issuer_response = await client.query(str(token_issuer_url), query)
        precision = token_issuer_response.account.get("precision")
        if precision is None:
            raise ValueError("Token issuer did not return a precision value")
        self.precision = int(precision)

        # Calculate the final on-chain amount.
        self.amount = self.provided_amount * (10 ** self.precision)

    def _encode_amount(self) -> bytes:
        """
        Encodes the final amount as a raw big-endian number.
        For example, if the final amount is 110000, then:
          big_number_marshal_binary(110000) should yield its minimal big-endian representation.
        """
        if self.amount is None:
            raise ValueError("BurnTokens instance is not initialized. Call initialize(client) first.")
        return big_number_marshal_binary(self.amount)

    def fields_to_encode(self):
        """
        Fields for BurnTokens:
          - Field 1: Transaction type (encoded as varint)
          - Field 2: Amount (encoded as a length-delimited big-endian number)

         NOTE: The token URL is NOT included in the encoded body.
        """
        return [
            (1, encode_uvarint(self.type().value), lambda x: x),
            (2, self._encode_amount(), lambda x: x),
        ]

    @classmethod
    def unmarshal(cls, data: bytes) -> "BurnTokens":
        """
        Deserialize BurnTokens transaction from bytes.
        (Since precision is not encoded, the returned instance will have token_account_url set to None.)
        """
        reader = io.BytesIO(data)
        transaction_type, _ = decode_uvarint(reader.read())
        if transaction_type != TransactionType.BURN_TOKENS.value:
            raise ValueError("Unexpected transaction type")
        amount_bytes = unmarshal_bytes(reader)
        final_amount = int.from_bytes(amount_bytes, byteorder='big')
        instance = cls(None, final_amount)  # token_account_url is unknown from the body
        instance.precision = 0  # unknown precision
        instance.amount = final_amount
        instance.provided_amount = final_amount  # fallback
        return instance

    def to_dict(self) -> dict:
        """
        Convert the BurnTokens transaction to a JSON-serializable dictionary.
        (Note: the token URL is not included in the output JSON.)
        """
        return {
            "type": self._format_transaction_type(self.type().name),
            "amount": str(self.amount) if self.amount is not None else None,
        }



class TransferCredits(TransactionBodyBase):
    def __init__(self, to: List[CreditRecipient]):
        """
        Represents a Transfer Credits transaction.

        :param to: A list of CreditRecipient objects.
        """
        if not isinstance(to, list) or not all(isinstance(recipient, CreditRecipient) for recipient in to):
            raise TypeError("to must be a list of CreditRecipient instances.")
        self.to = to

    def type(self) -> TransactionType:
        return TransactionType.TRANSFER_CREDITS

    def fields_to_encode(self):
        # TO DO
        # Required by TransactionBodyBase, but we override marshal() directly,
        # so there are no “generic” fields to encode here.
        return []


    def marshal(self) -> bytes:
        """Serialize TransferCredits transaction to bytes."""
        print("DEBUG: Marshaling TransferCredits")

        # Serialize number of recipients
        recipients_count = encode_uvarint(len(self.to))

        # Serialize each recipient
        recipients_data = b"".join([bytes_marshal_binary(recipient.marshal()) for recipient in self.to])

        # Combine all marshaled components
        serialized = recipients_count + recipients_data
        print(f"DEBUG: Marshaled TransferCredits: {serialized.hex()}")
        return serialized

    @staticmethod
    def unmarshal(data: bytes) -> "TransferCredits":
        """Deserialize TransferCredits transaction from bytes."""
        print("DEBUG: Unmarshaling TransferCredits")

        reader = io.BytesIO(data)

        # Read number of recipients
        recipients_count, _ = decode_uvarint(reader.read())

        recipients = []
        for _ in range(recipients_count):
            recipient_length, _ = decode_uvarint(reader.read())  # Read recipient length
            recipient_data = reader.read(recipient_length)  # Read recipient data
            recipients.append(CreditRecipient.unmarshal(recipient_data))

        print(f"DEBUG: Parsed TransferCredits: recipients={recipients}")
        return TransferCredits(recipients)

class RemoteTransaction(TransactionBodyBase):
    """
    Represents a Remote Transaction, which references another transaction by its hash.
    """

    def __init__(self, hash: bytes):
        """
        :param hash: The 32-byte transaction hash being referenced.
        """
        if not isinstance(hash, bytes) or len(hash) != 32:
            raise ValueError("hash must be a 32-byte value.")

        self.hash = hash  # Store the transaction hash

    def type(self) -> TransactionType:
        """Return the transaction type."""
        return TransactionType.REMOTE

    def fields_to_encode(self):
        """
        Fields to encode:
          Field 1: Transaction Type (remoteTransaction)
          Field 2: Transaction Hash (32-byte binary)
        """
        return [
            (1, self.type().value, bytes_marshal_binary),  # Transaction Type
            (2, self.hash, bytes_marshal_binary),  # Transaction Hash
        ]

    @classmethod
    def unmarshal(cls, data: bytes) -> "RemoteTransaction":
        """
        Deserialize RemoteTransaction from bytes.
        """
        reader = io.BytesIO(data)

        # Read the type field
        tx_type = reader.read(1)
        if int.from_bytes(tx_type, "big") != TransactionType.REMOTE.value:
            raise ValueError("Unexpected transaction type for RemoteTransaction")

        # Read the transaction hash
        hash_bytes = reader.read(32)
        if len(hash_bytes) != 32:
            raise ValueError("Invalid hash length (must be 32 bytes).")

        return cls(hash_bytes)

    def to_dict(self) -> dict:
        """Convert RemoteTransaction to a dictionary."""
        return {
            "type": "remoteTransaction",
            "hash": self.hash.hex(),  # Convert bytes to hex for JSON serialization
        }
