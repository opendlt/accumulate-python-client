#!/usr/bin/env python3
# File: accumulate-python-client/accumulate/models/base_transactions.py

from abc import ABC, abstractmethod
import base64
from typing import Any, Optional, Dict, List, TYPE_CHECKING, Type, Union
import struct
import time
import io
import logging
import hashlib
import struct

from accumulate.models.signature_types import SignatureType
from accumulate.models.enums import TransactionType
from accumulate.utils.encoding import (
    encode_uvarint,
    encode_compact_int,
    field_marshal_binary,
    read_uvarint,
    unmarshal_string,
    unmarshal_bytes,
)

logger = logging.getLogger(__name__)


if TYPE_CHECKING:
    from accumulate.signing.signer import Signer


class TransactionBodyBase(ABC):
    """Base class for all transaction bodies, providing standardized marshaling/unmarshaling."""

    @abstractmethod
    def type(self) -> TransactionType:
        """Return the transaction type."""
        pass

    @abstractmethod
    def fields_to_encode(self):
        """Return the fields to encode as a list of (field_id, value, encoding_function)."""
        pass


    def marshal(self) -> bytes:
        """Generic marshaling for all transactions using structured encoding."""
        logger.debug(f" START Marshaling {self.__class__.__name__}")

        serialized = b""

        #  Confirm Execution (Force an Output to Ensure it Runs)
        assert True, " DEBUG: `marshal()` method is being executed!"

        for field_num, value, encode_func in self.fields_to_encode():
            encoded_value = encode_func(value)
            
            #  Explicit Debugging of Each Field
            logger.debug(f" Encoding Field {field_num}: {encoded_value.hex() if isinstance(encoded_value, bytes) else encoded_value}")

            serialized += field_marshal_binary(field_num, encoded_value)

        logger.debug(f" FINAL Marshaled {self.__class__.__name__} (HEX): {serialized.hex()}")

        return serialized


    @classmethod
    @abstractmethod
    def unmarshal(cls, data: bytes):
        """Generic unmarshaling method to be implemented per transaction type."""
        pass

    def to_dict(self) -> dict:
        """Convert transaction to a dictionary with correct type formatting."""
        return {"type": self._format_transaction_type(self.type().name)}

    @staticmethod
    def _format_transaction_type(transaction_type: str) -> str:
        """Convert ENUM transaction type to lowerCamelCase for JSON compatibility."""
        words = transaction_type.lower().split("_")
        return words[0] + "".join(word.capitalize() for word in words[1:])

class TransactionBodyFactory:
    """
    Factory for creating transaction body instances based on transaction type.
    """

    @classmethod
    async def create(cls, client, transaction_type: TransactionType, *args, **kwargs) -> Optional[TransactionBodyBase]:
        """
        Dynamically create a transaction body instance of the specified type.

        :param client: AccumulateClient instance (optional, for API interactions).
        :param transaction_type: Enum specifying the transaction type.
        :param args: Positional arguments for the transaction body constructor.
        :param kwargs: Keyword arguments for the transaction body constructor.
        :return: A fully initialized TransactionBodyBase subclass instance, or None if unsupported.
        """
        from accumulate.models.transactions import (
            AddCredits, CreateIdentity, SendTokens, CreateDataAccount, CreateTokenAccount,
            WriteData, IssueTokens, BurnTokens, TransferCredits, RemoteTransaction, 
            UpdateKeyPage, UpdateAccountAuth, CreateToken
        )

        TRANSACTION_TYPE_MAP: Dict[TransactionType, Type[TransactionBodyBase]] = {
            TransactionType.ADD_CREDITS: AddCredits,
            TransactionType.CREATE_IDENTITY: CreateIdentity,
            TransactionType.SEND_TOKENS: SendTokens,
            TransactionType.CREATE_DATA_ACCOUNT: CreateDataAccount,
            TransactionType.CREATE_TOKEN_ACCOUNT: CreateTokenAccount,
            TransactionType.WRITE_DATA: WriteData,
            TransactionType.ISSUE_TOKENS: IssueTokens,
            TransactionType.BURN_TOKENS: BurnTokens,
            TransactionType.TRANSFER_CREDITS: TransferCredits,
            TransactionType.REMOTE: RemoteTransaction,
            TransactionType.UPDATE_KEY_PAGE: UpdateKeyPage,
            TransactionType.UPDATE_ACCOUNT_AUTH: UpdateAccountAuth,
            TransactionType.CREATE_TOKEN: CreateToken,
        }

        if transaction_type not in TRANSACTION_TYPE_MAP:
            logger.error(f" Unsupported transaction type: {transaction_type}")
            return None  # Or raise an exception if you prefer

        transaction_class = TRANSACTION_TYPE_MAP[transaction_type]

        #  Create the transaction body instance dynamically
        instance = transaction_class(client, *args, **kwargs)

        #  If it has an initialize method, call it asynchronously (e.g., fetching oracle price)
        if hasattr(instance, "initialize") and callable(instance.initialize):
            await instance.initialize(client)

        return instance


class ExpireOptions:
    """
    Represents expiration options for a transaction.
    """

    def __init__(self, at_time: Optional[int] = None):
        """
        :param at_time: The expiration time as a Unix timestamp.
        """
        self.at_time = at_time


class HoldUntilOptions:
    """
    Represents hold-until options for a transaction.
    """

    def __init__(self, minor_block: Optional[int] = None):
        """
        :param minor_block: The minor block at which the transaction is held until.
        """
        self.minor_block = minor_block


class TransactionHeader:
    """
    Represents the header of a transaction, containing metadata and conditions.
    """

    def __init__(
        self,
        principal: str,
        initiator: bytes,
        timestamp: int,
        signature_type: SignatureType,
        memo: Optional[str] = None,
        metadata: Optional[bytes] = None,
        expire: Optional["ExpireOptions"] = None,
        hold_until: Optional["HoldUntilOptions"] = None,
        authorities: Optional[List[str]] = None,
    ):
        self.timestamp = timestamp
        self.principal = principal
        self.initiator = initiator
        self.signature_type = signature_type
        self.memo = memo
        self.metadata = metadata
        self.expire = expire
        self.hold_until = hold_until
        self.authorities = authorities or []


    @classmethod
    async def create(
        cls,
        principal: str,
        public_key: bytes,
        signer: "Signer",
        timestamp: Optional[int] = None,
        transaction_body=None,  #  Add transaction body to check for RemoteTransaction
    ) -> "TransactionHeader":
        """Automatically compute the initiator hash and return a fully constructed TransactionHeader."""

        from accumulate.signing.signer import Signer
        from accumulate.signing.timestamp import TimestampFromVariable
        from accumulate.models.transactions import RemoteTransaction  #  Import RemoteTransaction

        #  If this is a RemoteTransaction, set header differently
        if isinstance(transaction_body, RemoteTransaction):
            logger.info(" RemoteTransaction detected! Adjusting header...")

            #  Use the referenced transaction's hash as the initiator
            initiator_hash = transaction_body.hash  # This should be the original signed transaction hash

            #  Remote Transactions do not need a new timestamp
            timestamp = None  

            logger.info(f" Using referenced transaction hash: {initiator_hash.hex()}")

        else:
        
            #  Generate timestamp only if it's not provided
            timestamp = timestamp or TimestampFromVariable().get()

            #  Fetch signer version dynamically
            signer_version = await signer.get_signer_version()

            #  Fetch the correct signature type dynamically
            signature_type = await signer.get_signature_type()

            #  Use the correct Lite Identity URL (not a token sub-account)
            signer_url = str(signer.url)  #  Extract URL from Signer object

            logger.info(f" Correcting Signer URL (used in metadata hash): {signer_url}")

            #  Compute initiator hash using the same function as `Signer.sign_transaction()`
            initiator_hash = Signer.calculate_metadata_hash(
                public_key, timestamp, signer_url, signer_version, signature_type.value
            )

            logger.info(f" Computed Initiator Hash Header (public key): {public_key.hex()}")
            logger.info(f" Computed Initiator Hash Header (timestamp): {timestamp}")
            logger.info(f" Computed Initiator Hash Header (signer): {principal}")
            logger.info(f" Computed Initiator Hash Header (signer_version): {signer_version}")
            logger.info(f" Computed Initiator Hash Header (signature_type.value): {signature_type.value}")
            logger.info(f" Computed Initiator Hash (from TransactionHeader.create()): {initiator_hash.hex()}")

        #  Ensure timestamp and signature type are included when creating the instance
        return cls(
            principal=principal,
            initiator=initiator_hash,
            timestamp=timestamp,  #  This will be None for Remote Transactions
            signature_type=signature_type if not isinstance(transaction_body, RemoteTransaction) else None,
        )

    
    def to_dict(self) -> dict:
        """Convert the transaction header to a dictionary while conditionally including optional fields."""
        txn_dict = {
            "principal": self.principal,
            "initiator": self.initiator.hex(),
        }
        if self.memo:
            txn_dict["memo"] = self.memo
        if self.metadata:
            txn_dict["metadata"] = base64.b64encode(self.metadata).decode()
        if self.expire:
            txn_dict["expire"] = self.expire.at_time
        if self.hold_until:
            txn_dict["hold_until"] = self.hold_until.minor_block
        if self.authorities:
            txn_dict["authorities"] = self.authorities
        return txn_dict

    def marshal_binary(self) -> bytes:
        """Serialize the transaction header to bytes using the updated field‐based encoding."""
        print("\n DEBUG: Marshaling Transaction Header")
        result = b""

        # Field 1: Principal – encode as: [varint(length)] + principal_bytes
        principal_bytes = self.principal.encode("utf-8")
        field1 = field_marshal_binary(1, encode_uvarint(len(principal_bytes)) + principal_bytes)
        result += field1
        print(f"   Field 1 (Principal): {field1.hex()}")

        # Field 2: Initiator – raw bytes (assumed fixed length, e.g. 32 bytes)
        field2 = field_marshal_binary(2, self.initiator)
        result += field2
        print(f"   Field 2 (Initiator): {field2.hex()}")

        # Optional Field 4: Memo (if present)
        if self.memo:
            memo_bytes = self.memo.encode("utf-8")
            field4 = field_marshal_binary(4, encode_uvarint(len(memo_bytes)) + memo_bytes)
            result += field4
            print(f"   Field 4 (Memo): {field4.hex()}")

        # Optional Field 5: Metadata (if present)
        if self.metadata:
            field5 = field_marshal_binary(5, encode_uvarint(len(self.metadata)) + self.metadata)
            result += field5
            print(f"   Field 5 (Metadata): {field5.hex()}")

        # Optional Field 6: Expire (if present; fixed 8 bytes)
        if self.expire:
            expire_bytes = struct.pack(">Q", self.expire.at_time)
            field6 = field_marshal_binary(6, expire_bytes)
            result += field6
            print(f"   Field 6 (Expire): {field6.hex()}")

        # Optional Field 7: Hold Until (if present; fixed 8 bytes)
        if self.hold_until:
            hold_until_bytes = struct.pack(">Q", self.hold_until.minor_block)
            field7 = field_marshal_binary(7, hold_until_bytes)
            result += field7
            print(f"   Field 7 (Hold Until): {field7.hex()}")

        # Optional Field 8: Authorities (if present; encoded as length-prefixed UTF-8 string)
        if self.authorities:
            auth_str = ",".join(self.authorities)
            auth_bytes = auth_str.encode("utf-8")
            field8 = field_marshal_binary(8, encode_uvarint(len(auth_bytes)) + auth_bytes)
            result += field8
            print(f"   Field 8 (Authorities): {field8.hex()}")

        print(f"   Final Header Encoding: {result.hex()}")
        return result

    @staticmethod
    def unmarshal(data: bytes) -> "TransactionHeader":
        """Deserialize the transaction header from bytes using the updated encoding scheme."""
        print("\n DEBUG: Unmarshaling Transaction Header")
        reader = io.BytesIO(data)

        principal = None
        initiator = None
        memo = None
        metadata = None
        expire = None
        hold_until = None
        authorities = None

        # Process fields one by one (each field starts with a 1-byte field id)
        while True:
            field_id_byte = reader.read(1)
            if not field_id_byte:
                break  # End of header data
            field_id = field_id_byte[0]
            if field_id == 1:
                # Principal is length-prefixed: read length then string
                plen = read_uvarint(reader)
                principal = reader.read(plen).decode("utf-8")
                print(f"   Unmarshaled Field 1 (Principal): {principal}")
            elif field_id == 2:
                # Initiator: fixed length (assume 32 bytes)
                initiator = reader.read(32)
                print(f"   Unmarshaled Field 2 (Initiator): {initiator.hex()}")
            elif field_id == 4:
                # Memo: length-prefixed string
                mlen = read_uvarint(reader)
                memo = reader.read(mlen).decode("utf-8")
                print(f"   Unmarshaled Field 4 (Memo): {memo}")
            elif field_id == 5:
                # Metadata: length-prefixed bytes
                mlen = read_uvarint(reader)
                metadata = reader.read(mlen)
                print(f"   Unmarshaled Field 5 (Metadata): {metadata.hex()}")
            elif field_id == 6:
                # Expire: fixed 8 bytes
                expire_val = struct.unpack(">Q", reader.read(8))[0]
                if expire_val > 0:
                    expire = ExpireOptions(expire_val)
                print(f"   Unmarshaled Field 6 (Expire): {expire_val}")
            elif field_id == 7:
                # Hold Until: fixed 8 bytes
                hold_val = struct.unpack(">Q", reader.read(8))[0]
                if hold_val > 0:
                    hold_until = HoldUntilOptions(hold_val)
                print(f"   Unmarshaled Field 7 (Hold Until): {hold_val}")
            elif field_id == 8:
                # Authorities: length-prefixed string (comma-separated)
                alen = read_uvarint(reader)
                auth_data = reader.read(alen).decode("utf-8")
                authorities = auth_data.split(",")
                print(f"   Unmarshaled Field 8 (Authorities): {authorities}")
            else:
                # Unknown field – skip (or break)
                print(f"   Unknown field id {field_id} encountered. Skipping.")
                break

        return TransactionHeader(
            principal=principal,
            initiator=initiator,
            memo=memo,
            metadata=metadata,
            expire=expire,
            hold_until=hold_until,
            authorities=authorities,
        )


    def build_transaction(self, txn):
        """
        Build transaction JSON while conditionally including optional fields.
        Ensures transactionHash matches header['initiator'] for validation.
        Automatically wraps the transaction inside a list.
        """
        from accumulate.models.transactions import Transaction

        txn_hash = txn.get_hash()

        expected_hash = txn.header.initiator.hex() if txn.header.initiator else None

        logger.info(f" Verifying Transaction Hash Before Sending")
        logger.info(f" Computed Transaction Hash: {txn_hash.hex()}")
        logger.info(f"vs Expected Hash from Initiator: {expected_hash}")

        if expected_hash and txn_hash.hex() != expected_hash:
            logger.error(" Transaction hash mismatch! Computed hash does not match the expected initiator hash.")
            raise ValueError("Transaction hash mismatch! Computed hash does not match the expected initiator hash.")

        txn_data = {
            "header": txn.header.to_dict(),
            "body": txn.body.to_dict() if txn.body else {}
        }

        #  Automatically wrap the transaction inside a list
        return {"transaction": [txn_data]}

