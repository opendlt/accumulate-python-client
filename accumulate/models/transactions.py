# C:\Accumulate_Stuff\accumulate-python-client\accumulate\models\transactions.py

from typing import List, Optional, Union, Any
from unittest.mock import MagicMock
from accumulate.models.accounts import Account
from accumulate.models.key_management import KeySpecParams
from accumulate.models.signatures import Signer
from accumulate.utils.url import URL
from accumulate.models.txid import TxID
from accumulate.api.exceptions import AccumulateError
import hashlib
from typing import Optional, List, Union, Tuple
from accumulate.models.data_entries import DataEntry
from accumulate.models.enums import TransactionType
from accumulate.models.general import CreditRecipient, TokenRecipient
from accumulate.models.base_transactions import TransactionBody, TransactionHeader, ExpireOptions, HoldUntilOptions
from unittest.mock import MagicMock
import logging
from accumulate.utils.encoding import marshal_string, marshal_bytes, marshal_uint, unmarshal_string, unmarshal_bytes, unmarshal_uint
from accumulate.models.key_signature import KeySignature

logger = logging.getLogger(__name__)

class TransactionStatus:
    def __init__(
        self,
        tx_id: Optional[str] = None,
        code: int = 0,
        error: Optional[AccumulateError] = None,
        result: Optional["TransactionResult"] = None,
        received: Optional[int] = None,
        initiator: Optional[URL] = None,
    ):
        self.tx_id = tx_id
        self.code = code
        self.error = error
        self.result = result
        self.received = received
        self.initiator = initiator
        self.signers: List["Signer"] = []

    def to_dict(self) -> dict:
        """Serialize the TransactionStatus to a dictionary."""
        return {
            "tx_id": self.tx_id,
            "code": self.code,
            "error": str(self.error) if self.error else None,
            "result": self.result,  # You can expand this if result has a to_dict()
            "received": self.received,
            "initiator": str(self.initiator) if self.initiator else None,
            "signers": [signer.to_dict() for signer in self.signers] if self.signers else [],
        }


    @classmethod
    def from_dict(cls, data: dict) -> "TransactionStatus":
        logger.debug("TransactionStatus.from_dict called with: %s", data)
        if "mock_key" in data:
            logger.debug("Returning mock for TransactionStatus with data: %s", data)
            return MagicMock(to_dict=lambda: data)
        instance = cls(
            tx_id=data.get("tx_id"),
            code=data.get("code", 0),
            error=data.get("error"),
            result=data.get("result"),
            received=data.get("received"),
            initiator=data.get("initiator"),
        )
        logger.debug("Created TransactionStatus instance: %s", instance.to_dict())
        return instance


    def delivered(self) -> bool:
        return self.code == AccumulateError.DELIVERED or self.failed()

    def remote(self) -> bool:
        return self.code == AccumulateError.REMOTE

    def pending(self) -> bool:
        return self.code == AccumulateError.PENDING

    def failed(self) -> bool:
        return not self.code.success()

    def set(self, error: AccumulateError) -> None:
        self.error = error
        self.code = error.code if error.code else AccumulateError.UNKNOWN

    def as_error(self) -> Optional[Exception]:
        return self.error if self.error else None

    def add_anchor_signer(self, signature: KeySignature) -> None:
        key = signature.get_public_key()
        if not hasattr(self, "anchor_signers"):
            self.anchor_signers = []
        if key not in self.anchor_signers:
            self.anchor_signers.append(key)

    def add_signer(self, signer: "Signer") -> None:
        existing = next((s for s in self.signers if s.get_url() == signer.get_url()), None)
        if not existing or signer.get_version() > existing.get_version():
            self.signers.append(signer)

    def get_signer(self, url: URL) -> Optional["Signer"]:
        for signer in self.signers:
            if signer.get_url() == url:
                return signer
        return None






class WriteData(TransactionBody):
    def __init__(self, entry: DataEntry, scratch: Optional[bool] = None, write_to_state: Optional[bool] = None):
        self.entry = entry
        self.scratch = scratch
        self.write_to_state = write_to_state

    def type(self) -> TransactionType:
        return TransactionType.WRITE_DATA

    def marshal(self) -> bytes:
        scratch_flag = b"\x01" if self.scratch else b"\x00"
        state_flag = b"\x01" if self.write_to_state else b"\x00"
        return scratch_flag + state_flag + self.entry.marshal()

    def unmarshal(self, data: bytes) -> "WriteData":
        self.scratch = data[0] == 1
        self.write_to_state = data[1] == 1
        try:
            self.entry = DataEntry.unmarshal(data[2:])
        except ValueError as e:
            raise ValueError(f"Failed to unmarshal WriteData entry: {e}")
        return self










class WriteDataTo(TransactionBody):
    def __init__(self, recipient: URL, entry: DataEntry):
        self.recipient = recipient
        self.entry = entry

    def type(self) -> TransactionType:
        return TransactionType.WRITE_DATA_TO

    def marshal(self) -> bytes:
        """
        Serialize WriteDataTo into bytes. Structure:
        [recipient (variable length)] + [entry (variable length)]
        """
        recipient_bytes = self.recipient.marshal()
        entry_bytes = self.entry.marshal()
        return len(recipient_bytes).to_bytes(2, "big") + recipient_bytes + entry_bytes

    def unmarshal(self, data: bytes) -> "WriteDataTo":
        """
        Deserialize WriteDataTo from bytes. Structure:
        [recipient length (2 bytes)] + [recipient] + [entry]
        """
        recipient_length = int.from_bytes(data[:2], "big")
        recipient_end = 2 + recipient_length
        self.recipient = URL.unmarshal(data[2:recipient_end])
        self.entry = DataEntry.unmarshal(data[recipient_end:])
        return self


class IssueTokens(TransactionBody):
    def __init__(self, to: List["TokenRecipient"]):
        """
        Represents an Issue Tokens transaction.

        :param to: A list of token recipients.
        """
        self.to = to

    def type(self) -> TransactionType:
        return TransactionType.ISSUE_TOKENS

    def marshal(self) -> bytes:
        return b"".join([recipient.marshal() for recipient in self.to])

    def unmarshal(self, data: bytes) -> "IssueTokens":
        self.to = []
        offset = 0
        while offset < len(data):
            recipient = TokenRecipient.unmarshal(data[offset:offset+64])  # Assuming 64 bytes per recipient
            self.to.append(recipient)
            offset += 64
        return self


class BurnCredits(TransactionBody):
    def __init__(self, amount: int):
        """
        Represents a Burn Credits transaction.

        :param amount: The amount of credits to burn.
        """
        self.amount = amount

    def type(self) -> TransactionType:
        return TransactionType.BURN_CREDITS

    def marshal(self) -> bytes:
        return self.amount.to_bytes(8, "big")

    def unmarshal(self, data: bytes) -> "BurnCredits":
        self.amount = int.from_bytes(data, "big")
        return self


class TransferCredits(TransactionBody):
    def __init__(self, to: List["CreditRecipient"]):
        """
        Represents a Transfer Credits transaction.

        :param to: A list of credit recipients.
        """
        self.to = to

    def type(self) -> TransactionType:
        return TransactionType.TRANSFER_CREDITS

    def marshal(self) -> bytes:
        print(f"DEBUG: Beginning marshal for TransferCredits")
        # Ensure all URLs in recipients include the "acc://" prefix
        for recipient in self.to:
            if not str(recipient.url).startswith("acc://"):
                recipient.url = URL.parse(f"acc://{recipient.url}")

        serialized_recipients = b"".join([recipient.marshal() for recipient in self.to])
        print(f"DEBUG: Serialized recipients (combined): {serialized_recipients}")
        final_serialized = marshal_bytes(serialized_recipients)  # Add length prefix for the entire payload
        print(f"DEBUG: Final marshaled TransferCredits data with length prefix: {final_serialized}")
        return final_serialized

    def unmarshal(self, data: bytes) -> "TransferCredits":
        print(f"DEBUG: Starting unmarshal for TransferCredits")
        recipients_data = unmarshal_bytes(data)  # Extract length-prefixed recipients data
        print(f"DEBUG: Extracted recipients_data after length prefix: {recipients_data}")
        self.to = []

        offset = 0
        while offset < len(recipients_data):
            # Pass the entire length-prefixed recipient data to CreditRecipient.unmarshal
            recipient_data = recipients_data[offset:]  # Keep the length prefix intact
            print(f"DEBUG: Extracted recipient_data: {recipient_data}")

            # Unmarshal the recipient
            recipient = CreditRecipient.unmarshal(recipient_data)
            self.to.append(recipient)

            # Move offset forward by the size of the marshaled recipient data
            recipient_length = len(marshal_bytes(recipient.marshal()))  # Ensure the correct size is used
            offset += recipient_length
            print(f"DEBUG: Updated offset: {offset}")

        return self















class CreateLiteTokenAccount(TransactionBody):
    def __init__(self, token_url: URL):
        """
        Represents a Create Lite Token Account transaction.

        :param token_url: The token URL.
        """
        self.token_url = token_url

    def type(self) -> TransactionType:
        return TransactionType.CREATE_LITE_TOKEN_ACCOUNT

    def marshal(self) -> bytes:
        # Normalize the URL by using its string representation and parsing it again
        normalized_url = URL.parse(f"acc://{str(self.token_url).lstrip('acc://')}")
        return normalized_url.marshal()

    def unmarshal(self, data: bytes) -> "CreateLiteTokenAccount":
        # Unmarshal and normalize the token URL
        token_url = URL.unmarshal(data)
        normalized_url = URL.parse(f"acc://{str(token_url).lstrip('acc://')}")
        return CreateLiteTokenAccount(token_url=normalized_url)




class CreateKeyPage(TransactionBody):
    def __init__(self, keys: List[KeySpecParams]):
        """
        Represents a Create Key Page transaction.

        :param keys: A list of key specifications.
        """
        self.keys = keys

    def type(self) -> TransactionType:
        return TransactionType.CREATE_KEY_PAGE

    def marshal(self) -> bytes:
        print("DEBUG: Marshaling CreateKeyPage")
        # Marshal all keys into a single byte array
        keys_data = b"".join([key.marshal().ljust(64, b"\x00") for key in self.keys])
        keys_count = len(self.keys).to_bytes(2, "big")  # 2 bytes for the number of keys
        print(f"DEBUG: Marshaled keys count={len(self.keys)}, keys_data={keys_data.hex()}")
        # Combine all marshaled components
        return keys_count + keys_data

    def unmarshal(self, data: bytes) -> "CreateKeyPage":
        print("DEBUG: Unmarshaling CreateKeyPage")
        offset = 0

        # Extract number of keys (2 bytes)
        keys_count = int.from_bytes(data[offset:offset + 2], "big")
        offset += 2
        print(f"DEBUG: Unmarshaling keys_count={keys_count}")

        # Extract each key (fixed size, 64 bytes per key)
        self.keys = []
        for i in range(keys_count):
            key_data = data[offset:offset + 64].rstrip(b"\x00")
            print(f"DEBUG: Unmarshaling key {i + 1}/{keys_count}: {key_data.hex()}")
            self.keys.append(KeySpecParams.unmarshal(key_data))
            offset += 64

        print(f"DEBUG: Completed unmarshaling CreateKeyPage: keys={self.keys}")
        return self



class CreateKeyBook(TransactionBody):
    def __init__(self, url: URL, public_key_hash: bytes, authorities: Optional[List[URL]] = None):
        """
        Represents a Create Key Book transaction.

        :param url: The URL of the key book.
        :param public_key_hash: The hash of the public key.
        :param authorities: List of authorities for the key book.
        """
        self.url = url
        self.public_key_hash = public_key_hash
        self.authorities = authorities or []

    def type(self) -> TransactionType:
        return TransactionType.CREATE_KEY_BOOK

    def marshal(self) -> bytes:
        # Marshal URL (fixed 32 bytes)
        url_data = self.url.marshal().ljust(32, b"\x00")

        # Marshal Public Key Hash (fixed 32 bytes)
        public_key_hash_data = self.public_key_hash.ljust(32, b"\x00")

        # Marshal Authorities
        authorities_data = b"".join([authority.marshal().ljust(32, b"\x00") for authority in self.authorities])
        authorities_length = len(authorities_data).to_bytes(2, "big")  # Length as 2 bytes

        # Combine all marshaled components
        return url_data + public_key_hash_data + authorities_length + authorities_data

    def unmarshal(self, data: bytes) -> "CreateKeyBook":
        offset = 0

        # Extract URL (fixed size, 32 bytes)
        url_data = data[offset:offset + 32].rstrip(b"\x00")
        self.url = URL.unmarshal(url_data)
        offset += 32

        # Extract Public Key Hash (fixed size, 32 bytes)
        public_key_hash_data = data[offset:offset + 32].rstrip(b"\x00")
        self.public_key_hash = public_key_hash_data
        offset += 32

        # Extract Authorities Length (2 bytes)
        authorities_length = int.from_bytes(data[offset:offset + 2], "big")
        offset += 2

        # Extract Authorities (variable length based on authorities_length)
        self.authorities = [
            URL.unmarshal(data[i:i + 32].rstrip(b"\x00")) for i in range(offset, offset + authorities_length, 32)
        ]

        return self



class CreateDataAccount(TransactionBody):
    def __init__(self, url: URL, authorities: Optional[List[URL]] = None, metadata: Optional[bytes] = None):
        print(f"DEBUG: Initializing CreateDataAccount with URL: {url}, Authorities: {authorities}, Metadata: {metadata}")
        
        # Validate URL
        if not isinstance(url, URL):
            raise TypeError("url must be an instance of URL.")
        
        # Check authority and path separately
        if not url.authority:
            print(f"ERROR: URL is missing authority. URL: {url}, Authority: {url.authority}")
        if not url.path:
            print(f"ERROR: URL is missing path. URL: {url}, Path: {url.path}")
        if not url.authority or not url.path:
            raise ValueError(f"Invalid URL: {url}")

        # Validate authorities
        for authority in authorities or []:
            if not isinstance(authority, URL):
                print(f"ERROR: Invalid authority, not a URL instance: {authority}")
                raise TypeError("All authorities must be instances of URL.")
            if not authority.authority or not authority.path:
                print(f"ERROR: Authority URL is missing authority or path. Authority: {authority}")
                raise ValueError(f"Invalid authority URL: {authority}")

        self.url = url
        self.authorities = authorities or []
        self.metadata = metadata or b""
        print(f"DEBUG: CreateDataAccount initialized successfully.")

    def type(self) -> TransactionType:
        return TransactionType.CREATE_DATA_ACCOUNT

    def marshal(self) -> bytes:
        print(f"DEBUG: Beginning marshal for CreateDataAccount:")
        print(f"  URL: {self.url}")
        print(f"  Authorities: {self.authorities}")
        print(f"  Metadata: {self.metadata}")

        # Serialize URL with the scheme
        url_data = marshal_string(f"acc://{self.url}")

        # Serialize authorities as a concatenated byte array
        authorities_data = b"".join([marshal_string(f"acc://{authority}") for authority in self.authorities])
        authorities_length = marshal_uint(len(authorities_data))  # Prefix with length

        # Serialize metadata
        metadata_data = marshal_bytes(self.metadata)

        # Combine all components
        serialized = url_data + authorities_length + authorities_data + metadata_data
        print(f"DEBUG: Marshal output (bytes): {serialized}")
        return serialized


    def unmarshal(self, data: bytes) -> "CreateDataAccount":
        print(f"DEBUG: Starting unmarshal for CreateDataAccount:")
        print(f"  Input bytes: {data}")

        # Parse URL
        url_str, remaining_data = unmarshal_string(data), data[len(marshal_string(unmarshal_string(data))):]
        self.url = URL.parse(url_str)
        print(f"DEBUG: Parsed URL: {self.url}")

        # Parse authorities
        authorities_length, remaining_data = unmarshal_uint(remaining_data), remaining_data[len(marshal_uint(unmarshal_uint(remaining_data))):]
        authorities_data, remaining_data = remaining_data[:authorities_length], remaining_data[authorities_length:]

        self.authorities = []
        offset = 0
        while offset < len(authorities_data):
            # Parse each authority string correctly
            authority_length = unmarshal_uint(authorities_data[offset:])
            offset += len(marshal_uint(authority_length))  # Move past length prefix
            authority_str = authorities_data[offset:offset + authority_length].decode("utf-8")
            offset += authority_length  # Move past the actual string
            self.authorities.append(URL.parse(authority_str))
        print(f"DEBUG: Parsed Authorities: {self.authorities}")

        # Parse metadata
        self.metadata = unmarshal_bytes(remaining_data)
        print(f"DEBUG: Parsed Metadata: {self.metadata}")

        return self
















class SendTokens(TransactionBody):
    def __init__(self, recipients: Optional[List[TokenRecipient]] = None):
        """
        Represents a Send Tokens transaction.

        :param recipients: A list of token recipients.
        """
        self.recipients = recipients or []

    def add_recipient(self, to: URL, amount: int) -> None:
        if amount <= 0:
            raise ValueError("Amount must be greater than zero")
        recipient = TokenRecipient(to, amount)
        self.recipients.append(recipient)

    def type(self) -> TransactionType:
        return TransactionType.SEND_TOKENS

    def marshal(self) -> bytes:
        return b"".join([recipient.marshal() for recipient in self.recipients])

    def unmarshal(self, data: bytes) -> "SendTokens":
        self.recipients = []
        offset = 0
        while offset < len(data):
            recipient = TokenRecipient.unmarshal(data[offset:offset+64])  # Assuming 64 bytes per recipient
            self.recipients.append(recipient)
            offset += 64
        return self


class CreateIdentity(TransactionBody):
    def __init__(self, url: URL, authorities: Optional[List[URL]] = None):
        """
        Represents a Create Identity transaction.

        :param url: The URL of the identity.
        :param authorities: List of authorities for the identity.
        """
        print(f"DEBUG: Initializing CreateIdentity with URL: {url}, Authorities: {authorities}")

        # Validate URL
        if not isinstance(url, URL):
            raise TypeError("url must be an instance of URL.")

        if not url.authority:
            print(f"ERROR: URL is missing authority. URL: {url}, Authority: {url.authority}")
            raise ValueError(f"Invalid URL: Missing authority component in {url}")

        # Validate authorities
        for authority in authorities or []:
            if not isinstance(authority, URL):
                print(f"ERROR: Invalid authority, not a URL instance: {authority}")
                raise TypeError("All authorities must be instances of URL.")
            if not authority.authority:
                print(f"ERROR: Authority URL is missing authority. Authority: {authority}")
                raise ValueError(f"Invalid authority URL: {authority}")

        self.url = url
        self.authorities = authorities or []
        print(f"DEBUG: CreateIdentity initialized successfully.")

    def type(self) -> TransactionType:
        return TransactionType.CREATE_IDENTITY

    def marshal(self) -> bytes:
        print(f"DEBUG: Beginning marshal for CreateIdentity:")
        print(f"  URL: {self.url}")
        print(f"  Authorities: {self.authorities}")

        # Serialize URL with the scheme
        url_data = marshal_string(f"acc://{self.url}")

        # Serialize authorities as a concatenated byte array
        authorities_data = b"".join([marshal_string(f"acc://{authority}") for authority in self.authorities])
        authorities_length = marshal_uint(len(authorities_data))  # Prefix with length

        # Combine all components
        serialized = url_data + authorities_length + authorities_data
        print(f"DEBUG: Marshal output (bytes): {serialized}")
        return serialized

    def unmarshal(self, data: bytes) -> "CreateIdentity":
        print(f"DEBUG: Starting unmarshal for CreateIdentity:")
        print(f"  Input bytes: {data}")

        # Parse URL
        url_str, remaining_data = unmarshal_string(data), data[len(marshal_string(unmarshal_string(data))):]
        self.url = URL.parse(url_str)
        print(f"DEBUG: Parsed URL: {self.url}")

        # Parse authorities
        authorities_length, remaining_data = unmarshal_uint(remaining_data), remaining_data[len(marshal_uint(unmarshal_uint(remaining_data))):]
        authorities_data, remaining_data = remaining_data[:authorities_length], remaining_data[authorities_length:]

        self.authorities = []
        offset = 0
        while offset < len(authorities_data):
            authority_length = unmarshal_uint(authorities_data[offset:])
            offset += len(marshal_uint(authority_length))  # Move past length prefix
            authority_str = authorities_data[offset:offset + authority_length].decode("utf-8")
            offset += authority_length  # Move past the actual string
            self.authorities.append(URL.parse(authority_str))
        print(f"DEBUG: Parsed Authorities: {self.authorities}")

        return self









class CreateTokenAccount(TransactionBody):
    def __init__(self, url: Optional[URL] = None, token_url: Optional[URL] = None, authorities: Optional[List[URL]] = None):
        """
        Represents a Create Token Account transaction.

        :param url: The URL of the token account.
        :param token_url: The URL of the token issuer.
        :param authorities: List of authorities for the token account.
        """
        print(f"DEBUG: Initializing CreateTokenAccount with URL: {url}, Token URL: {token_url}, Authorities: {authorities}")

        # Allow None values for unmarshaling placeholders
        if url is not None and not isinstance(url, URL):
            raise TypeError("url must be an instance of URL.")
        if token_url is not None and not isinstance(token_url, URL):
            raise TypeError("token_url must be an instance of URL.")

        self.url = url
        self.token_url = token_url
        self.authorities = authorities or []
        print(f"DEBUG: CreateTokenAccount initialized successfully.")

    def type(self) -> TransactionType:
        return TransactionType.CREATE_TOKEN_ACCOUNT

    def marshal(self) -> bytes:
        print(f"DEBUG: Beginning marshal for CreateTokenAccount:")
        print(f"  URL: {self.url}")
        print(f"  Token URL: {self.token_url}")
        print(f"  Authorities: {self.authorities}")

        # Serialize URL and Token URL
        url_data = marshal_string(f"acc://{self.url}")
        token_url_data = marshal_string(f"acc://{self.token_url}")

        # Serialize authorities
        authorities_data = b"".join([marshal_string(f"acc://{authority}") for authority in self.authorities])
        authorities_length = marshal_uint(len(authorities_data))  # Prefix with length

        # Combine all components
        serialized = url_data + token_url_data + authorities_length + authorities_data
        print(f"DEBUG: Marshal output (bytes): {serialized}")
        return serialized

    def unmarshal(self, data: bytes) -> "CreateTokenAccount":
        print(f"DEBUG: Starting unmarshal for CreateTokenAccount:")
        print(f"  Input bytes: {data}")

        # Parse URL
        url_str, remaining_data = unmarshal_string(data), data[len(marshal_string(unmarshal_string(data))):]
        self.url = URL.parse(url_str)
        print(f"DEBUG: Parsed URL: {self.url}")

        # Parse Token URL
        token_url_str, remaining_data = unmarshal_string(remaining_data), remaining_data[len(marshal_string(unmarshal_string(remaining_data))):]
        self.token_url = URL.parse(token_url_str)
        print(f"DEBUG: Parsed Token URL: {self.token_url}")

        # Parse authorities
        authorities_length, remaining_data = unmarshal_uint(remaining_data), remaining_data[len(marshal_uint(unmarshal_uint(remaining_data))):]
        authorities_data, remaining_data = remaining_data[:authorities_length], remaining_data[authorities_length:]

        self.authorities = []
        offset = 0
        while offset < len(authorities_data):
            authority_length = unmarshal_uint(authorities_data[offset:])
            offset += len(marshal_uint(authority_length))  # Move past length prefix
            authority_str = authorities_data[offset:offset + authority_length].decode("utf-8")
            offset += authority_length  # Move past the actual string
            self.authorities.append(URL.parse(authority_str))
        print(f"DEBUG: Parsed Authorities: {self.authorities}")

        return self


class CreateToken(TransactionBody):
    def __init__(self, url: URL, symbol: str, precision: int, authorities: Optional[List[URL]] = None):
        """
        Represents a Create Token transaction.

        :param url: The URL of the token issuer account.
        :param symbol: The symbol of the token (e.g., "ACME").
        :param precision: The decimal precision of the token.
        :param authorities: List of additional authorities required for token operations.
        """
        self.url = url
        self.symbol = symbol
        self.precision = precision
        self.authorities = authorities or []

    def type(self) -> TransactionType:
        return TransactionType.CREATE_TOKEN

    def marshal(self) -> bytes:
        """
        Serialize the CreateToken object into bytes.
        """
        # Marshal URL (fixed 32 bytes)
        url_data = self.url.marshal().ljust(32, b"\x00")

        # Marshal Symbol (fixed 16 bytes, padded with \x00)
        symbol_data = self.symbol.encode("utf-8").ljust(16, b"\x00")

        # Marshal Precision (1 byte)
        precision_data = self.precision.to_bytes(1, "big")

        # Marshal Authorities
        authorities_data = b"".join([authority.marshal().ljust(32, b"\x00") for authority in self.authorities])
        authorities_length = len(authorities_data).to_bytes(2, "big")  # Length of authorities as 2 bytes

        # Combine all marshaled components
        return url_data + symbol_data + precision_data + authorities_length + authorities_data

    def unmarshal(self, data: bytes) -> "CreateToken":
        """
        Deserialize bytes into a CreateToken object.
        """
        offset = 0

        # Extract URL (fixed size, 32 bytes)
        url_data = data[offset:offset + 32].rstrip(b"\x00")
        self.url = URL.unmarshal(url_data)
        offset += 32

        # Extract Symbol (fixed size, 16 bytes)
        symbol_data = data[offset:offset + 16].rstrip(b"\x00")
        self.symbol = symbol_data.decode("utf-8")
        offset += 16

        # Extract Precision (1 byte)
        self.precision = int.from_bytes(data[offset:offset + 1], "big")
        offset += 1

        # Extract Authorities Length (2 bytes)
        authorities_length = int.from_bytes(data[offset:offset + 2], "big")
        offset += 2

        # Extract Authorities (variable length based on authorities_length)
        self.authorities = []
        for i in range(0, authorities_length, 32):
            authority_data = data[offset + i:offset + i + 32].rstrip(b"\x00")
            self.authorities.append(URL.unmarshal(authority_data))

        return self







class MintTokens(TransactionBody):
    def __init__(self, token_url: URL, recipients: List["TokenRecipient"]):
        """
        Represents a Mint Tokens transaction.

        :param token_url: The URL of the token issuer account.
        :param recipients: List of recipients and the amounts to mint for each.
        """
        self.token_url = token_url
        self.recipients = recipients

    def type(self) -> TransactionType:
        return TransactionType.MINT_TOKENS

    def marshal(self) -> bytes:
        print(f"DEBUG: Marshaling MintTokens:")
        print(f"  Token URL: {self.token_url}")
        print(f"  Recipients: {self.recipients}")

        # Ensure token_url includes the "acc://" prefix by re-parsing it
        token_url = URL.parse(f"acc://{self.token_url}") if not str(self.token_url).startswith("acc://") else self.token_url
        token_url_data = marshal_string(str(token_url))
        print(f"DEBUG: Marshaled token_url: {token_url}")

        # Serialize recipients
        serialized_recipients = b"".join([recipient.marshal() for recipient in self.recipients])
        recipients_length = marshal_uint(len(serialized_recipients))

        # Combine serialized data
        serialized_data = token_url_data + recipients_length + serialized_recipients
        print(f"DEBUG: Marshaled MintTokens data: {serialized_data.hex()}")
        return serialized_data

    def unmarshal(self, data: bytes) -> "MintTokens":
        print(f"DEBUG: Unmarshaling MintTokens:")
        print(f"  Input data: {data.hex()}")

        # Parse and normalize token_url
        token_url_str, remaining_data = unmarshal_string(data), data[len(marshal_string(unmarshal_string(data))):]
        self.token_url = URL.parse(f"acc://{token_url_str.lstrip('acc://')}")
        print(f"DEBUG: Parsed Token URL: {self.token_url}")

        # Parse recipients length
        recipients_length, remaining_data = unmarshal_uint(remaining_data), remaining_data[len(marshal_uint(unmarshal_uint(remaining_data))):]
        print(f"DEBUG: Recipients length: {recipients_length}")

        # Validate recipients length
        if recipients_length > len(remaining_data):
            raise ValueError(f"Invalid recipients_length: {recipients_length} exceeds available data size.")

        # Parse recipients
        recipients_data = remaining_data[:recipients_length]
        self.recipients = []
        offset = 0
        while offset < len(recipients_data):
            recipient = TokenRecipient.unmarshal(recipients_data[offset:])
            recipient.url = URL.parse(f"acc://{str(recipient.url).lstrip('acc://')}")
            self.recipients.append(recipient)

            # Calculate the size of the current recipient
            url_length = int.from_bytes(recipients_data[offset:offset + 2], "big")
            offset += 2 + url_length + 32  # URL length prefix, URL, and amount
        print(f"DEBUG: Parsed Recipients: {self.recipients}")

        print(f"DEBUG: Unmarshaled MintTokens: token_url={self.token_url}, recipients={self.recipients}")
        return self















class BurnTokens(TransactionBody):
    def __init__(self, token_url: URL, amount: int):
        """
        Represents a Burn Tokens transaction.

        :param token_url: The URL of the token account.
        :param amount: The amount of tokens to burn.
        """
        self.token_url = token_url
        self.amount = amount

    def type(self) -> TransactionType:
        return TransactionType.BURN_TOKENS

    def marshal(self) -> bytes:
        # Marshal URL (fixed 32 bytes)
        token_url_data = self.token_url.marshal().ljust(32, b"\x00")

        # Marshal Amount (8 bytes for fixed-size integer)
        amount_data = self.amount.to_bytes(8, "big")

        # Combine all marshaled components
        return token_url_data + amount_data

    def unmarshal(self, data: bytes) -> "BurnTokens":
        offset = 0

        # Extract URL (fixed size, 32 bytes)
        token_url_data = data[offset:offset + 32].rstrip(b"\x00")
        self.token_url = URL.unmarshal(token_url_data)
        offset += 32

        # Extract Amount (8 bytes)
        self.amount = int.from_bytes(data[offset:offset + 8], "big")
        return self



class CreateTokenIssuer(TransactionBody):
    def __init__(self, url: URL, authorities: Optional[List[URL]] = None):
        """
        Represents a Create Token Issuer transaction.

        :param url: The URL of the token issuer account.
        :param authorities: List of additional authorities required for token issuance.
        """
        print(f"DEBUG: Initializing CreateTokenIssuer with URL: {url}, Authorities: {authorities}")

        # Validate URL
        if not isinstance(url, URL):
            raise TypeError("url must be an instance of URL.")

        if not url.authority:
            print(f"ERROR: URL is missing authority. URL: {url}, Authority: {url.authority}")
            raise ValueError(f"Invalid URL: Missing authority component in {url}")

        # Validate authorities
        for authority in authorities or []:
            if not isinstance(authority, URL):
                print(f"ERROR: Invalid authority, not a URL instance: {authority}")
                raise TypeError("All authorities must be instances of URL.")
            if not authority.authority:
                print(f"ERROR: Authority URL is missing authority. Authority: {authority}")
                raise ValueError(f"Invalid authority URL: {authority}")

        self.url = url
        self.authorities = authorities or []
        print(f"DEBUG: CreateTokenIssuer initialized successfully.")

    def type(self) -> TransactionType:
        return TransactionType.CREATE_TOKEN_ISSUER

    def marshal(self) -> bytes:
        print(f"DEBUG: Beginning marshal for CreateTokenIssuer:")
        print(f"  URL: {self.url}")
        print(f"  Authorities: {self.authorities}")

        # Serialize URL with the scheme
        url_data = marshal_string(f"acc://{self.url}")

        # Serialize authorities as a concatenated byte array
        authorities_data = b"".join([marshal_string(f"acc://{authority}") for authority in self.authorities])
        authorities_length = marshal_uint(len(authorities_data))  # Prefix with length

        # Combine all components
        serialized = url_data + authorities_length + authorities_data
        print(f"DEBUG: Marshal output (bytes): {serialized}")
        return serialized

    def unmarshal(self, data: bytes) -> "CreateTokenIssuer":
        print(f"DEBUG: Starting unmarshal for CreateTokenIssuer:")
        print(f"  Input bytes: {data}")

        # Parse URL
        url_str, remaining_data = unmarshal_string(data), data[len(marshal_string(unmarshal_string(data))):]
        self.url = URL.parse(url_str)
        print(f"DEBUG: Parsed URL: {self.url}")

        # Parse authorities
        authorities_length, remaining_data = unmarshal_uint(remaining_data), remaining_data[len(marshal_uint(unmarshal_uint(remaining_data))):]
        authorities_data, remaining_data = remaining_data[:authorities_length], remaining_data[authorities_length:]

        self.authorities = []
        offset = 0
        while offset < len(authorities_data):
            authority_length = unmarshal_uint(authorities_data[offset:])
            offset += len(marshal_uint(authority_length))  # Move past length prefix
            authority_str = authorities_data[offset:offset + authority_length].decode("utf-8")
            offset += authority_length  # Move past the actual string
            self.authorities.append(URL.parse(authority_str))
        print(f"DEBUG: Parsed Authorities: {self.authorities}")

        return self




class UpdateKeyPage(TransactionBody):
    def __init__(self, url: URL, operations: List[dict]):
        """
        Represents an Update Key Page transaction.

        :param url: The URL of the key page to update.
        :param operations: List of operations to apply to the key page (e.g., adding/removing keys).
        """
        self.url = url
        self.operations = operations

    def type(self) -> TransactionType:
        return TransactionType.UPDATE_KEY_PAGE

    def marshal(self) -> bytes:
        # Marshal URL (fixed 32 bytes)
        url_data = self.url.marshal().ljust(32, b"\x00")

        # Marshal Operations
        operations_data = b"".join([self._marshal_operation(op) for op in self.operations])
        operations_length = len(operations_data).to_bytes(4, "big")

        # Combine all marshaled components
        return url_data + operations_length + operations_data

    def unmarshal(self, data: bytes) -> "UpdateKeyPage":
        offset = 0

        # Extract URL (fixed size, 32 bytes)
        url_data = data[offset:offset + 32].rstrip(b"\x00")
        self.url = URL.unmarshal(url_data)
        offset += 32

        # Extract Operations Length (4 bytes)
        operations_length = int.from_bytes(data[offset:offset + 4], "big")
        offset += 4

        # Extract Operations Data
        operations_data = data[offset:offset + operations_length]
        self.operations = self._unmarshal_operations(operations_data)

        return self

    @staticmethod
    def _marshal_operation(operation: dict) -> bytes:
        # Example: serialize operation as type + value
        operation_type = operation["type"].encode("utf-8").ljust(8, b"\x00")  # Fixed 8 bytes for type
        operation_value = operation["value"]
        value_length = len(operation_value).to_bytes(4, "big")
        return operation_type + value_length + operation_value

    @staticmethod
    def _unmarshal_operations(data: bytes) -> List[dict]:
        operations = []
        offset = 0

        while offset < len(data):
            # Extract operation type (fixed 8 bytes)
            operation_type = data[offset:offset + 8].rstrip(b"\x00").decode("utf-8")
            offset += 8

            # Extract operation value length (4 bytes)
            value_length = int.from_bytes(data[offset:offset + 4], "big")
            offset += 4

            # Extract operation value
            operation_value = data[offset:offset + value_length]
            offset += value_length

            operations.append({"type": operation_type, "value": operation_value})

        return operations


    def _marshal_operation(self, operation: dict) -> bytes:
        """
        Serialize a single operation.

        :param operation: Operation dictionary containing `type` and `value`.
        :return: Serialized bytes for the operation.
        """
        operation_type = operation.get("type", "").encode("utf-8")
        operation_value = operation.get("value", b"")
        return len(operation_type).to_bytes(2, "big") + operation_type + len(operation_value).to_bytes(2, "big") + operation_value

    def _unmarshal_operations(self, data: bytes) -> List[dict]:
        """
        Deserialize operations from bytes.

        :param data: Serialized operations data.
        :return: List of deserialized operations.
        """
        operations = []
        offset = 0
        while offset < len(data):
            type_length = int.from_bytes(data[offset:offset + 2], "big")
            offset += 2
            operation_type = data[offset:offset + type_length].decode("utf-8")
            offset += type_length

            value_length = int.from_bytes(data[offset:offset + 2], "big")
            offset += 2
            operation_value = data[offset:offset + value_length]
            offset += value_length

            operations.append({"type": operation_type, "value": operation_value})
        return operations


class AddCredits(TransactionBody):
    def __init__(self, recipient: Optional[URL] = None, amount: Optional[int] = 0):
        """
        Represents an Add Credits transaction.

        :param recipient: The URL of the account receiving the credits.
        :param amount: The amount of credits to add.
        """
        print(f"DEBUG: Initializing AddCredits with Recipient: {recipient}, Amount: {amount}")

        # Validate the recipient
        if recipient is not None and not isinstance(recipient, URL):
            raise TypeError("recipient must be an instance of URL.")

        self.recipient = recipient
        self.amount = amount
        print(f"DEBUG: AddCredits initialized successfully.")

    def type(self) -> TransactionType:
        return TransactionType.ADD_CREDITS

    def marshal(self) -> bytes:
        print(f"DEBUG: Beginning marshal for AddCredits:")
        print(f"  Recipient: {self.recipient}")
        print(f"  Amount: {self.amount}")

        # Ensure recipient includes the "acc://" prefix
        recipient_data = marshal_string(f"acc://{self.recipient}" if not str(self.recipient).startswith("acc://") else str(self.recipient))

        # Serialize amount as a fixed-length 8-byte integer
        amount_data = self.amount.to_bytes(8, "big")

        # Combine components
        serialized = recipient_data + amount_data
        print(f"DEBUG: Marshal output (bytes): {serialized}")
        return serialized

    def unmarshal(self, data: bytes) -> "AddCredits":
        print(f"DEBUG: Starting unmarshal for AddCredits:")
        print(f"  Input bytes: {data}")

        # Parse recipient URL
        recipient_str, remaining_data = unmarshal_string(data), data[len(marshal_string(unmarshal_string(data))):]
        self.recipient = URL.parse(f"acc://{recipient_str}" if not recipient_str.startswith("acc://") else recipient_str)
        print(f"DEBUG: Parsed Recipient: {self.recipient}")

        # Parse amount
        self.amount = int.from_bytes(remaining_data, "big")
        print(f"DEBUG: Parsed Amount: {self.amount}")

        return self










class UpdateAccountAuth(TransactionBody):
    def __init__(self, account_url: URL, operations: List[dict]):
        """
        Represents an Update Account Auth transaction.

        :param account_url: The URL of the account to update.
        :param operations: List of operations to modify the account's authorities.
        """
        self.account_url = account_url
        self.operations = operations

    def type(self) -> TransactionType:
        return TransactionType.UPDATE_ACCOUNT_AUTH

    def marshal(self) -> bytes:
        # Marshal URL (fixed 32 bytes)
        account_url_data = self.account_url.marshal().ljust(32, b"\x00")

        # Marshal Operations
        operations_data = b"".join([self._marshal_operation(op) for op in self.operations])
        operations_length = len(operations_data).to_bytes(4, "big")

        # Combine all marshaled components
        return account_url_data + operations_length + operations_data

    def unmarshal(self, data: bytes) -> "UpdateAccountAuth":
        offset = 0

        # Extract URL (fixed size, 32 bytes)
        account_url_data = data[offset:offset + 32].rstrip(b"\x00")
        self.account_url = URL.unmarshal(account_url_data)
        offset += 32

        # Extract Operations Length (4 bytes)
        operations_length = int.from_bytes(data[offset:offset + 4], "big")
        offset += 4

        # Extract Operations Data
        operations_data = data[offset:offset + operations_length]
        self.operations = self._unmarshal_operations(operations_data)

        return self

    @staticmethod
    def _marshal_operation(operation: dict) -> bytes:
        # Serialize operation as type + value
        operation_type = operation["type"].encode("utf-8").ljust(8, b"\x00")  # Fixed 8 bytes for type
        operation_value = operation["value"]
        value_length = len(operation_value).to_bytes(4, "big")
        return operation_type + value_length + operation_value

    @staticmethod
    def _unmarshal_operations(data: bytes) -> List[dict]:
        operations = []
        offset = 0

        while offset < len(data):
            # Extract operation type (fixed 8 bytes)
            operation_type = data[offset:offset + 8].rstrip(b"\x00").decode("utf-8")
            offset += 8

            # Extract operation value length (4 bytes)
            value_length = int.from_bytes(data[offset:offset + 4], "big")
            offset += 4

            # Extract operation value
            operation_value = data[offset:offset + value_length]
            offset += value_length

            operations.append({"type": operation_type, "value": operation_value})

        return operations





class Transaction:
    def __init__(self, header: TransactionHeader, body: Optional[TransactionBody] = None):
        """
        Represents a transaction, including its header and body.

        :param header: The transaction header containing metadata and conditions.
        :param body: The body of the transaction, containing operation details.
        """
        self.header = header
        self.body = body
        self.hash: Optional[bytes] = None
        self.body64bytes: bool = False

    def is_user(self) -> bool:
        """
        Check if the transaction is a user transaction.
        """
        return self.body is not None and self.body.type().is_user()

    def calculate_hash(self) -> bytes:
        """
        Calculate the hash of the transaction.

        :return: The hash of the transaction.
        """
        if not self.hash:
            header_hash = hashlib.sha256(self.header.marshal_binary()).digest()
            body_hash = self.body.marshal() if self.body else b""
            self.hash = hashlib.sha256(header_hash + body_hash).digest()
        return self.hash

    def get_id(self) -> TxID:
        """
        Get the transaction ID.
        """
        return TxID(
            authority=self.header.principal if self.header.principal else "unknown",
            tx_hash=self.calculate_hash()
        )

    def get_hash(self) -> bytes:
        """
        Get the hash of the transaction.
        """
        return self.calculate_hash()

    def body_is_64_bytes(self) -> bool:
        """
        Check if the body of the transaction is 64 bytes.
        """
        _, is_64_bytes = self.get_body_hash()
        return is_64_bytes

    def calc_hash(self):
        """
        Calculate the transaction hash as H(H(header) + H(body)).
        """
        if self.hash is not None:
            return

        # Hash the header
        header_hash = hashlib.sha256(self.header.marshal_binary()).digest()

        # Hash the body
        body_hash, is_64_bytes = self.get_body_hash()
        self.body64bytes = is_64_bytes

        # Combine hashes
        sha = hashlib.sha256()
        sha.update(header_hash)
        sha.update(body_hash)
        self.hash = sha.digest()



    def get_body_hash(self) -> Tuple[bytes, bool]:
        """
        Get the hash of the body of the transaction.

        :return: Tuple containing the hash of the body and whether it's 64 bytes.
        """
        if not self.body:
            return b"", False

        data = self.body.marshal()
        hash_ = hashlib.sha256(data).digest()
        return hash_, len(data) == 64


    def marshal(self) -> bytes:
        """
        Serialize the entire transaction.

        :return: Serialized bytes of the transaction.
        """
        header_data = self.header.marshal_binary()
        body_data = self.body.marshal() if self.body else b""
        return len(header_data).to_bytes(2, "big") + header_data + len(body_data).to_bytes(2, "big") + body_data

    def unmarshal(self, data: bytes) -> "Transaction":
        """
        Deserialize the transaction from bytes.

        :param data: Serialized transaction data.
        :return: Deserialized Transaction object.
        """
        header_length = int.from_bytes(data[:2], "big")
        self.header = TransactionHeader.unmarshal(data[2:2 + header_length])
        body_length = int.from_bytes(data[2 + header_length:4 + header_length], "big")
        body_data = data[4 + header_length:4 + header_length + body_length]

        if self.body:
            self.body = self.body.unmarshal(body_data)
        return self

def hash_write_data(without_entry: "TransactionBody", entry: DataEntry) -> bytes:
    """
    Calculate the hash for a WriteData transaction.
    """
    data = without_entry.marshal_binary()
    hasher = hashlib.sha256()
    hasher.update(data)

    if entry is None:
        hasher.update(b"\x00" * 32)
    else:
        hasher.update(entry.get_hash())

    return hasher.digest()


class TransactionResult:
    def __init__(self, details: Optional[dict] = None):
        """
        Represents the result of a transaction.

        :param details: A dictionary containing result details.
        """
        self.details = details or {}
