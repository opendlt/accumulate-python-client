# C:\Accumulate_Stuff\accumulate-python-client\accumulate\models\enums.py 

from enum import Enum
from typing import Optional

# Service Types
class ServiceType(Enum):
    """Types of services available in the Accumulate network."""
    UNKNOWN = 0
    QUERY = 5
    EVENT = 6
    SUBMIT = 7
    FAUCET = 9

# Querier type mapping
EVENT_TYPE_MAPPING = {
    "BlockEvent": "accumulate.models.events.BlockEvent",
    "ErrorEvent": "accumulate.models.events.ErrorEvent",
    "GlobalsEvent": "accumulate.models.events.GlobalsEvent",
}

# Query Types
class QueryType(Enum):
    """Query types for retrieving blockchain data."""
    DEFAULT = 0x00
    CHAIN = 0x01
    DATA = 0x02
    DIRECTORY = 0x03
    PENDING = 0x04
    BLOCK = 0x05
    ANCHOR_SEARCH = 0x10
    PUBLIC_KEY_SEARCH = 0x11
    PUBLIC_KEY_HASH_SEARCH = 0x12
    DELEGATE_SEARCH = 0x13
    MESSAGE_HASH_SEARCH = 0x14


# Record Types
class RecordType(Enum):
    """Types of records stored in the blockchain."""
    ACCOUNT = 0x01
    CHAIN = 0x02
    CHAIN_ENTRY = 0x03
    KEY = 0x04
    MESSAGE = 0x10
    SIGNATURE_SET = 0x11
    MINOR_BLOCK = 0x20
    MAJOR_BLOCK = 0x21
    RANGE = 0x80
    URL = 0x81
    TX_ID = 0x82
    INDEX_ENTRY = 0x83
    ERROR = 0x8F


# Event Types
class EventType(Enum):
    """Types of blockchain events."""
    ERROR = 1
    BLOCK = 2
    GLOBALS = 3


# Peer Status
class KnownPeerStatus(Enum):
    """Statuses of known peers in the network."""
    UNKNOWN = 0
    GOOD = 1
    BAD = 2


# Account Types
class AccountType(Enum):
    """Types of accounts in the Accumulate blockchain."""
    UNKNOWN = 0
    ANCHOR_LEDGER = 1
    IDENTITY = 2
    TOKEN_ISSUER = 3
    TOKEN_ACCOUNT = 4
    LITE_TOKEN_ACCOUNT = 5
    BLOCK_LEDGER = 6
    KEY_PAGE = 9
    KEY_BOOK = 10
    DATA_ACCOUNT = 11
    LITE_DATA_ACCOUNT = 12
    SYSTEM_LEDGER = 14
    LITE_IDENTITY = 15
    SYNTHETIC_LEDGER = 16


# Vote Types
class VoteType(Enum):
    """Vote types used in governance."""
    ACCEPT = 0
    REJECT = 1
    ABSTAIN = 2
    SUGGEST = 3


# Data Entry Types
class DataEntryType(Enum):
    """Types of data entries in the blockchain."""
    UNKNOWN = 0
    FACTOM = 1
    ACCUMULATE = 2
    DOUBLE_HASH = 3



# Transaction Types
class TransactionType(Enum):
    """Transaction types supported by the Accumulate blockchain."""
    UNKNOWN = 0
    CREATE_IDENTITY = 1
    CREATE_TOKEN_ACCOUNT = 2
    SEND_TOKENS = 3
    CREATE_DATA_ACCOUNT = 4
    WRITE_DATA = 5
    ACME_FAUCET = 7
    ISSUE_TOKENS = 9
    BURN_TOKENS = 10
    CREATE_KEY_PAGE = 12
    CREATE_KEY_BOOK = 13
    ADD_CREDITS = 14
    UPDATE_KEY_PAGE = 15
    UPDATE_ACCOUNT_AUTH = 19
    DIRECTORY_ANCHOR = 20
    BLOCK_VALIDATOR_ANCHOR = 21
    SYNTHETIC_CREATE_IDENTITY = 49
    SYNTHETIC_WRITE_DATA = 50
    SYNTHETIC_DEPOSIT_TOKENS = 51
    SYNTHETIC_BURN_TOKENS = 53

    def is_user(self) -> bool:
        """Check if the transaction type is a user transaction."""
        return self.value <= 19

    def is_synthetic(self) -> bool:
        """Check if the transaction type is synthetic."""
        return 49 <= self.value <= 53

    def is_anchor(self) -> bool:
        """Check if the transaction type is an anchor transaction."""
        return self in {TransactionType.DIRECTORY_ANCHOR, TransactionType.BLOCK_VALIDATOR_ANCHOR}

# Key Page Operations
class KeyPageOperationType(Enum):
    """Operations for key pages."""
    UNKNOWN = 0
    ADD = 3
    REMOVE = 2
    UPDATE = 1
    SET_THRESHOLD = 4


# Account Authorization Operations
class AccountAuthOperationType(Enum):
    """Operations for account authorization."""
    UNKNOWN = 0
    ENABLE = 1
    DISABLE = 2
    ADD_AUTHORITY = 3
    REMOVE_AUTHORITY = 4


# Executor Versions
class ExecutorVersion(Enum):
    """Versions of the executor system."""
    V1 = 1
    V1_SIGNATURE_ANCHORING = 2
    V1_DOUBLE_HASH_ENTRIES = 3
    V1_HALT = 4
    V2 = 5
    V2_BAIKONUR = 6
    V2_VANDENBERG = 7
    V2_JIUQUAN = 8
    V_NEXT = 9


# Book Types
class BookType(Enum):
    """Types of key books."""
    NORMAL = 0
    VALIDATOR = 1
    OPERATOR = 2


# Utility Functions
def enum_from_name(enum_cls, name: str):
    """Retrieve enum value by name."""
    try:
        return enum_cls[name.upper()]
    except KeyError:
        raise ValueError(f"Invalid {enum_cls.__name__}: {name}")
