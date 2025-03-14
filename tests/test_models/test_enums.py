# accumulate-python-client\tests\test_models\test_enums.py

import pytest
from accumulate.models.enums import (
    ServiceType,
    QueryType,
    RecordType,
    EventType,
    KnownPeerStatus,
    AccountType,
    VoteType,
    DataEntryType,
    TransactionType,
    KeyPageOperationType,
    AccountAuthOperationType,
    ExecutorVersion,
    BookType,
    enum_from_name,
)


def test_service_type_enum():
    """Test ServiceType enum values."""
    assert ServiceType.UNKNOWN.value == 0
    assert ServiceType.QUERY.value == 5
    assert ServiceType.EVENT.value == 6
    assert ServiceType.SUBMIT.value == 7
    assert ServiceType.FAUCET.value == 9


def test_query_type_enum():
    """Test QueryType enum values."""
    assert QueryType.DEFAULT.value == 0x00
    assert QueryType.CHAIN.value == 0x01
    assert QueryType.DATA.value == 0x02
    assert QueryType.DIRECTORY.value == 0x03
    assert QueryType.PENDING.value == 0x04
    assert QueryType.BLOCK.value == 0x05
    assert QueryType.ANCHOR_SEARCH.value == 0x10
    assert QueryType.PUBLIC_KEY_SEARCH.value == 0x11
    assert QueryType.DELEGATE_SEARCH.value == 0x13


def test_record_type_enum():
    """Test RecordType enum values."""
    assert RecordType.ACCOUNT.value == 0x01
    assert RecordType.CHAIN.value == 0x02
    assert RecordType.CHAIN_ENTRY.value == 0x03
    assert RecordType.KEY.value == 0x04
    assert RecordType.MESSAGE.value == 0x10
    assert RecordType.ERROR.value == 0x8F


def test_event_type_enum():
    """Test EventType enum values."""
    assert EventType.ERROR.value == 1
    assert EventType.BLOCK.value == 2
    assert EventType.GLOBALS.value == 3


def test_known_peer_status_enum():
    """Test KnownPeerStatus enum values."""
    assert KnownPeerStatus.UNKNOWN.value == 0
    assert KnownPeerStatus.GOOD.value == 1
    assert KnownPeerStatus.BAD.value == 2


def test_account_type_enum():
    """Test AccountType enum values."""
    assert AccountType.UNKNOWN.value == 0
    assert AccountType.IDENTITY.value == 2
    assert AccountType.TOKEN_ISSUER.value == 3
    assert AccountType.TOKEN_ACCOUNT.value == 4
    assert AccountType.LITE_TOKEN_ACCOUNT.value == 5
    assert AccountType.SYSTEM_LEDGER.value == 14


def test_vote_type_enum():
    """Test VoteType enum values."""
    assert VoteType.ACCEPT.value == 0
    assert VoteType.REJECT.value == 1
    assert VoteType.ABSTAIN.value == 2
    assert VoteType.SUGGEST.value == 3


def test_data_entry_type_enum():
    """Test DataEntryType enum values."""
    assert DataEntryType.UNKNOWN.value == 0
    assert DataEntryType.FACTOM.value == 1
    assert DataEntryType.ACCUMULATE.value == 2
    assert DataEntryType.DOUBLE_HASH.value == 3


def test_transaction_type_enum():
    """Test TransactionType enum values and methods."""
    assert TransactionType.UNKNOWN.value == 0
    assert TransactionType.CREATE_IDENTITY.value == 1
    assert TransactionType.SEND_TOKENS.value == 3
    assert TransactionType.SYNTHETIC_CREATE_IDENTITY.value == 49

    assert TransactionType.CREATE_IDENTITY.is_user() is True
    assert TransactionType.SYNTHETIC_CREATE_IDENTITY.is_user() is False

    assert TransactionType.SYNTHETIC_CREATE_IDENTITY.is_synthetic() is True
    assert TransactionType.CREATE_IDENTITY.is_synthetic() is False

    assert TransactionType.DIRECTORY_ANCHOR.is_anchor() is True
    assert TransactionType.BLOCK_VALIDATOR_ANCHOR.is_anchor() is True
    assert TransactionType.CREATE_IDENTITY.is_anchor() is False


def test_key_page_operation_type_enum():
    """Test KeyPageOperationType enum values."""
    assert KeyPageOperationType.UNKNOWN.value == 0
    assert KeyPageOperationType.ADD.value == 3
    assert KeyPageOperationType.REMOVE.value == 2
    assert KeyPageOperationType.SET_THRESHOLD.value == 15


def test_account_auth_operation_type_enum():
    """Test AccountAuthOperationType enum values."""
    assert AccountAuthOperationType.UNKNOWN.value == 0
    assert AccountAuthOperationType.ENABLE.value == 1
    assert AccountAuthOperationType.DISABLE.value == 2
    assert AccountAuthOperationType.ADD_AUTHORITY.value == 3


def test_executor_version_enum():
    """Test ExecutorVersion enum values."""
    assert ExecutorVersion.V1.value == 1
    assert ExecutorVersion.V2.value == 5
    assert ExecutorVersion.V_NEXT.value == 9


def test_book_type_enum():
    """Test BookType enum values."""
    assert BookType.NORMAL.value == 0
    assert BookType.VALIDATOR.value == 1
    assert BookType.OPERATOR.value == 2


def test_enum_from_name():
    """Test the utility function enum_from_name."""
    assert enum_from_name(ServiceType, "query") == ServiceType.QUERY
    assert enum_from_name(QueryType, "chain") == QueryType.CHAIN

    with pytest.raises(ValueError, match="Invalid ServiceType: invalid"):
        enum_from_name(ServiceType, "invalid")
