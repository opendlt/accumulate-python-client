# accumulate-python-client\tests\test_models\test_AccountAuthOperations.py

import pytest
from accumulate.models.AccountAuthOperations import (
    AccountAuthOperation,
    EnableAccountAuthOperation,
    DisableAccountAuthOperation,
    AddAccountAuthorityOperation,
    RemoveAccountAuthorityOperation,
)
from accumulate.utils.url import URL
from accumulate.models.enums import AccountAuthOperationType


def test_account_auth_operation_base_class():
    """Test the base class for account authentication operations."""
    authority = URL("acc://adi.acme/book")
    operation = AccountAuthOperation(authority)

    assert operation.authority == authority

    # Ensure NotImplementedError is raised for the type method
    with pytest.raises(NotImplementedError, match="Subclasses must implement the `type` method."):
        operation.type()

    # Test the hash method raises an exception for unimplemented `type`
    with pytest.raises(NotImplementedError):
        operation.hash()


def test_enable_account_auth_operation():
    """Test the EnableAccountAuthOperation class."""
    authority = URL("acc://adi.acme/book")
    operation = EnableAccountAuthOperation(authority=authority)

    assert operation.authority == authority
    assert operation.type() == AccountAuthOperationType.ENABLE
    assert operation.hash() == operation.hash()  # Ensure consistent hash generation


def test_disable_account_auth_operation():
    """Test the DisableAccountAuthOperation class."""
    authority = URL("acc://adi.acme/book")
    operation = DisableAccountAuthOperation(authority=authority)

    assert operation.authority == authority
    assert operation.type() == AccountAuthOperationType.DISABLE
    assert operation.hash() == operation.hash()  # Ensure consistent hash generation


def test_add_account_authority_operation():
    """Test the AddAccountAuthorityOperation class."""
    authority = URL("acc://adi.acme/book")
    operation = AddAccountAuthorityOperation(authority=authority)

    assert operation.authority == authority
    assert operation.type() == AccountAuthOperationType.ADD_AUTHORITY
    assert operation.hash() == operation.hash()  # Ensure consistent hash generation


def test_remove_account_authority_operation():
    """Test the RemoveAccountAuthorityOperation class."""
    authority = URL("acc://adi.acme/book")
    operation = RemoveAccountAuthorityOperation(authority=authority)

    assert operation.authority == authority
    assert operation.type() == AccountAuthOperationType.REMOVE_AUTHORITY
    assert operation.hash() == operation.hash()  # Ensure consistent hash generation
