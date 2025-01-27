# accumulate-python-client\tests\test_models\test_credits.py

import pytest
from accumulate.models.credits import CreditsAccount


def test_initial_credit_balance():
    """Test the default initialization of a CreditsAccount."""
    account = CreditsAccount()
    assert account.get_credit_balance() == 0

    account_with_balance = CreditsAccount(100)
    assert account_with_balance.get_credit_balance() == 100


def test_get_credit_balance():
    """Test retrieving the credit balance."""
    account = CreditsAccount(50)
    assert account.get_credit_balance() == 50

    account.credit_credits(20)
    assert account.get_credit_balance() == 70


def test_credit_credits():
    """Test adding credits to the account."""
    account = CreditsAccount(30)

    account.credit_credits(20)
    assert account.get_credit_balance() == 50

    account.credit_credits(0)
    assert account.get_credit_balance() == 50

    account.credit_credits(100)
    assert account.get_credit_balance() == 150


def test_can_debit_credits():
    """Test if the account can debit a given amount."""
    account = CreditsAccount(50)

    assert account.can_debit_credits(30) is True
    assert account.can_debit_credits(50) is True
    assert account.can_debit_credits(51) is False
    assert account.can_debit_credits(0) is True


def test_debit_credits_success():
    """Test successfully debiting credits from the account."""
    account = CreditsAccount(100)

    assert account.debit_credits(50) is True
    assert account.get_credit_balance() == 50

    assert account.debit_credits(50) is True
    assert account.get_credit_balance() == 0


def test_debit_credits_failure():
    """Test failing to debit credits when insufficient balance."""
    account = CreditsAccount(20)

    assert account.debit_credits(30) is False
    assert account.get_credit_balance() == 20

    assert account.debit_credits(21) is False
    assert account.get_credit_balance() == 20

    assert account.debit_credits(0) is True
    assert account.get_credit_balance() == 20


def test_edge_cases():
    """Test edge cases for credit and debit operations."""
    account = CreditsAccount()

    # Adding zero credits
    account.credit_credits(0)
    assert account.get_credit_balance() == 0

    # Debiting zero credits
    assert account.debit_credits(0) is True
    assert account.get_credit_balance() == 0

    # Checking if zero credits can be debited
    assert account.can_debit_credits(0) is True

    # Adding a large number of credits
    large_amount = 10**9
    account.credit_credits(large_amount)
    assert account.get_credit_balance() == large_amount

    # Debiting a large amount
    assert account.debit_credits(large_amount) is True
    assert account.get_credit_balance() == 0
