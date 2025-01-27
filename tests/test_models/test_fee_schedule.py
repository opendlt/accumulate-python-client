# accumulate-python-client\tests\test_models\test_fee_schedule.py

import pytest
from accumulate.models.fee_schedule import Fee, FeeSchedule
from unittest.mock import MagicMock
import logging

def test_fee_constants():
    """Test the Fee enumeration values."""
    assert Fee.FEE_SIGNATURE == 1
    assert Fee.FEE_CREATE_IDENTITY == 50000
    assert Fee.FEE_TRANSFER_TOKENS == 300
    assert Fee.FEE_CREATE_TOKEN == 500000
    assert Fee.FEE_MINIMUM_CREDIT_PURCHASE == 100

def test_compute_signature_fee_basic():
    """Test computation of a basic signature fee."""
    logger = logging.getLogger(__name__)
    logger.debug("Running test_compute_signature_fee_basic")

    # Configure the mock to simulate a signature
    signature = MagicMock()
    signature.serialize.return_value = b"x" * 100  # 100 bytes
    signature.delegated_signature = None  # No delegation

    # Compute the fee
    fee = FeeSchedule.compute_signature_fee(signature)
    logger.debug(f"Computed fee: {fee}")
    assert fee == Fee.FEE_SIGNATURE


def test_compute_signature_fee_large_signature():
    """Test computation of a fee for a large signature."""
    logger = logging.getLogger(__name__)
    logger.debug("Running test_compute_signature_fee_large_signature")

    # Configure the mock to simulate a large signature
    signature = MagicMock()
    signature.serialize.return_value = b"x" * 600  # 600 bytes
    signature.delegated_signature = None  # No delegation

    # Compute the fee
    fee = FeeSchedule.compute_signature_fee(signature)
    expected_chunks = (600 - 1) // 256 + 1
    expected_fee = Fee.FEE_SIGNATURE + Fee.FEE_SIGNATURE * (expected_chunks - 1)
    logger.debug(f"Computed fee: {fee}, Expected fee: {expected_fee}")
    assert fee == expected_fee




def test_compute_signature_fee_with_delegated():
    """Test computation of a fee for a signature with delegation."""
    logger = logging.getLogger(__name__)

    delegated_signature = MagicMock()
    delegated_signature.serialize.return_value = b"x" * 100  # 100 bytes
    delegated_signature.delegated_signature = None

    signature = MagicMock()
    signature.serialize.return_value = b"x" * 300  # 300 bytes
    signature.delegated_signature = delegated_signature

    fee = FeeSchedule.compute_signature_fee(signature)
    expected_chunks = (300 - 1) // 256 + 1
    expected_fee = Fee.FEE_SIGNATURE + Fee.FEE_SIGNATURE * (expected_chunks - 1) + Fee.FEE_SIGNATURE

    logger.debug(f"Expected fee: {expected_fee}, Calculated fee: {fee}")
    assert fee == expected_fee




def test_compute_signature_fee_oversized():
    """Test computation for an oversized signature."""
    signature = MagicMock()
    signature.serialize.return_value = b"x" * 2000  # 2000 bytes

    with pytest.raises(ValueError, match="Signature size exceeds 1024 bytes."):
        FeeSchedule.compute_signature_fee(signature, signature_size_max=1024)


def test_compute_transaction_fee_create_token():
    """Test computation of transaction fee for creating a token."""
    transaction = MagicMock()
    transaction.serialize.return_value = b"x" * 500  # 500 bytes
    transaction.body.type.return_value = "CreateToken"

    fee = FeeSchedule.compute_transaction_fee(transaction)
    expected_chunks = (500 - 1) // 256 + 1
    expected_fee = Fee.FEE_CREATE_TOKEN + Fee.FEE_DATA * (expected_chunks - 1)
    assert fee == expected_fee


def test_compute_transaction_fee_send_tokens():
    """Test computation of transaction fee for sending tokens."""
    transaction = MagicMock()
    transaction.serialize.return_value = b"x" * 700  # 700 bytes
    transaction.body.type.return_value = "SendTokens"
    transaction.body.to = [1, 2, 3]  # Sending tokens to three recipients

    fee = FeeSchedule.compute_transaction_fee(transaction)
    expected_chunks = (700 - 1) // 256 + 1
    expected_fee = (
        Fee.FEE_TRANSFER_TOKENS
        + Fee.FEE_TRANSFER_TOKENS_EXTRA * 2  # Two additional recipients
        + Fee.FEE_DATA * (expected_chunks - 1)
    )
    assert fee == expected_fee


def test_compute_transaction_fee_general_small():
    """Test computation of a general small transaction fee."""
    transaction = MagicMock()
    transaction.serialize.return_value = b"x" * 400  # 400 bytes
    transaction.body.type.return_value = "OtherType"

    fee = FeeSchedule.compute_transaction_fee(transaction)
    expected_chunks = (400 - 1) // 256 + 1
    expected_fee = Fee.FEE_GENERAL_SMALL + Fee.FEE_DATA * (expected_chunks - 1)
    assert fee == expected_fee


def test_compute_transaction_fee_oversized():
    """Test computation for an oversized transaction."""
    transaction = MagicMock()
    transaction.serialize.return_value = b"x" * 30000  # 30000 bytes

    with pytest.raises(ValueError, match="Transaction size exceeds 20480 bytes."):
        FeeSchedule.compute_transaction_fee(transaction, transaction_size_max=20480)


def test_compute_synthetic_refund():
    """Test computation of synthetic refund for a transaction."""
    transaction = MagicMock()
    transaction.serialize.return_value = b"x" * 500  # 500 bytes
    transaction.body.type.return_value = "SendTokens"

    refund = FeeSchedule.compute_synthetic_refund(transaction, synth_count=1)
    assert refund == Fee.FEE_TRANSFER_TOKENS_EXTRA


def test_compute_synthetic_refund_no_refund():
    """Test no refund for a transaction under the minimum fee."""
    transaction = MagicMock()
    transaction.serialize.return_value = b"x" * 100  # 100 bytes
    transaction.body.type.return_value = "OtherType"

    refund = FeeSchedule.compute_synthetic_refund(transaction, synth_count=1)
    assert refund == 0


def test_compute_synthetic_refund_multiple_outputs():
    """Test error for synthetic refund with multiple outputs."""
    transaction = MagicMock()
    transaction.serialize.return_value = b"x" * 500  # 500 bytes
    transaction.body.type.return_value = "SendTokens"

    with pytest.raises(ValueError, match="A SendTokens transaction cannot have multiple outputs."):
        FeeSchedule.compute_synthetic_refund(transaction, synth_count=2)

