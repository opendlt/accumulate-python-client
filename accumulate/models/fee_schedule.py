# accumulate-python-client\accumulate\models\fee_schedule.py

from typing import Union, List
from accumulate.utils.url import URL
from accumulate.models.transactions import Transaction
from accumulate.models.signatures import Signature

import logging

class Fee:
    """Enumeration of transaction fees in credits."""
    FEE_FAILED_MAXIMUM = 100  # $0.01
    FEE_SIGNATURE = 1         # $0.0001
    FEE_CREATE_IDENTITY = 50000  # $5.00
    FEE_CREATE_DIRECTORY = 1000  # $0.10
    FEE_CREATE_ACCOUNT = 2500    # $0.25
    FEE_TRANSFER_TOKENS = 300    # $0.03
    FEE_TRANSFER_TOKENS_EXTRA = 100  # $0.01
    FEE_CREATE_TOKEN = 500000    # $50.00
    FEE_GENERAL_TINY = 1         # $0.001
    FEE_GENERAL_SMALL = 10       # $0.001
    FEE_CREATE_KEY_PAGE = 10000  # $1.00
    FEE_CREATE_KEY_PAGE_EXTRA = 100  # $0.01
    FEE_DATA = 10                # $0.001 / 256 bytes
    FEE_SCRATCH_DATA = 1         # $0.0001 / 256 bytes
    FEE_UPDATE_AUTH = 300        # $0.03
    FEE_UPDATE_AUTH_EXTRA = 100  # $0.01
    FEE_MINIMUM_CREDIT_PURCHASE = 100  # $0.01


# Configure the logger
logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)

class FeeSchedule:
    @staticmethod
    def compute_signature_fee(sig: Signature, signature_size_max: int = 1024) -> int:
        logger.debug(f"Starting compute_signature_fee with signature: {sig}")
        size = len(sig.serialize())
        logger.debug(f"Initial signature size: {size}")
        if size > signature_size_max:
            raise ValueError(f"Signature size exceeds {signature_size_max} bytes.")

        fee = Fee.FEE_SIGNATURE
        chunks = max(1, (size - 1) // 256 + 1)
        fee += Fee.FEE_SIGNATURE * (chunks - 1)
        logger.debug(f"Fee after chunk calculation for main signature: {fee} (chunks: {chunks})")

        visited_signatures = set()  # Avoid repeated processing
        while sig and hasattr(sig, "delegated_signature"):
            if sig in visited_signatures:
                raise RuntimeError("Circular delegation detected.")
            visited_signatures.add(sig)

            sig = sig.delegated_signature
            if sig is None:  # Break if no further delegation
                break

            size = len(sig.serialize())
            logger.debug(f"Delegated signature size: {size}")

            chunks = max(1, (size - 1) // 256 + 1)
            fee += Fee.FEE_SIGNATURE * chunks
            logger.debug(f"Updated fee after processing delegated signature: {fee}")

        logger.debug(f"Final computed fee: {fee}")
        return fee



    @staticmethod
    def compute_transaction_fee(tx: Transaction, transaction_size_max: int = 20480) -> int:
        """
        Compute the fee for a given transaction.

        :param tx: The transaction object.
        :param transaction_size_max: Maximum allowed size for a transaction.
        :return: The calculated fee in credits.
        """
        size = len(tx.serialize())
        if size > transaction_size_max:
            raise ValueError(f"Transaction size exceeds {transaction_size_max} bytes.")

        fee = 0
        count = max(1, (size - 1) // 256 + 1)

        tx_type = tx.body.type()
        if tx_type == "CreateToken":
            fee = Fee.FEE_CREATE_TOKEN + Fee.FEE_DATA * (count - 1)
        elif tx_type == "CreateIdentity":
            fee = Fee.FEE_CREATE_IDENTITY + Fee.FEE_DATA * (count - 1)
        elif tx_type in {"CreateTokenAccount", "CreateDataAccount"}:
            fee = Fee.FEE_CREATE_ACCOUNT + Fee.FEE_DATA * (count - 1)
        elif tx_type == "SendTokens":
            fee = (
                Fee.FEE_TRANSFER_TOKENS
                + Fee.FEE_TRANSFER_TOKENS_EXTRA * (len(tx.body.to) - 1)
                + Fee.FEE_DATA * (count - 1)
            )
        elif tx_type == "CreateKeyPage":
            fee = (
                Fee.FEE_CREATE_KEY_PAGE
                + Fee.FEE_CREATE_KEY_PAGE_EXTRA * (len(tx.body.keys) - 1)
                + Fee.FEE_DATA * (count - 1)
            )
        else:
            fee = Fee.FEE_GENERAL_SMALL + Fee.FEE_DATA * (count - 1)

        return fee

    @staticmethod
    def compute_synthetic_refund(tx: Transaction, synth_count: int) -> int:
        paid = FeeSchedule.compute_transaction_fee(tx)
        if paid <= Fee.FEE_FAILED_MAXIMUM:
            return 0

        tx_type = tx.body.type()
        if tx_type in {"SendTokens", "IssueTokens"}:
            if synth_count > 1:  # Ensure this condition is correctly evaluated
                raise ValueError(f"A {tx_type} transaction cannot have multiple outputs.")
            return Fee.FEE_TRANSFER_TOKENS_EXTRA

        return paid - Fee.FEE_FAILED_MAXIMUM

