# accumulate-python-client\accumulate\models\options.py

from dataclasses import dataclass, field
from typing import Optional


@dataclass
class RangeOptions:
    """Options for querying ranges."""
    start: Optional[int] = None  # Starting index
    count: Optional[int] = None  # Number of results to return
    expand: Optional[bool] = None  # Request expanded results
    from_end: Optional[bool] = False  # Query from the end

    def to_dict(self) -> dict:
        """Convert RangeOptions to a dictionary."""
        return {
            "start": self.start,
            "count": self.count,
            "expand": self.expand,
            "from_end": self.from_end,
        }

@dataclass
class SubmitOptions:
    """Options for submitting transactions."""
    verify: Optional[bool] = True  # Verify the envelope before submitting
    wait: Optional[bool] = True  # Wait for inclusion into a block or rejection


@dataclass
class ValidateOptions:
    """Options for validating transactions."""
    full: Optional[bool] = True  # Fully validate signatures and transactions


@dataclass
class FaucetOptions:
    """Options for requesting tokens from the faucet."""
    token: Optional[str] = None  # Token URL


@dataclass
class SubscribeOptions:
    """Options for subscribing to events."""
    partition: Optional[str] = None  # Partition name
    account: Optional[str] = None  # Account URL


@dataclass
class ReceiptOptions:
    """Options for querying receipts."""
    for_any: bool = False  # Query for any receipt
    for_height: Optional[int] = None  # Query for receipts at a specific height

    def to_dict(self) -> dict:
        """Convert ReceiptOptions to a dictionary."""
        return {
            "for_any": self.for_any,
            "for_height": self.for_height,
        }

    def is_valid(self) -> bool:
        """Validate the receipt options."""
        return self.for_any or self.for_height is not None

