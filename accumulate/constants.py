# accumulate-python-client\accumulate\constants.py
from decimal import Decimal

# Core Constants
TLD = ".acme"
ACME = "ACME"
UNKNOWN = "unknown"
DIRECTORY = "Directory"
DEFAULT_MAJOR_BLOCK_SCHEDULE = "0 */12 * * *"
ACCOUNT_URL_MAX_LENGTH = 500

# Token and Credit Constants
ACME_SUPPLY_LIMIT = Decimal("500000000")  # ACME token supply limit
ACME_PRECISION = 10**8  # Precision for ACME token amounts (100 million units)
CREDIT_PRECISION = 10**2  # Precision for credit balances (100 units per dollar)
CREDITS_PER_DOLLAR = 10**2  # 100 credits per dollar
DELEGATION_DEPTH_LIMIT = 20  # Maximum allowed delegation depth

# Validation Constants
MAX_CHAIN_ID_LENGTH = 32
LITE_DATA_CHECKSUM_LEN = 4