# C:\Accumulate_Stuff\accumulate-python-client\accumulate\models\accounts.py 


from typing import Optional, List, Tuple, Any
from decimal import Decimal
from hashlib import sha256
from accumulate.models.data_entries import DataEntry
from accumulate.models.key_management import KeySpec
from accumulate.utils.union import UnionValue
from accumulate.utils.url import URL
from .auth import AccountAuth

# Base Classes
class Account(UnionValue):
    """Base class for all account types."""

    def type(self) -> str:
        raise NotImplementedError("Account type not implemented")

    def get_url(self) -> Any:
        raise NotImplementedError("get_url() not implemented")

    def strip_url(self) -> None:
        raise NotImplementedError("strip_url() not implemented")


class FullAccount(Account):
    """Base class for accounts with authentication."""

    def __init__(self, account_auth: Optional['AccountAuth'] = None):
        self.account_auth = account_auth or AccountAuth()

    def get_auth(self) -> 'AccountAuth':
        return self.account_auth


# Account Implementations
class UnknownAccount(Account):
    def __init__(self, url: Any):
        self.url = self._ensure_url(url)

    def _ensure_url(self, url: Any) -> Any:
        """Ensure the URL is a valid instance or parse it."""
        if isinstance(url, str):
            from accumulate.utils.url import URL  # Lazy import
            return URL.parse(url)
        return url

    def get_url(self) -> Any:
        return self.url

    def strip_url(self) -> None:
        self.url = self.url.strip_extras()


class LiteDataAccount(Account):
    def __init__(self, url: Any):
        self.url = self._ensure_url(url)

    def _ensure_url(self, url: Any) -> Any:
        if isinstance(url, str):
            from accumulate.utils.url import URL
            return URL.parse(url)
        return url

    def get_url(self) -> Any:
        return self.url

    def strip_url(self) -> None:
        self.url = self.url.strip_extras()


class LiteIdentity(Account):
    def __init__(self, url: Any, credit_balance: int = 0, last_used_on: Optional[int] = None):
        if url is None:
            raise ValueError("URL cannot be None.")
        if credit_balance < 0:
            raise ValueError("Credit balance cannot be negative.")
        self.url = self._ensure_url(url)
        self.credit_balance = credit_balance
        self.last_used_on = last_used_on

    def _ensure_url(self, url: Any) -> Any:
        if isinstance(url, str):
            from accumulate.utils.url import URL
            return URL.parse(url)
        return url

    def get_url(self) -> Any:
        return self.url

    def strip_url(self) -> None:
        self.url = self.url.strip_extras()

    def get_credit_balance(self) -> int:
        return self.credit_balance

    def get_signature_threshold(self) -> int:
        return 1

    def entry_by_key(self, key: bytes) -> Tuple[int, Optional['LiteIdentity'], bool]:
        key_hash = sha256(key).digest()
        lite_key = self._parse_lite_identity(self.url)
        if lite_key == key_hash[:20]:
            return 0, self, True
        return -1, None, False

    @staticmethod
    def _parse_lite_identity(url: Any) -> bytes:
        return sha256(url.authority.encode()).digest()[:20]


class LiteTokenAccount(Account):
    def __init__(self, url: Any, token_url: Any, balance: Decimal = Decimal("0.00")):
        if url is None or token_url is None:
            raise ValueError("URL and Token URL cannot be None.")
        if balance < 0:
            raise ValueError("Balance cannot be negative.")

        self.url = self._ensure_url(url)
        self.token_url = self._ensure_url(token_url)
        if not self.token_url.path:
            raise ValueError(f"Invalid lite token account URL: {self.token_url}")

        self.balance = balance

    def _ensure_url(self, url: Any) -> Any:
        """Ensure the URL is valid or parse it."""
        if isinstance(url, str):
            from accumulate.utils.url import URL
            return URL.parse(url)
        return url

    def get_url(self) -> Any:
        return self.url

    def strip_url(self) -> None:
        self.url = self.url.strip_extras()

    def token_balance(self) -> Decimal:
        return self.balance

    def credit_tokens(self, amount: Decimal) -> bool:
        if amount <= 0:
            return False
        self.balance += amount
        return True

    def can_debit_tokens(self, amount: Decimal) -> bool:
        return amount > 0 and self.balance >= amount

    def debit_tokens(self, amount: Decimal) -> bool:
        if not self.can_debit_tokens(amount):
            return False
        self.balance -= amount
        return True



class ADI(FullAccount):
    def __init__(self, url: Any, account_auth: Optional['AccountAuth'] = None):
        super().__init__(account_auth)
        self.url = self._ensure_url(url)

    def _ensure_url(self, url: Any) -> Any:
        if isinstance(url, str):
            from accumulate.utils.url import URL
            return URL.parse(url)
        return url

    def get_url(self) -> Any:
        return self.url

    def strip_url(self) -> None:
        self.url = self.url.strip_extras()

class DataAccount(FullAccount):
    def __init__(self, url: Any, account_auth: Optional['AccountAuth'] = None, entry: Optional['DataEntry'] = None):
        super().__init__(account_auth)
        self.url = self._ensure_url(url)
        self.entry = entry

    def _ensure_url(self, url: Any) -> Any:
        if isinstance(url, str):
            from accumulate.utils.url import URL  # Lazy import to avoid circular dependencies
            return URL.parse(url)
        return url

    def get_url(self) -> Any:
        return self.url

    def strip_url(self) -> None:
        self.url = self.url.strip_extras()



class KeyBook(FullAccount):
    def __init__(self, url: Any, account_auth: Optional['AccountAuth'] = None, page_count: int = 0, book_type: str = ''):
        print(f"DEBUG: Initializing KeyBook with URL: {url}, page_count: {page_count}, book_type: {book_type}")
        super().__init__(account_auth)
        self.url = self._ensure_url(url)

        # Enforce additional validation specific to KeyBook
        print(f"DEBUG: Ensured URL in KeyBook: {self.url}")
        self._validate_key_book_url()

        self.page_count = page_count
        self.book_type = book_type
        print(f"DEBUG: KeyBook initialized successfully with URL: {self.url}")

    def _ensure_url(self, url: Any) -> Any:
        from accumulate.utils.url import URL
        if isinstance(url, str):
            print(f"DEBUG: Parsing URL from string in _ensure_url: {url}")
            return URL.parse(url.strip())

        if isinstance(url, URL):
            # Normalize existing URL objects
            if "@" in url.authority or url.authority.endswith("@"):
                raise ValueError(f"Invalid URL: '@' not allowed in authority: {url.authority}")
            if url.authority.startswith("acc://"):
                raise ValueError(f"Invalid URL: Redundant 'acc://' in authority: {url.authority}")

        return url

    def _validate_key_book_url(self):
        """Validation specific to KeyBook URLs."""
        # Ensure the URL path is not empty or just "/"
        if not self.url.path or self.url.path == "/":
            print(f"ERROR: Invalid KeyBook URL - Missing book name in path: {self.url}")
            raise ValueError(f"Invalid KeyBook URL: {self.url} must include a book name in the path.")

        # Ensure the path does not contain invalid characters
        if "@" in self.url.path or " " in self.url.path:
            print(f"ERROR: Invalid KeyBook URL - Invalid characters in path: {self.url}")
            raise ValueError(f"Invalid KeyBook URL: {self.url} contains invalid characters in the path.")

        # Ensure authority is not empty or invalid
        if not self.url.authority or not self.url.authority.strip():
            print(f"ERROR: Invalid KeyBook URL - Missing or empty authority: {self.url}")
            raise ValueError(f"Invalid KeyBook URL: Authority must not be empty in {self.url}")

        # Check for invalid domain names
        if self.url.authority.startswith(".") or self.url.authority.endswith(".com"):
            print(f"ERROR: Invalid KeyBook URL - Invalid domain in authority: {self.url}")
            raise ValueError(f"Invalid KeyBook URL: {self.url} contains invalid domain in authority.")


    def get_url(self) -> Any:
        print(f"DEBUG: Retrieving URL in KeyBook: {self.url}")
        return self.url

    def strip_url(self) -> None:
        print(f"DEBUG: Stripping extras from URL in KeyBook: {self.url}")
        self.url = self.url.strip_extras()
        print(f"DEBUG: URL after stripping: {self.url}")

    def get_signers(self) -> List[Any]:
        print(f"DEBUG: Generating signers for KeyBook with page_count: {self.page_count}")
        signers = [self._format_key_page_url(self.url, i) for i in range(self.page_count)]
        print(f"DEBUG: Generated signers in KeyBook: {[str(signer) for signer in signers]}")
        return signers

    def _format_key_page_url(self, book_url: URL, index: int) -> URL:
        if not book_url.authority or not book_url.path:
            raise ValueError(f"Invalid KeyBook URL: {book_url}")
        
        normalized_path = f"{book_url.path.rstrip('/')}/{index}"
        return URL(authority=book_url.authority, path=normalized_path)










class KeyPage(Account):
    def __init__(self, url: Any, credit_balance: int = 0, accept_threshold: int = 0,
                 reject_threshold: int = 0, response_threshold: int = 0,
                 block_threshold: int = 0, version: int = 0, keys: Optional[List['KeySpec']] = None):
        if url is None:
            raise ValueError("URL cannot be None.")
        if any(threshold < 0 for threshold in [accept_threshold, reject_threshold, response_threshold, block_threshold]):
            raise ValueError("Thresholds cannot be negative.")
        self.url = self._ensure_url(url)
        self.credit_balance = credit_balance
        self.accept_threshold = accept_threshold
        self.reject_threshold = reject_threshold
        self.response_threshold = response_threshold
        self.block_threshold = block_threshold
        self.version = version
        self.keys = keys or []

    def _ensure_url(self, url: Any) -> Any:
        if isinstance(url, str):
            from accumulate.utils.url import URL
            return URL.parse(url)
        return url

    def get_url(self) -> Any:
        return self.url

    def strip_url(self) -> None:
        self.url = self.url.strip_extras()

    def get_signature_threshold(self) -> int:
        return max(1, self.accept_threshold)

    def entry_by_key(self, key: bytes) -> Tuple[int, Optional['KeySpec'], bool]:
        key_hash = sha256(key).digest()
        for i, entry in enumerate(self.keys):
            if entry.public_key_hash == key_hash:  # Use public_key_hash
                return i, entry, True
        return -1, None, False



class TokenAccount(FullAccount):
    def __init__(self, url: Any, token_url: Any, balance: Decimal = Decimal(0), account_auth: Optional['AccountAuth'] = None):
        super().__init__(account_auth)
        self.url = self._ensure_url(url)
        self.token_url = self._ensure_url(token_url)
        self.balance = balance

    def _ensure_url(self, url: Any) -> Any:
        if isinstance(url, str):
            from accumulate.utils.url import URL
            return URL.parse(url)
        return url

    def get_url(self) -> Any:
        return self.url

    def strip_url(self) -> None:
        self.url = self.url.strip_extras()

    def token_balance(self) -> Decimal:
        return self.balance

    def credit_tokens(self, amount: Decimal) -> bool:
        if amount is None or amount < 0:
            return False
        self.balance += amount
        return True

    def can_debit_tokens(self, amount: Decimal) -> bool:
        return amount is not None and self.balance >= amount

    def debit_tokens(self, amount: Decimal) -> bool:
        if not self.can_debit_tokens(amount):
            return False
        self.balance -= amount
        return True


class TokenIssuer(FullAccount):
    def __init__(self, url: Any, symbol: str, precision: int, issued: Decimal = Decimal(0), supply_limit: Optional[Decimal] = None):
        super().__init__()
        self.url = self._ensure_url(url)
        self.symbol = symbol
        self.precision = precision
        self.issued = issued
        self.supply_limit = supply_limit

    def _ensure_url(self, url: Any) -> Any:
        if isinstance(url, str):
            from accumulate.utils.url import URL
            return URL.parse(url)
        return url

    def get_url(self) -> Any:
        return self.url

    def strip_url(self) -> None:
        self.url = self.url.strip_extras()

    def issue(self, amount: Decimal) -> bool:
        if amount < 0:
            raise ValueError("Amount cannot be negative.")
        if self.supply_limit is not None and self.issued + amount > self.supply_limit:
            return False
        self.issued += amount
        return True