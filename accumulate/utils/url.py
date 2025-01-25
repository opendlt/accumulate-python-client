# C:\Accumulate_Stuff\accumulate-python-client\accumulate\utils\url.py 

import logging
import hashlib
import re
import urllib.parse
from threading import Lock
from typing import Optional, Any
from accumulate.constants import TLD, ACCOUNT_URL_MAX_LENGTH

# Define custom exceptions
class URLParseError(Exception):
    """Base class for URL parsing errors."""


class MissingHostError(URLParseError):
    """Raised when a URL does not include a hostname."""


class WrongSchemeError(URLParseError):
    """Raised when a URL includes an invalid scheme."""


class MissingHashError(URLParseError):
    """Raised when a transaction ID does not include a hash."""


class InvalidHashError(URLParseError):
    """Raised when a transaction ID includes an invalid hash."""


# Helper functions for detailed error messages
def missing_host(url: str) -> MissingHostError:
    return MissingHostError(f"Missing host in URL: {url}")


def wrong_scheme(url: str) -> WrongSchemeError:
    return WrongSchemeError(f"Wrong scheme in URL: {url}. Expected 'acc://'.")


def missing_hash(url: str) -> MissingHashError:
    return MissingHashError(f"{url} is not a transaction ID: Missing hash.")


def invalid_hash(url: str, error_details: Any) -> InvalidHashError:
    return InvalidHashError(f"{url} is not a transaction ID: Invalid hash. Details: {error_details}")


class URL:
    def __init__(self, user_info: str = "", authority: str = "", path: str = "", query: str = "", fragment: str = ""):
        self.user_info = user_info
        self.authority = authority
        self.path = self._normalize_path(path)
        self.query = query
        self.fragment = fragment

        # Memoized values
        self._str_cache = None
        self._hash_cache = None
        self._account_id_cache = None
        self._identity_id_cache = None
        self._lock = Lock()


    @staticmethod
    def _normalize_path(path: str) -> str:
        """Normalize a path to ensure it is clean and starts with a '/'."""
        path = path.strip("/")
        return f"/{path}" if path else ""



    @staticmethod
    def parse(url_str: str) -> "URL":
        """Parse a string into an Accumulate URL."""
        print(f"DEBUG: Starting parse method with URL string: {url_str}")

        # Validate input
        if not url_str:
            print(f"ERROR: Received empty URL string.")
            raise ValueError("URL string cannot be empty.")

        # Ensure correct scheme
        if not url_str.startswith("acc://"):
            print(f"ERROR: Invalid scheme detected. URL must start with 'acc://', got: {url_str}")
            raise wrong_scheme(url_str)

        # Normalize URL by removing redundant prefixes
        original_url_str = url_str
        while url_str.startswith("acc://acc://"):
            url_str = url_str.replace("acc://acc://", "acc://")
        if url_str != original_url_str:
            print(f"DEBUG: Normalized URL by removing redundant prefixes. Before: {original_url_str}, After: {url_str}")
        else:
            print(f"DEBUG: No redundant prefixes detected in URL string: {url_str}")

        # Prevent URLs from ending with '@'
        if url_str.endswith("@"):
            print(f"WARNING: URL ends with '@'. Cleaning it up: {url_str}")
            url_str = url_str.rstrip("@")

        # Parse components using urllib
        print(f"DEBUG: Parsing URL components using urllib.parse: {url_str}")
        parsed = urllib.parse.urlparse(url_str)
        print(f"DEBUG: Parsed URL result: {parsed}")

        # Verify scheme consistency
        if parsed.scheme != "acc":
            print(f"ERROR: Invalid scheme detected after parsing. Found: {parsed.scheme}, Expected: 'acc'")
            raise wrong_scheme(url_str)

        # Ensure a valid netloc (authority)
        if not parsed.netloc:
            print(f"ERROR: Parsed URL missing authority component. URL: {url_str}, netloc: {parsed.netloc}")
            raise missing_host(url_str)

        # Validate and handle user_info and authority
        user_info, authority = "", parsed.netloc
        print(f"DEBUG: Initial netloc value: {parsed.netloc}")
        if "@" in parsed.netloc:
            print(f"DEBUG: '@' character found in netloc. Splitting into user_info and authority.")
            parts = parsed.netloc.split("@", 1)
            if len(parts) != 2 or not parts[0] or not parts[1]:
                print(f"ERROR: Invalid '@' usage in netloc. Netloc: {parsed.netloc}")
                raise ValueError("Invalid URL: '@' must separate valid user info and authority.")
            user_info, authority = parts
            print(f"DEBUG: Extracted user_info: {user_info}, authority: {authority}")
        else:
            print(f"DEBUG: No user_info detected in netloc. Authority: {authority}")

        # Ensure the authority is not empty
        if not authority:
            print(f"ERROR: Empty authority component detected in URL: {url_str}")
            raise ValueError("Invalid URL: Authority cannot be empty.")

        # Reject .com domains in the authority
        if authority.endswith(".com"):
            print(f"ERROR: Authority ends with '.com', which is not allowed: {authority}")
            raise ValueError(f"Invalid authority domain: {authority}. Domains ending with '.com' are not allowed.")

        print(f"DEBUG: Finalized components - user_info: {user_info}, authority: {authority}, path: {parsed.path}, query: {parsed.query}, fragment: {parsed.fragment}")

        return URL(
            user_info=user_info,
            authority=authority,
            path=parsed.path,
            query=parsed.query,
            fragment=parsed.fragment,
        )



    def marshal(self) -> bytes:
        url_str = f"acc://{self.user_info + '@' if self.user_info else ''}{self.authority}{self.path or ''}"
        print(f"DEBUG: Marshaling URL to string: {url_str}")
        return url_str.encode('utf-8')

    @staticmethod
    def unmarshal(data: bytes) -> "URL":
        url_str = data.decode('utf-8')
        print(f"DEBUG: Unmarshaling URL from string: {url_str}")
        return URL.parse(url_str)

    def __str__(self) -> str:
        if self._str_cache is None:
            components = []
            if self.user_info:
                components.append(self.user_info)
            components.append(self.authority.replace("acc://", "", 1))  
            if self.path:
                components.append(self.path)
            if self.query:
                components.append(f"?{self.query}")
            if self.fragment:
                components.append(f"#{self.fragment}")

            self._str_cache = "".join(components)
        return self._str_cache





    def __eq__(self, other: Any) -> bool:
        """Equality operator for URLs (case-insensitive)."""
        return isinstance(other, URL) and str(self).lower() == str(other).lower()

    def __lt__(self, other: "URL") -> bool:
        """Comparison operator for URLs."""
        return str(self).lower() < str(other).lower()

    def with_user_info(self, user_info: str) -> "URL":
        """Return a new URL with modified user info."""
        return URL(user_info=user_info, authority=self.authority, path=self.path, query=self.query, fragment=self.fragment)

    def with_path(self, path: str) -> "URL":
        """Return a new URL with modified path."""
        return URL(user_info=self.user_info, authority=self.authority, path=path, query=self.query, fragment=self.fragment)

    def with_query(self, query: str) -> "URL":
        """Return a new URL with modified query."""
        return URL(user_info=self.user_info, authority=self.authority, path=self.path, query=query, fragment=self.fragment)

    def strip_extras(self) -> "URL":
        """Return a URL with only the authority and path."""
        return URL(authority=self.authority, path=self.path)

    def root_identity(self) -> "URL":
        """Return the root identity (authority only)."""
        return URL(authority=self.authority)

    def identity(self) -> "URL":
        """Return the identity (parent path)."""
        parent_path = self.path.rsplit("/", 1)[0]
        return URL(authority=self.authority, path=parent_path)

    def account_id(self) -> bytes:
        """Generate the Account ID hash."""
        if not self._account_id_cache:
            normalized = f"{self.authority}{self.path}".lower()
            self._account_id_cache = hashlib.sha256(normalized.encode()).digest()
        return self._account_id_cache

    def identity_id(self) -> bytes:
        """Generate the Identity ID hash."""
        if not self._identity_id_cache:
            normalized = self.authority.split(":")[0].lower()
            self._identity_id_cache = hashlib.sha256(normalized.encode()).digest()
        return self._identity_id_cache

    def hash(self) -> bytes:
        """Generate a hash of the entire URL."""
        if not self._hash_cache:
            account_hash = self.account_id()
            query_hash = hashlib.sha256(self.query.encode()).digest() if self.query else b""
            fragment_hash = hashlib.sha256(self.fragment.encode()).digest() if self.fragment else b""
            self._hash_cache = hashlib.sha256(account_hash + query_hash + fragment_hash).digest()
        return self._hash_cache

    def valid_utf8(self) -> bool:
        """Validate that all components are UTF-8."""
        components = [self.user_info, self.authority, self.path, self.query, self.fragment]
        return all((comp.encode("utf-8", "strict") if comp else True) for comp in components)
