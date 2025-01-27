# accumulate-python-client\accumulate\models\auth.py

from typing import List, Optional, Tuple
from accumulate.utils.url import URL

class AuthorityEntry:
    """Represents an authority entry with a URL and a disabled flag."""

    def __init__(self, url: URL, disabled: bool = False):
        """
        Initialize an AuthorityEntry.

        :param url: The URL of the authority.
        :param disabled: Boolean flag indicating if the authority is disabled.
        """
        self.url = url
        self.disabled = disabled


class AccountAuth:
    """Manages account authorities for access control."""

    def __init__(self, authorities: Optional[List[AuthorityEntry]] = None):
        """
        Initialize AccountAuth.

        :param authorities: Optional list of AuthorityEntry objects.
        """
        self.authorities: List[AuthorityEntry] = authorities or []

    def key_book(self) -> Optional[URL]:
        """
        Get the primary authority's URL.

        :return: URL of the primary authority or None if not available.
        """
        return self.authorities[0].url if self.authorities else None

    def manager_key_book(self) -> Optional[URL]:
        """
        Get the secondary authority's URL.

        :return: URL of the secondary authority or None if not available.
        """
        return self.authorities[1].url if len(self.authorities) > 1 else None

    def all_authorities_are_disabled(self) -> bool:
        """
        Check if all authorities are disabled.

        :return: True if all authorities are disabled, False otherwise.
        """
        return all(authority.disabled for authority in self.authorities)

    def get_authority(self, entry_url: URL) -> Tuple[Optional[AuthorityEntry], bool]:
        """
        Get an authority entry by its URL.

        :param entry_url: The URL of the authority to find.
        :return: A tuple containing the AuthorityEntry and a boolean indicating if it was found.
        """
        for authority in self.authorities:
            if authority.url == entry_url:
                return authority, True
        return None, False

    def add_authority(self, entry_url: URL) -> Tuple[AuthorityEntry, bool]:
        """
        Add a new authority entry.

        :param entry_url: The URL of the new authority.
        :return: A tuple containing the new or existing AuthorityEntry and a boolean indicating if it was newly added.
        """
        existing_authority, found = self.get_authority(entry_url)
        if found:
            return existing_authority, False
        new_authority = AuthorityEntry(url=entry_url)
        self.authorities.append(new_authority)
        self.authorities.sort(key=lambda auth: auth.url)  # Keep the list sorted
        return new_authority, True

    def remove_authority(self, entry_url: URL) -> bool:
        """
        Remove an authority entry by its URL.

        :param entry_url: The URL of the authority to remove.
        :return: True if the authority was removed, False otherwise.
        """
        for i, authority in enumerate(self.authorities):
            if authority.url == entry_url:
                del self.authorities[i]
                return True
        return False
