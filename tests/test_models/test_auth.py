# accumulate-python-client\tests\test_models\test_auth.py

import unittest
from unittest.mock import Mock
from accumulate.models.auth import AuthorityEntry, AccountAuth
from accumulate.utils.url import URL

class TestAuthorityEntry(unittest.TestCase):
    def test_authority_entry_initialization(self):
        url = URL("acc://example.com")
        authority = AuthorityEntry(url, disabled=True)
        self.assertEqual(authority.url, url)
        self.assertTrue(authority.disabled)

        authority = AuthorityEntry(url)
        self.assertFalse(authority.disabled)

class TestAccountAuth(unittest.TestCase):
    def setUp(self):
        self.url1 = URL("acc://example.com")
        self.url2 = URL("acc://secondary.com")
        self.url3 = URL("acc://tertiary.com")
        self.entry1 = AuthorityEntry(self.url1, disabled=False)
        self.entry2 = AuthorityEntry(self.url2, disabled=True)
        self.auth = AccountAuth(authorities=[self.entry1, self.entry2])

    def test_initialization(self):
        auth = AccountAuth()
        self.assertEqual(auth.authorities, [])

        auth = AccountAuth(authorities=[self.entry1, self.entry2])
        self.assertEqual(auth.authorities, [self.entry1, self.entry2])

    def test_key_book1(self):
        self.assertEqual(self.auth.key_book(), self.url1)

        auth = AccountAuth()
        self.assertIsNone(auth.key_book())

    def test_manager_key_book(self):
        self.assertEqual(self.auth.manager_key_book(), self.url2)

        auth = AccountAuth(authorities=[self.entry1])
        self.assertIsNone(auth.manager_key_book())

    def test_all_authorities_are_disabled(self):
        self.assertFalse(self.auth.all_authorities_are_disabled())

        self.entry1.disabled = True
        self.assertTrue(self.auth.all_authorities_are_disabled())

    def test_get_authority(self):
        authority, found = self.auth.get_authority(self.url1)
        self.assertTrue(found)
        self.assertEqual(authority, self.entry1)

        authority, found = self.auth.get_authority(URL("acc://nonexistent.com"))
        self.assertFalse(found)
        self.assertIsNone(authority)

    def test_add_authority(self):
        # Add an existing authority
        authority, newly_added = self.auth.add_authority(self.url1)
        self.assertFalse(newly_added)
        self.assertEqual(authority, self.entry1)

        # Add a new authority
        authority, newly_added = self.auth.add_authority(self.url3)
        self.assertTrue(newly_added)
        self.assertEqual(authority.url, self.url3)
        self.assertIn(authority, self.auth.authorities)

    def test_remove_authority(self):
        # Remove an existing authority
        removed = self.auth.remove_authority(self.url1)
        self.assertTrue(removed)
        self.assertNotIn(self.entry1, self.auth.authorities)

        # Attempt to remove a non-existent authority
        removed = self.auth.remove_authority(URL("acc://nonexistent.com"))
        self.assertFalse(removed)

    def test_sorted_authorities(self):
        self.auth.add_authority(URL("acc://zeta.com"))
        self.auth.add_authority(URL("acc://alpha.com"))
        self.assertEqual(
            [auth.url for auth in self.auth.authorities],
            [URL("acc://alpha.com"), self.url1, self.url2, URL("acc://zeta.com")]
        )

if __name__ == "__main__":
    unittest.main()
