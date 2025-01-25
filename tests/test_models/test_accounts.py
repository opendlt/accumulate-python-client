# C:\Accumulate_Stuff\accumulate-python-client\tests\test_models\test_accounts.py

import unittest
from decimal import Decimal
from hashlib import sha256
from accumulate.models.accounts import (
    UnknownAccount,
    LiteDataAccount,
    LiteIdentity,
    LiteTokenAccount,
    ADI,
    DataAccount,
    KeyBook,
    KeyPage,
    TokenAccount,
    TokenIssuer,
)
from accumulate.models.key_management import KeySpec
from accumulate.utils.url import URL


class TestAccounts(unittest.TestCase):

    def test_unknown_account(self):
        url = URL("acc://example.com")
        account = UnknownAccount(url)
        self.assertEqual(account.get_url(), url)
        account.strip_url()
        # Check that strip_url doesn't modify the path if it's empty
        self.assertEqual(account.get_url().path, url.path)

    def test_lite_data_account(self):
        url = URL("acc://example.com")
        account = LiteDataAccount(url)
        self.assertEqual(account.get_url(), url)
        account.strip_url()
        self.assertEqual(account.get_url().path, url.path)

    def test_lite_identity(self):
        url = URL("acc://example.acme")
        account = LiteIdentity(url, credit_balance=100, last_used_on=12345)
        self.assertEqual(account.get_url(), url)
        self.assertEqual(account.get_credit_balance(), 100)
        self.assertEqual(account.get_signature_threshold(), 1)

        # Test key matching
        key = b"test-key"
        key_hash = sha256(key).digest()
        lite_key = sha256(url.authority.encode()).digest()[:20]
        index, matched_account, is_match = account.entry_by_key(key)
        self.assertEqual(index, 0 if lite_key == key_hash[:20] else -1)
        self.assertEqual(matched_account, account if lite_key == key_hash[:20] else None)
        self.assertEqual(is_match, lite_key == key_hash[:20])

    def test_lite_token_account(self):
        url = URL("acc://example.com")
        token_url = URL(authority="example.com", path="/ACME")  # Correctly formatted token URL
        account = LiteTokenAccount(url, token_url, balance=Decimal("100.50"))
        self.assertEqual(account.get_url(), url)
        self.assertEqual(account.token_balance(), Decimal("100.50"))
        self.assertEqual(account.token_url.path, "/ACME")

        # Validate credit and debit
        self.assertTrue(account.credit_tokens(Decimal("50.50")))
        self.assertEqual(account.token_balance(), Decimal("151.00"))
        self.assertTrue(account.debit_tokens(Decimal("50.50")))
        self.assertEqual(account.token_balance(), Decimal("100.50"))

    def test_adi(self):
        url = URL("acc://example.com")
        account = ADI(url)
        self.assertEqual(account.get_url(), url)
        account.strip_url()
        self.assertEqual(account.get_url().path, url.path)

    def test_data_account(self):
        url = URL("acc://example.com")
        account = DataAccount(url, entry=None)
        self.assertEqual(account.get_url(), url)
        self.assertIsNone(account.entry)
        account.strip_url()
        self.assertEqual(account.get_url().path, url.path)



    def test_key_book_validation(self):
        """Test validation of KeyBook URLs with detailed error message matching."""
        valid_key_book_urls = [
            URL(authority="DefiDevs.acme", path="/book"),      # Standard format
            URL(authority="DefiDevs.acme", path="/myBook"),   # Custom book name
            URL(authority="DefiDevs.acme", path="/book0"),    # Numeric suffix
        ]
        invalid_key_book_cases = [
            (URL(authority="DefiDevs.acme", path="/"), "Invalid KeyBook URL: .* must include a book name in the path."),
            (
                URL(authority="DefiDevs.acme@", path="/book"),
                r"(Invalid URL: '@' not allowed in authority: .*|Invalid KeyBook URL: .* contains invalid characters in the path\.)"
            ),
            (URL(authority="", path="/book"), "Invalid KeyBook URL: Authority must not be empty in .*"),
            (URL(authority=".com", path="/book"), "Invalid KeyBook URL: .* contains invalid domain in authority."),
            (URL(authority="DefiDevs.acme", path="/@"), "Invalid KeyBook URL: .* contains invalid characters in the path."),
        ]

        # Validate valid KeyBook URLs
        for url in valid_key_book_urls:
            account = KeyBook(url, page_count=2, book_type="test-book")
            self.assertEqual(account.get_url(), url)

        # Validate invalid KeyBook URLs
        for url, expected_error in invalid_key_book_cases:
            with self.assertRaisesRegex(ValueError, expected_error):
                KeyBook(url, page_count=2, book_type="test-book")




    def test_key_book(self):
        """Test KeyBook with various URL configurations."""
        # Test with a valid URL including a book name in the path
        url = URL(authority="DefiDevs.acme", path="/book")
        account = KeyBook(url, page_count=2, book_type="test-book")

        # Validate KeyBook URL
        self.assertEqual(account.get_url(), url)

        # Generate and validate signer URLs
        generated_signers = account.get_signers()
        expected_signers = [
            URL(authority="DefiDevs.acme", path="/book/0"),
            URL(authority="DefiDevs.acme", path="/book/1"),
        ]
        self.assertEqual(generated_signers, expected_signers)

        # Test stripping extras from the KeyBook URL
        account.strip_url()
        self.assertEqual(account.get_url().path, "/book")

        # Test with a redundant prefix
        redundant_url = URL(authority="DefiDevs.acme", path="/book")
        account = KeyBook(redundant_url, page_count=2, book_type="test-book")
        self.assertEqual(account.get_url().authority, "DefiDevs.acme")

        # Test with an invalid URL missing the book name
        with self.assertRaises(ValueError):
            KeyBook(URL(authority="DefiDevs.acme", path="/"), page_count=2, book_type="test-book")

        # Test with a trailing '@'
        with self.assertRaises(ValueError):
            KeyBook(URL(authority="DefiDevs.acme@", path="/book"), page_count=2, book_type="test-book")










    def test_key_page(self):
        url = URL("acc://example.com")
        key_spec = KeySpec(public_key_hash=sha256(b"key").digest())
        account = KeyPage(url, credit_balance=100, keys=[key_spec])
        self.assertEqual(account.get_url(), url)
        self.assertEqual(account.get_signature_threshold(), 1)

        index, entry, is_match = account.entry_by_key(b"key")
        self.assertEqual(index, 0)
        self.assertEqual(entry, key_spec)
        self.assertTrue(is_match)

    def test_token_account(self):
        url = URL("acc://example.com")
        token_url = URL("acc://example.com/ACME")
        account = TokenAccount(url, token_url, balance=Decimal("100.00"))
        self.assertEqual(account.get_url(), url)
        self.assertEqual(account.token_balance(), Decimal("100.00"))

        # Test credit and debit
        self.assertTrue(account.credit_tokens(Decimal("50.00")))
        self.assertEqual(account.token_balance(), Decimal("150.00"))
        self.assertFalse(account.credit_tokens(Decimal("-10")))  # Negative credit
        self.assertTrue(account.debit_tokens(Decimal("50.00")))
        self.assertFalse(account.debit_tokens(Decimal("200.00")))  # Overdraw

    def test_token_issuer(self):
        url = URL("acc://example.com")
        account = TokenIssuer(url, "SYM", 2, issued=Decimal("50.00"), supply_limit=Decimal("100.00"))
        self.assertEqual(account.get_url(), url)
        self.assertTrue(account.issue(Decimal("50.00")))  # Within limit
        self.assertFalse(account.issue(Decimal("10.00")))  # Exceeds limit
        self.assertEqual(account.issued, Decimal("100.00"))

    def test_invalid_inputs(self):
        with self.assertRaises(ValueError):
            LiteIdentity(None)  # Invalid URL

        with self.assertRaises(ValueError):
            LiteIdentity(URL("acc://example.com"), credit_balance=-10)  # Negative credit balance

        with self.assertRaises(ValueError):
            LiteTokenAccount(URL("acc://example.com"), URL("acc://example.com/ACME"), balance=Decimal("-10"))  # Negative balance

        with self.assertRaises(ValueError):
            KeyPage(URL("acc://example.com"), accept_threshold=-1)  # Invalid threshold

    def test_edge_cases(self):
        url = URL("acc://0143b52490530b90eef9b1a2405e322c6badc1e90e200c56")
        token_url = "acc://0143b52490530b90eef9b1a2405e322c6badc1e90e200c56/ACME"
        account = LiteTokenAccount(url, token_url, balance=Decimal("0.00"))

        # Debit with zero balance
        self.assertFalse(account.debit_tokens(Decimal("10.00")))
        self.assertEqual(account.token_balance(), Decimal("0.00"))

        # LiteIdentity with empty credit balance
        identity = LiteIdentity(url, credit_balance=0)
        self.assertEqual(identity.get_credit_balance(), 0)

        # TokenIssuer with no supply limit
        issuer = TokenIssuer(url, "SYM", 2, issued=Decimal("0.00"), supply_limit=None)
        self.assertTrue(issuer.issue(Decimal("1000.00")))  # Unlimited supply


if __name__ == "__main__":
    unittest.main()
