# accumulate-python-client\tests\test_models\test_accounts.py

import unittest
from decimal import Decimal
from hashlib import sha256
from unittest.mock import MagicMock, patch
from accumulate.models.accounts import (
    Account,
    FullAccount,
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
        # Patch DataEntry.__init__ so that if called without data,
        # it defaults to an empty list.
        from accumulate.models.data_entries import DataEntry
        with patch.object(DataEntry, "__init__", lambda self, data=[]: setattr(self, "data", data)):
            account = DataAccount(url, entry=None)
            self.assertEqual(account.get_url(), url)
            # Now lazy instantiation creates a DataEntry with empty data.
            self.assertEqual(account.entry.get_data(), [])
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

#######################
#######################

    def test_account_type_not_implemented(self):
        """Test the `type` method in `Account` base class."""
        account = Account()
        with self.assertRaises(NotImplementedError, msg="Account type not implemented"):
            account.type()  # #

    def test_account_get_url_not_implemented(self):
        """Test the `get_url` method in `Account` base class."""
        account = Account()
        with self.assertRaises(NotImplementedError, msg="get_url() not implemented"):
            account.get_url()  # #

    def test_account_strip_url_not_implemented(self):
        """Test the `strip_url` method in `Account` base class."""
        account = Account()
        with self.assertRaises(NotImplementedError, msg="strip_url() not implemented"):
            account.strip_url()  # #

    def test_full_account_get_auth(self):
        """Test the `get_auth` method in `FullAccount`."""
        mock_auth = MagicMock()
        account = FullAccount(account_auth=mock_auth)
        self.assertEqual(account.get_auth(), mock_auth)  # #

    def test_unknown_account_ensure_url(self):
        """Test the `_ensure_url` method in `UnknownAccount`."""
        with patch("accumulate.models.accounts.URL.parse", return_value="parsed_url") as mock_parse:
            account = UnknownAccount(url="test_url")
            self.assertEqual(account.url, "parsed_url")  # #
            mock_parse.assert_called_once_with("test_url")  # #

    def test_lite_data_account_ensure_url(self):
        """Test the `_ensure_url` method in `LiteDataAccount`."""
        with patch("accumulate.models.accounts.URL.parse", return_value="parsed_url") as mock_parse:
            account = LiteDataAccount(url="test_url")
            self.assertEqual(account.url, "parsed_url")  # #
            mock_parse.assert_called_once_with("test_url")  # #

    def test_lite_identity_entry_by_key_match(self):
        """Test the `entry_by_key` method in `LiteIdentity` when key matches."""
        # Mock URL with a known authority
        mock_url = MagicMock()
        mock_url.authority = "test_key"  # Align key and URL authority

        # Create a LiteIdentity instance
        account = LiteIdentity(url=mock_url, credit_balance=100)

        # Define the test key and its expected hash
        key = b"test_key"  # Match key to the mock URL's authority
        key_hash = sha256(key).digest()
        expected_lite_key = sha256(mock_url.authority.encode()).digest()[:20]

        print(f"[DEBUG] key_hash[:20]: {key_hash[:20].hex()}")
        print(f"[DEBUG] expected_lite_key: {expected_lite_key.hex()}")

        # Patch `_parse_lite_identity` to return the expected lite key
        with patch.object(LiteIdentity, "_parse_lite_identity", return_value=expected_lite_key):
            # Execute the method under test
            result = account.entry_by_key(key)

            # Print the result
            print(f"[DEBUG] entry_by_key result: {result}")

            # Assert that the result matches the expected output
            self.assertEqual(result, (0, account, True))

    def test_lite_identity_entry_by_key_no_match(self):
        """Test the `entry_by_key` method in `LiteIdentity` when key does not match."""
        mock_url = MagicMock()
        mock_url.authority = "test_authority"
        account = LiteIdentity(url=mock_url, credit_balance=100)

        key = b"test_key"
        key_hash = sha256(key).digest()
        mismatched_lite_key = b"non_matching_key"

        with patch.object(LiteIdentity, "_parse_lite_identity", return_value=mismatched_lite_key):
            result = account.entry_by_key(key)
            self.assertEqual(result, (-1, None, False))  # #

    def test_lite_identity_ensure_url(self):
        """Test the `_ensure_url` method in `LiteIdentity`."""
        # Test with a string URL
        string_url = "acc://example.url"
        expected_parsed_url = MagicMock()
        with patch("accumulate.models.accounts.URL.parse", return_value=expected_parsed_url) as mock_parse:
            identity = LiteIdentity(url=string_url)
            self.assertEqual(identity.url, expected_parsed_url)
            mock_parse.assert_called_once_with(string_url)

        # Test with a pre-parsed URL
        pre_parsed_url = MagicMock()
        identity = LiteIdentity(url=pre_parsed_url)
        self.assertEqual(identity.url, pre_parsed_url)

    def test_lite_identity_strip_url(self):
        """Test the `strip_url` method in `LiteIdentity`."""
        mock_url = MagicMock()
        identity = LiteIdentity(url=mock_url)

        # Call `strip_url` and check that `strip_extras` was called
        identity.strip_url()
        mock_url.strip_extras.assert_called_once()


    def test_lite_token_account_url_token_url_none(self):
        """Test that ValueError is raised when URL or Token URL is None."""
        with self.assertRaises(ValueError, msg="URL and Token URL cannot be None."):
            LiteTokenAccount(url=None, token_url=MagicMock(path="/token"))
        with self.assertRaises(ValueError, msg="URL and Token URL cannot be None."):
            LiteTokenAccount(url=MagicMock(path="/account"), token_url=None)


    def test_lite_token_account_invalid_token_url(self):
        """Test that ValueError is raised for an invalid token URL."""
        url = MagicMock()
        token_url = MagicMock()
        token_url.path = ""  # Simulate invalid token URL with an empty path

        with self.assertRaises(ValueError) as context:
            LiteTokenAccount(url=url, token_url=token_url)
        self.assertIn("Invalid lite token account URL", str(context.exception))

    def test_lite_token_account_strip_url(self):
        """Test the `strip_url` method of `LiteTokenAccount`."""
        mock_url = MagicMock()
        token_url = MagicMock()
        mock_url.strip_extras = MagicMock()
        account = LiteTokenAccount(url=mock_url, token_url=token_url)
        account.strip_url()
        mock_url.strip_extras.assert_called_once()

    def test_lite_token_account_credit_tokens_invalid_amount(self):
        """Test that `credit_tokens` returns False for invalid amounts."""
        url = MagicMock()
        token_url = MagicMock()
        token_url.path = "/token"

        account = LiteTokenAccount(url=url, token_url=token_url)
        self.assertFalse(account.credit_tokens(Decimal("0.00")))
        self.assertFalse(account.credit_tokens(Decimal("-10.00")))

    def test_lite_token_account_credit_tokens_valid_amount(self):
        """Test that `credit_tokens` correctly updates the balance for valid amounts."""
        url = MagicMock()
        token_url = MagicMock()
        token_url.path = "/token"

        account = LiteTokenAccount(url=url, token_url=token_url, balance=Decimal("100.00"))
        self.assertTrue(account.credit_tokens(Decimal("50.00")))
        self.assertEqual(account.token_balance(), Decimal("150.00"))

    def test_ensure_url_with_string(self):
        """Test _ensure_url method when URL is a string."""
        url_str = "acc://example.url"
        with patch("accumulate.models.accounts.URL.parse", return_value=MagicMock(spec=URL)) as mock_parse:
            account = DataAccount(url=url_str)
            mock_parse.assert_called_once_with(url_str)
            self.assertIsInstance(account.url, MagicMock)  # Ensure the URL is parsed

    def test_ensure_url_with_url_object(self):
        """Test _ensure_url method when URL is already a URL object."""
        mock_url = MagicMock(spec=URL)
        account = DataAccount(url=mock_url)
        self.assertEqual(account.url, mock_url)

    def test_keybook_ensure_url_valid_string(self):
        """Test _ensure_url with a valid KeyBook string URL."""
        url_str = "acc://DefiDevs.acme/book"

        # Create a mock URL object with required attributes
        mock_url = MagicMock(spec=URL)
        mock_url.path = "/book"
        mock_url.authority = "DefiDevs.acme"

        # Patch URL.parse to return the mocked URL object
        with patch("accumulate.models.accounts.URL.parse", return_value=mock_url) as mock_parse:
            key_book = KeyBook(url=url_str, page_count=2, book_type="test_book")
            
            # Ensure parse was called correctly
            mock_parse.assert_called_once_with(url_str.strip())
            
            # Validate the parsed URL attributes
            self.assertEqual(key_book.url.path, "/book")  # Path should be correctly set
            self.assertEqual(key_book.url.authority, "DefiDevs.acme")  # Authority should be correctly set


    def test_keybook_redundant_acc_in_authority(self):
        """Test _ensure_url raises an error for redundant 'acc://' in authority."""
        mock_url = MagicMock(spec=URL)
        mock_url.authority = "acc://DefiDevs.acme"
        with self.assertRaises(ValueError, msg="Invalid URL: Redundant 'acc://' in authority"):
            KeyBook(url=mock_url, page_count=2, book_type="test_book")

    def test_keybook_validate_url_missing_book_name(self):
        """Test _validate_key_book_url raises error when book name is missing in path."""
        url_str = "acc://DefiDevs.acme"
        with self.assertRaises(ValueError, msg="Invalid KeyBook URL: must include a book name in the path."):
            KeyBook(url=url_str, page_count=2, book_type="test_book")

    def test_keybook_validate_url_invalid_characters_in_path(self):
        """Test _validate_key_book_url raises error for invalid characters in the path."""
        url_str = "acc://DefiDevs.acme/book@1"
        with self.assertRaises(ValueError, msg="Invalid KeyBook URL: contains invalid characters in the path."):
            KeyBook(url=url_str, page_count=2, book_type="test_book")

    def test_keybook_format_key_page_url(self):
        """Test _format_key_page_url returns a valid URL for KeyBook."""
        url = URL(authority="DefiDevs.acme", path="/book")
        key_book = KeyBook(url=url, page_count=2, book_type="test_book")
        formatted_url = key_book._format_key_page_url(url, 1)
        self.assertEqual(formatted_url.path, "/book/1")
        self.assertEqual(formatted_url.authority, "DefiDevs.acme")

    def test_keybook_format_key_page_url_invalid(self):
        """Test _format_key_page_url raises error for invalid KeyBook URL."""
        mock_url = MagicMock(spec=URL)
        mock_url.authority = ""
        mock_url.path = ""
        key_book = KeyBook(url="acc://DefiDevs.acme/book", page_count=2, book_type="test_book")
        with self.assertRaises(ValueError, msg="Invalid KeyBook URL:"):
            key_book._format_key_page_url(mock_url, 0)

    def test_adi_ensure_url_valid_string(self):
        """Test _ensure_url with a valid ADI string URL."""
        url_str = "acc://DefiDevs.acme"

        # Create a mock URL object
        mock_url = MagicMock()
        mock_url.authority = "DefiDevs.acme"
        mock_url.path = ""

        # Patch URL.parse to return the mocked URL object
        with patch("accumulate.models.accounts.URL.parse", return_value=mock_url) as mock_parse:
            # Create an ADI instance with the test URL
            adi = ADI(url=url_str)

            # Verify that URL.parse was called correctly
            mock_parse.assert_called_once_with(url_str)

            # Validate that the ADI's URL matches the mock
            self.assertEqual(adi.url, mock_url)

    def test_keypage_init_url_none(self):
        """Test that KeyPage raises ValueError when URL is None."""
        with self.assertRaises(ValueError) as context:
            KeyPage(url=None)
        self.assertEqual(str(context.exception), "URL cannot be None.")

    def test_keypage_ensure_url_valid_string(self):
        """Test _ensure_url with a valid KeyPage string URL."""
        url_str = "acc://DefiDevs.acme/book/1"

        # Mock URL.parse
        mock_url = MagicMock()
        mock_url.authority = "DefiDevs.acme"
        mock_url.path = "/book/1"
        with patch("accumulate.models.accounts.URL.parse", return_value=mock_url) as mock_parse:
            key_page = KeyPage(url=url_str)

            # Verify URL.parse is called
            mock_parse.assert_called_once_with(url_str)

            # Validate the URL on the KeyPage instance
            self.assertEqual(key_page.url, mock_url)

    def test_keypage_strip_url(self):
        """Test strip_url to ensure it strips extras from the URL."""
        # Create a mock for the URL
        mock_url = MagicMock()
        
        # Ensure the mock has a `strip_extras` method
        mock_url.strip_extras = MagicMock()

        # Create the KeyPage instance with the mocked URL
        key_page = KeyPage(url=mock_url)

        # Call the `strip_url` method
        key_page.strip_url()

        # Assert `strip_extras` was called on the mock
        mock_url.strip_extras.assert_called_once()


    def test_keypage_entry_by_key_not_found(self):
        """Test entry_by_key returns (-1, None, False) for a non-matching key."""
        mock_url = MagicMock()
        key_page = KeyPage(url=mock_url, keys=[])

        key = b"test_key"
        result = key_page.entry_by_key(key)

        # Validate the result
        self.assertEqual(result, (-1, None, False))


    def test_token_account_ensure_url(self):
        """Test _ensure_url with valid and invalid inputs."""
        # Mock the URL.parse method
        with patch("accumulate.models.accounts.URL.parse", return_value=MagicMock(spec=URL)) as mock_parse:
            # Test with a valid string URL
            url_str = "acc://example.token"
            account = TokenAccount(url=url_str, token_url=url_str)
            mock_parse.assert_called_with(url_str)  # Ensure URL.parse is called with the correct URL
            self.assertEqual(account.url, mock_parse.return_value)  # Ensure the parsed URL is assigned

        # Test with an invalid input (non-string, non-URL)
        with self.assertRaises(ValueError, msg="URL and Token URL cannot be None."):
            TokenAccount(url=None, token_url="acc://example.token")

    def test_token_account_strip_url(self):
        """Test strip_url to ensure it calls strip_extras on the URL."""
        # Mock the URL object with a `strip_extras` method
        mock_url = MagicMock()
        mock_url.strip_extras = MagicMock()

        # Create a TokenAccount instance with the mocked URL
        account = TokenAccount(url=mock_url, token_url=mock_url)

        # Call the strip_url method
        account.strip_url()

        # Assert that strip_extras was called once
        mock_url.strip_extras.assert_called_once()




    def test_ensure_url_valid(self):
        """Test `_ensure_url` with a valid string URL."""
        url_str = "acc://example.tokenissuer"
        with patch("accumulate.models.accounts.URL.parse", return_value=MagicMock(spec=URL)) as mock_parse:
            token_issuer = TokenIssuer(url=url_str, symbol="EXM", precision=2)
            mock_parse.assert_called_once_with(url_str)  # Ensure URL.parse was called
            self.assertEqual(token_issuer.url, mock_parse.return_value)  # Check URL was correctly assigned

    def test_ensure_url_invalid(self):
        """Test `_ensure_url` with an invalid input."""
        with self.assertRaises(ValueError, msg="URL cannot be None."):
            TokenIssuer(url=None, symbol="EXM", precision=2)


    def test_strip_url(self):
        """Test `strip_url` to ensure it strips extras from the URL."""
        # Create a mock URL object
        mock_url = MagicMock(spec=URL)
        mock_strip_extras = MagicMock()
        mock_url.strip_extras = mock_strip_extras

        # Create the TokenIssuer object with the mock URL
        token_issuer = TokenIssuer(url=mock_url, symbol="EXM", precision=2)

        # Call the strip_url method
        token_issuer.strip_url()

        # Assert that strip_extras was called once
        mock_strip_extras.assert_called_once()


    def test_issue_negative_amount(self):
        """Test `issue` raises ValueError for a negative amount."""
        token_issuer = TokenIssuer(url="acc://example.tokenissuer", symbol="EXM", precision=2)
        with self.assertRaises(ValueError, msg="Amount cannot be negative."):
            token_issuer.issue(Decimal("-10"))

    def test_issue_within_supply_limit(self):
        """Test `issue` works correctly within supply limit."""
        token_issuer = TokenIssuer(
            url="acc://example.tokenissuer",
            symbol="EXM",
            precision=2,
            supply_limit=Decimal("100")
        )
        self.assertTrue(token_issuer.issue(Decimal("50")))
        self.assertEqual(token_issuer.issued, Decimal("50"))

    def test_issue_exceeds_supply_limit(self):
        """Test `issue` fails when exceeding supply limit."""
        token_issuer = TokenIssuer(
            url="acc://example.tokenissuer",
            symbol="EXM",
            precision=2,
            issued=Decimal("80"),
            supply_limit=Decimal("100")
        )
        self.assertFalse(token_issuer.issue(Decimal("30")))
        self.assertEqual(token_issuer.issued, Decimal("80"))

if __name__ == "__main__":
    unittest.main()
