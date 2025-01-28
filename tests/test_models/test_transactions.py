# accumulate-python-client\tests\test_models\test_transactions.py


import unittest
from unittest.mock import MagicMock
from accumulate.models.base_transactions import TransactionHeader
from accumulate.models.enums import TransactionType
from accumulate.models.errors import AccumulateError, ErrorCode
from accumulate.models.data_entries import AccumulateDataEntry
from accumulate.models.transactions import (
    TransactionResult, TransactionStatus, WriteData, WriteDataTo, IssueTokens, BurnCredits,
    TransferCredits, CreateLiteTokenAccount, CreateKeyPage, CreateKeyBook,
    CreateDataAccount, SendTokens, CreateIdentity, CreateTokenAccount, CreateToken,
    MintTokens, BurnTokens, CreateTokenIssuer, UpdateKeyPage, AddCredits, UpdateAccountAuth, Transaction, hash_write_data
)
from accumulate.models.general import CreditRecipient, TokenRecipient
from accumulate.utils.encoding import marshal_uint
from accumulate.utils.url import URL
import hashlib
from accumulate.models.key_management import KeySpecParams
from accumulate.models.txid import TxID
from unittest.mock import patch

class TestTransactionModels(unittest.TestCase):

    def test_transaction_status_to_dict_and_from_dict(self):
        """Test serialization and deserialization of TransactionStatus."""
        status = TransactionStatus(
            tx_id="test_tx_id",
            code=0,
            error=None,
            result=None,
            received=1234567890,
            initiator=URL("test_initiator")
        )
        status.signers = [MagicMock(to_dict=lambda: {"signer_key": "signer_value"})]
        result = status.to_dict()
        expected = {
            "tx_id": "test_tx_id",
            "code": 0,
            "error": None,
            "result": None,
            "received": 1234567890,
            "initiator": "test_initiator",
            "signers": [{"signer_key": "signer_value"}]
        }
        self.assertEqual(result, expected)

        recreated_status = TransactionStatus.from_dict(expected)
        self.assertEqual(recreated_status.tx_id, "test_tx_id")
        self.assertEqual(recreated_status.code, 0)
        self.assertEqual(recreated_status.received, 1234567890)
        self.assertEqual(str(recreated_status.initiator), "test_initiator")

    def setUp(self):
        """Set up common mocks and data for transaction tests."""
        # Mock URL and operations for UpdateKeyPage tests
        self.mock_url = URL(authority="example.acme", path="/key-page")
        self.mock_operations = [
            {"type": "add", "value": b"key1"},
            {"type": "remove", "value": b"key2"}
        ]
        # Create UpdateKeyPage transaction instance
        self.update_key_page_transaction = UpdateKeyPage(url=self.mock_url, operations=self.mock_operations)

        # Mock TransactionHeader and TransactionBody for Transaction tests
        self.mock_header = MagicMock()
        self.mock_body = MagicMock()

        # Mock methods for header and body
        self.mock_header.marshal_binary.return_value = b"mock_header_data"
        self.mock_body.marshal.return_value = b"mock_body_data"

        # Mock principal
        self.mock_header.principal = "acc://example_account"

        # Create a Transaction instance
        self.transaction = Transaction(header=self.mock_header, body=self.mock_body)

        # Extend get_body_hash with realistic behavior
        def mock_get_body_hash():
            body_data = self.mock_body.marshal()  # Get mocked marshaled body data
            body_hash = hashlib.sha256(body_data).digest()
            is_64_bytes = len(body_data) == 64
            return body_hash, is_64_bytes

        self.transaction.get_body_hash = mock_get_body_hash

        # Debug logs to confirm setup
        print("DEBUG: setUp completed with mock_header, mock_body, and mock_url.")
        print(f"DEBUG: Mock URL: {self.mock_url}")
        print(f"DEBUG: Mock Operations: {self.mock_operations}")
        print(f"DEBUG: Mock Header Principal: {self.mock_header.principal}")





    def test_write_data_to_marshal_unmarshal(self):
        """Test WriteDataTo serialization and deserialization."""
        recipient = URL(user_info="test_user", authority="mock_entry")
        entry = AccumulateDataEntry([b"mock_chunk"])
        
        write_data_to = WriteDataTo(recipient=recipient, entry=entry)
        print(f"DEBUG: Initialized WriteDataTo with recipient: {recipient}, entry: {entry}")

        # Test marshaling
        marshaled = write_data_to.marshal()
        print(f"DEBUG: Marshaled WriteDataTo data: {marshaled}")
        self.assertIsInstance(marshaled, bytes)

        # Test unmarshaling
        unmarshaled = WriteDataTo(recipient=None, entry=None).unmarshal(marshaled)
        print(f"DEBUG: Unmarshaled WriteDataTo: recipient={unmarshaled.recipient}, entry={unmarshaled.entry}")

        # Verify fields after unmarshaling
        self.assertEqual(str(unmarshaled.recipient), str(recipient))
        self.assertEqual(unmarshaled.entry.data, entry.data)





    def test_transfer_credits_marshal_unmarshal(self):
        """Test TransferCredits serialization and deserialization."""
        print("DEBUG: Starting test for TransferCredits marshaling and unmarshaling")
        recipient = CreditRecipient(URL.parse("acc://recipient_url"), 200)
        print(f"DEBUG: Created CreditRecipient: {recipient}")
        transfer_credits = TransferCredits(to=[recipient])
        marshaled = transfer_credits.marshal()
        print(f"MARSHAL OUTPUT: {marshaled}")

        unmarshaled = TransferCredits(to=[]).unmarshal(marshaled)
        print(f"UNMARSHAL OUTPUT: {unmarshaled.to}")

        # Verify unmarshaled data
        self.assertEqual(len(unmarshaled.to), 1)
        self.assertEqual(unmarshaled.to[0].url.marshal().decode("utf-8"), "acc://recipient_url")
        self.assertEqual(unmarshaled.to[0].amount, 200)






    def test_create_lite_token_account_marshal_unmarshal(self):
        """Test CreateLiteTokenAccount serialization and deserialization."""
        token_url = URL.parse("acc://token_account_url")  # Use URL.parse to ensure normalization
        transaction = CreateLiteTokenAccount(token_url=token_url)

        # Marshal and unmarshal the transaction
        marshaled = transaction.marshal()
        unmarshaled = CreateLiteTokenAccount(token_url=None).unmarshal(marshaled)

        # Assert the token URL matches after unmarshaling
        self.assertEqual(unmarshaled.token_url.marshal().decode("utf-8"), "acc://token_account_url")





    def test_create_key_page_marshal_unmarshal(self):
        """Test CreateKeyPage serialization and deserialization."""
        print("DEBUG: Starting test_create_key_page_marshal_unmarshal")

        # Create a KeySpecParams instance
        key = KeySpecParams(key_hash=b"mock_key", delegate="delegate_key")
        print(f"DEBUG: Created KeySpecParams: key_hash={key.key_hash}, delegate={key.delegate}")

        # Create the CreateKeyPage instance
        create_key_page = CreateKeyPage(keys=[key])
        print(f"DEBUG: Created CreateKeyPage: keys={create_key_page.keys}")

        # Marshal the object
        marshaled = create_key_page.marshal()
        print(f"DEBUG: Marshaled CreateKeyPage data (hex): {marshaled.hex()}")

        # Unmarshal the object
        unmarshaled = CreateKeyPage(keys=[]).unmarshal(marshaled)
        print(f"DEBUG: Unmarshaled CreateKeyPage: keys={unmarshaled.keys}")

        # Validate unmarshaled data
        assert len(unmarshaled.keys) == 1
        assert unmarshaled.keys[0].key_hash == b"mock_key", f"DEBUG: Unexpected key_hash={unmarshaled.keys[0].key_hash}"
        assert unmarshaled.keys[0].delegate == "delegate_key", f"DEBUG: Unexpected delegate={unmarshaled.keys[0].delegate}"
        print("DEBUG: Test passed!")




    def test_create_key_book_marshal_unmarshal(self):
        """Test CreateKeyBook serialization and deserialization."""
        key_book = CreateKeyBook(
            url=URL("key_book_url"),
            public_key_hash=b"mock_hash",
            authorities=[URL("authority_url")]
        )
        marshaled = key_book.marshal()
        self.assertIsInstance(marshaled, bytes)

        unmarshaled = CreateKeyBook(url=None, public_key_hash=None).unmarshal(marshaled)
        self.assertEqual(str(unmarshaled.url), "acc://key_book_url")
        self.assertEqual(unmarshaled.public_key_hash, b"mock_hash")
        self.assertEqual(len(unmarshaled.authorities), 1)
        self.assertEqual(str(unmarshaled.authorities[0]), "acc://authority_url")



    def test_create_data_account_marshal_unmarshal(self):
        """Test CreateDataAccount serialization and deserialization."""
        url = URL.parse("acc://DefiDevs.acme/data_account_name")
        authorities = [URL.parse("acc://DefiDevs.acme/authority_name")]
        metadata = b"mock_metadata"

        print(f"TEST INPUT: URL: {url}, Authorities: {authorities}, Metadata: {metadata}")

        try:
            # Create and marshal
            data_account = CreateDataAccount(url=url, authorities=authorities, metadata=metadata)
            marshaled = data_account.marshal()
            print(f"MARSHAL OUTPUT: {marshaled}")

            # Unmarshal and compare
            unmarshaled_account = CreateDataAccount(url=url).unmarshal(marshaled)
            print(f"UNMARSHAL OUTPUT: URL: {unmarshaled_account.url}, Authorities: {unmarshaled_account.authorities}, Metadata: {unmarshaled_account.metadata}")

            assert data_account.url == unmarshaled_account.url
            assert data_account.authorities == unmarshaled_account.authorities
            assert data_account.metadata == unmarshaled_account.metadata

        except ValueError as e:
            print(f"TEST FAILURE: {str(e)}")
            raise







    def test_mint_tokens_marshal_unmarshal(self):
        """Test MintTokens serialization and deserialization."""
        # Create a valid recipient URL and MintTokens object
        recipient = TokenRecipient(URL(authority="recipient.example", path="/account"), 500)
        mint_tokens = MintTokens(
            token_url=URL(authority="mint.example", path="/token"),
            recipients=[recipient]
        )

        # Marshal the object
        marshaled = mint_tokens.marshal()
        print(f"DEBUG: Marshaled MintTokens data: {marshaled.hex()}")
        self.assertIsInstance(marshaled, bytes)

        # Use a valid placeholder URL for unmarshaling
        unmarshaled = MintTokens(token_url=URL(authority="placeholder", path="/placeholder"), recipients=[]).unmarshal(marshaled)
        print(f"DEBUG: Unmarshaled MintTokens: token_url={unmarshaled.token_url}, recipients={unmarshaled.recipients}")

        # Verify unmarshaled data
        self.assertEqual(unmarshaled.token_url.marshal().decode("utf-8"), "acc://mint.example/token")
        self.assertEqual(len(unmarshaled.recipients), 1)
        self.assertEqual(unmarshaled.recipients[0].url.marshal().decode("utf-8"), "acc://recipient.example/account")
        self.assertEqual(unmarshaled.recipients[0].amount, 500)












    def test_burn_tokens_marshal_unmarshal(self):
        """Test BurnTokens serialization and deserialization."""
        burn_tokens = BurnTokens(token_url=URL.parse("acc://burn_url"), amount=300)

        # Marshal the object
        marshaled = burn_tokens.marshal()
        print(f"DEBUG: Marshaled BurnTokens data: {marshaled.hex()}")
        assert isinstance(marshaled, bytes)

        # Unmarshal the object
        unmarshaled = BurnTokens(token_url=None, amount=0).unmarshal(marshaled)
        print(f"DEBUG: Unmarshaled BurnTokens: token_url={unmarshaled.token_url}, amount={unmarshaled.amount}")

        # Validate unmarshaled data
        assert unmarshaled.token_url.marshal().decode("utf-8") == "acc://burn_url"
        assert unmarshaled.amount == 300





    def test_create_token_issuer_marshal_unmarshal(self):
        """Test CreateTokenIssuer serialization and deserialization."""
        url = URL.parse("acc://issuer_url")
        authorities = [URL.parse("acc://authority_url")]

        print(f"TEST INPUT: URL: {url}, Authorities: {authorities}")

        try:
            # Create and marshal
            token_issuer = CreateTokenIssuer(url=url, authorities=authorities)
            marshaled = token_issuer.marshal()
            print(f"MARSHAL OUTPUT: {marshaled}")

            # Unmarshal and compare
            unmarshaled_issuer = CreateTokenIssuer(url=url).unmarshal(marshaled)
            print(f"UNMARSHAL OUTPUT: URL: {unmarshaled_issuer.url}, Authorities: {unmarshaled_issuer.authorities}")

            assert token_issuer.url == unmarshaled_issuer.url
            assert token_issuer.authorities == unmarshaled_issuer.authorities

        except ValueError as e:
            print(f"TEST FAILURE: {str(e)}")
            raise



    def test_create_key_book_marshal_unmarshal(self):
        """Test CreateKeyBook serialization and deserialization."""
        key_book = CreateKeyBook(
            url=URL.parse("acc://key_book_url"),
            public_key_hash=b"mock_hash",
            authorities=[URL.parse("acc://authority_url")]
        )

        # Marshal the object
        marshaled = key_book.marshal()
        print(f"DEBUG: Marshaled CreateKeyBook data: {marshaled.hex()}")
        assert isinstance(marshaled, bytes)

        # Unmarshal the object
        unmarshaled = CreateKeyBook(url=None, public_key_hash=None).unmarshal(marshaled)
        print(f"DEBUG: Unmarshaled CreateKeyBook: url={unmarshaled.url}, public_key_hash={unmarshaled.public_key_hash}, "
            f"authorities={unmarshaled.authorities}")

        # Validate unmarshaled data
        assert unmarshaled.url.marshal().decode("utf-8") == "acc://key_book_url"
        assert unmarshaled.public_key_hash == b"mock_hash"
        assert len(unmarshaled.authorities) == 1
        assert unmarshaled.authorities[0].marshal().decode("utf-8") == "acc://authority_url"



    def test_add_credits_marshal_unmarshal(self):
        """Test AddCredits serialization and deserialization."""
        # Use a properly formatted URL
        url = URL.parse("acc://credit_recipient")
        amount = 150

        print(f"TEST INPUT: Recipient: {url}, Amount: {amount}")

        try:
            # Create and marshal
            add_credits = AddCredits(recipient=url, amount=amount)
            marshaled = add_credits.marshal()
            print(f"MARSHAL OUTPUT: {marshaled}")

            # Unmarshal and compare
            unmarshaled_credits = AddCredits().unmarshal(marshaled)
            print(f"UNMARSHAL OUTPUT: Recipient: {unmarshaled_credits.recipient}, Amount: {unmarshaled_credits.amount}")

            # Assertions
            expected_recipient = f"acc://{unmarshaled_credits.recipient}"  # Ensure "acc://" prefix
            assert expected_recipient == "acc://credit_recipient"
            assert unmarshaled_credits.amount == 150

        except Exception as e:
            print(f"TEST FAILURE: {str(e)}")
            raise







    def test_update_account_auth_marshal_unmarshal(self):
        """Test UpdateAccountAuth serialization and deserialization."""
        operation = {"type": "remove", "value": b"auth_value"}
        update_auth = UpdateAccountAuth(account_url=URL.parse("acc://account_url"), operations=[operation])

        # Marshal the object
        marshaled = update_auth.marshal()
        print(f"DEBUG: Marshaled UpdateAccountAuth data: {marshaled.hex()}")
        assert isinstance(marshaled, bytes)

        # Unmarshal the object
        unmarshaled = UpdateAccountAuth(account_url=None, operations=[]).unmarshal(marshaled)
        print(f"DEBUG: Unmarshaled UpdateAccountAuth: account_url={unmarshaled.account_url}, operations={unmarshaled.operations}")

        # Validate unmarshaled data
        assert unmarshaled.account_url.marshal().decode("utf-8") == "acc://account_url"
        assert len(unmarshaled.operations) == 1
        assert unmarshaled.operations[0] == operation



    def test_send_tokens_marshal_unmarshal(self):
        """Test SendTokens serialization and deserialization."""
        recipient = TokenRecipient(URL("recipient_url"), 1000)
        send_tokens = SendTokens(recipients=[recipient])

        marshaled = send_tokens.marshal()
        self.assertIsInstance(marshaled, bytes)

        unmarshaled = SendTokens().unmarshal(marshaled)
        self.assertEqual(len(unmarshaled.recipients), 1)
        self.assertEqual(str(unmarshaled.recipients[0].url), "recipient_url")
        self.assertEqual(unmarshaled.recipients[0].amount, 1000)



    def test_create_identity_marshal_unmarshal(self):
        """Test CreateIdentity serialization and deserialization."""
        url = URL.parse("acc://identity_url")
        authorities = [URL.parse("acc://authority_url")]

        print(f"TEST INPUT: URL: {url}, Authorities: {authorities}")

        try:
            # Create and marshal
            identity = CreateIdentity(url=url, authorities=authorities)
            marshaled = identity.marshal()
            print(f"MARSHAL OUTPUT: {marshaled}")

            # Unmarshal and compare
            unmarshaled_identity = CreateIdentity(url=url).unmarshal(marshaled)
            print(f"UNMARSHAL OUTPUT: URL: {unmarshaled_identity.url}, Authorities: {unmarshaled_identity.authorities}")

            assert identity.url == unmarshaled_identity.url
            assert identity.authorities == unmarshaled_identity.authorities

        except ValueError as e:
            print(f"TEST FAILURE: {str(e)}")
            raise





    def test_create_token_account_marshal_unmarshal(self):
        """Test CreateTokenAccount serialization and deserialization."""
        url = URL.parse("acc://account_url")
        token_url = URL.parse("acc://token_url")
        authorities = [URL.parse("acc://authority_url")]

        print(f"TEST INPUT: URL: {url}, Token URL: {token_url}, Authorities: {authorities}")

        try:
            # Create and marshal
            token_account = CreateTokenAccount(url=url, token_url=token_url, authorities=authorities)
            marshaled = token_account.marshal()
            print(f"MARSHAL OUTPUT: {marshaled}")

            # Unmarshal and compare
            unmarshaled_account = CreateTokenAccount().unmarshal(marshaled)
            print(f"UNMARSHAL OUTPUT: URL: {unmarshaled_account.url}, Token URL: {unmarshaled_account.token_url}, Authorities: {unmarshaled_account.authorities}")

            assert token_account.url == unmarshaled_account.url
            assert token_account.token_url == unmarshaled_account.token_url
            assert token_account.authorities == unmarshaled_account.authorities

        except ValueError as e:
            print(f"TEST FAILURE: {str(e)}")
            raise




    def test_create_token_marshal_unmarshal(self):
        """Test CreateToken serialization and deserialization."""
        create_token = CreateToken(
            url=URL.parse("acc://token_url"),
            symbol="ACME",
            precision=8,
            authorities=[URL.parse("acc://authority_url")]
        )

        # Marshal the object
        marshaled = create_token.marshal()
        print(f"DEBUG: Marshaled CreateToken data: {marshaled.hex()}")
        assert isinstance(marshaled, bytes)

        # Unmarshal the object
        unmarshaled = CreateToken(url=None, symbol=None, precision=None).unmarshal(marshaled)
        print(f"DEBUG: Unmarshaled CreateToken: url={unmarshaled.url}, symbol={unmarshaled.symbol}, "
            f"precision={unmarshaled.precision}, authorities={unmarshaled.authorities}")

        # Validate unmarshaled data
        assert unmarshaled.url.marshal().decode("utf-8") == "acc://token_url"
        assert unmarshaled.symbol == "ACME"
        assert unmarshaled.precision == 8
        assert len(unmarshaled.authorities) == 1
        assert unmarshaled.authorities[0].marshal().decode("utf-8") == "acc://authority_url"








    def test_issue_tokens_marshal_unmarshal(self):
        """Test IssueTokens serialization and deserialization."""
        recipient = TokenRecipient(URL("recipient_url"), 500)
        issue_tokens = IssueTokens(to=[recipient])

        marshaled = issue_tokens.marshal()
        self.assertIsInstance(marshaled, bytes)

        unmarshaled = IssueTokens(to=[]).unmarshal(marshaled)
        self.assertEqual(len(unmarshaled.to), 1)
        self.assertEqual(str(unmarshaled.to[0].url), "recipient_url")
        self.assertEqual(unmarshaled.to[0].amount, 500)

    def test_burn_credits_marshal_unmarshal(self):
        """Test BurnCredits serialization and deserialization."""
        burn_credits = BurnCredits(amount=1500)

        marshaled = burn_credits.marshal()
        self.assertEqual(marshaled, (1500).to_bytes(8, "big"))

        unmarshaled = BurnCredits(amount=0).unmarshal(marshaled)
        self.assertEqual(unmarshaled.amount, 1500)


    def test_write_data_marshal_unmarshal(self):
        entry = AccumulateDataEntry([b"mock_chunk"])
        write_data = WriteData(entry=entry, scratch=True, write_to_state=False)

        print(f"DEBUG: Initialized WriteData with entry: {entry}")

        marshaled = write_data.marshal()
        print(f"DEBUG: Marshaled data: {marshaled}")

        unmarshaled = WriteData(entry=None).unmarshal(marshaled)
        print(f"DEBUG: Unmarshaled WriteData: {unmarshaled}")

        self.assertTrue(unmarshaled.scratch)
        self.assertFalse(unmarshaled.write_to_state)
        self.assertEqual(unmarshaled.entry.data, [b"mock_chunk"])


    def test_transaction_status_delivered(self):
        """Test the delivered method of TransactionStatus."""
        # Case 1: Code is OK (delivered is True)
        status = TransactionStatus(code=ErrorCode.OK.value)
        self.assertTrue(status.delivered(), "Delivered should return True for OK code")

        # Case 2: Code indicates failure (not delivered)
        status.code = ErrorCode.FAILED.value
        self.assertFalse(status.delivered(), "Delivered should return False if code is FAILED")

    def test_transaction_status_failed(self):
        """Test the failed method of TransactionStatus."""
        # Case 1: Code is OK (not failed)
        status = TransactionStatus(code=ErrorCode.OK.value)
        self.assertFalse(status.failed(), "Failed should return False for OK code")

        # Case 2: Code is FAILED (failed is True)
        status.code = ErrorCode.FAILED.value
        self.assertTrue(status.failed(), "Failed should return True for FAILED code")

    def test_transaction_status_remote(self):
        status = TransactionStatus(code=ErrorCode.FAILED.value)
        self.assertTrue(status.remote(), "Remote should return True for FAILED code")

        status.code = 0
        self.assertFalse(status.remote(), "Remote should return False for non-FAILED code")

    def test_transaction_status_pending(self):
        status = TransactionStatus(code=ErrorCode.DID_PANIC.value)
        self.assertTrue(status.pending(), "Pending should return True for DID_PANIC code")

        status.code = 0
        self.assertFalse(status.pending(), "Pending should return False for non-DID_PANIC code")

    def test_transaction_status_set_error(self):
        """Test the set method of TransactionStatus with an error."""
        # Case 1: Valid error with a specific code
        mock_error = AccumulateError(ErrorCode.ENCODING_ERROR, "Encoding failed")
        status = TransactionStatus()
        status.set(mock_error)
        self.assertEqual(status.code, ErrorCode.ENCODING_ERROR.value, "Set should update the code from the error")
        self.assertEqual(status.error, mock_error, "Set should update the error")

        # Case 2: Error with None code (fallback to UNKNOWN_ERROR)
        mock_error = AccumulateError(ErrorCode.UNKNOWN_ERROR, None)  # Provide a valid error code
        status.set(mock_error)
        self.assertEqual(status.code, ErrorCode.UNKNOWN_ERROR.value, "Set should fallback to UNKNOWN_ERROR if no specific code")

        # Case 3: None error (simulate no error provided)
        status.set(None)
        self.assertEqual(status.code, ErrorCode.UNKNOWN_ERROR.value, "Set should fallback to UNKNOWN_ERROR if error is None")
        self.assertIsNone(status.error, "Error should be None when set with None")

    def test_transaction_status_as_error(self):
        """Test the as_error method of TransactionStatus."""
        mock_error = MagicMock()
        status = TransactionStatus(error=mock_error)
        self.assertEqual(status.as_error(), mock_error, "As_error should return the error if present")

        status.error = None
        self.assertIsNone(status.as_error(), "As_error should return None if no error is present")

    def test_transaction_status_add_anchor_signer(self):
        """Test the add_anchor_signer method of TransactionStatus."""
        status = TransactionStatus()
        mock_signature = MagicMock()
        mock_signature.get_public_key.return_value = "mock_key"

        # Add a signer for the first time
        status.add_anchor_signer(mock_signature)
        self.assertIn("mock_key", status.anchor_signers, "Anchor signer should be added to the list")

        # Try adding the same key again
        status.add_anchor_signer(mock_signature)
        self.assertEqual(len(status.anchor_signers), 1, "Duplicate anchor signer should not be added")

        # Add a different key
        mock_signature.get_public_key.return_value = "mock_key_2"
        status.add_anchor_signer(mock_signature)
        self.assertIn("mock_key_2", status.anchor_signers, "New anchor signer should be added to the list")


    def test_transaction_status_add_signer(self):
        """Test the add_signer method of TransactionStatus."""
        status = TransactionStatus()
        mock_signer = MagicMock()
        mock_signer.get_url.return_value = "mock_url"
        mock_signer.get_version.return_value = 1

        # Add a signer for the first time
        status.add_signer(mock_signer)
        self.assertIn(mock_signer, status.signers, "Signer should be added to the list")

        # Add a signer with the same URL but a higher version
        new_signer = MagicMock()
        new_signer.get_url.return_value = "mock_url"
        new_signer.get_version.return_value = 2
        status.add_signer(new_signer)
        self.assertEqual(status.signers[-1], new_signer, "Signer with a higher version should replace the existing signer")

        # Add a signer with a different URL
        another_signer = MagicMock()
        another_signer.get_url.return_value = "mock_url_2"
        another_signer.get_version.return_value = 1
        status.add_signer(another_signer)
        self.assertIn(another_signer, status.signers, "Signer with a new URL should be added to the list")


    def test_transaction_status_get_signer(self):
        """Test the get_signer method of TransactionStatus."""
        status = TransactionStatus()
        mock_signer1 = MagicMock()
        mock_signer1.get_url.return_value = "mock_url_1"
        mock_signer2 = MagicMock()
        mock_signer2.get_url.return_value = "mock_url_2"

        # Add signers to the list
        status.signers = [mock_signer1, mock_signer2]

        # Retrieve an existing signer
        result = status.get_signer("mock_url_1")
        self.assertEqual(result, mock_signer1, "get_signer should return the correct signer based on the URL")

        # Try to retrieve a non-existing signer
        result = status.get_signer("non_existing_url")
        self.assertIsNone(result, "get_signer should return None for a non-existing URL")

    def test_write_data_type(self):
        """Test the type method of WriteData."""
        mock_entry = MagicMock()  # Mock the DataEntry to avoid dependencies
        write_data = WriteData(entry=mock_entry)
        self.assertEqual(write_data.type(), TransactionType.WRITE_DATA, "type should return TransactionType.WRITE_DATA")


    def test_write_data_unmarshal_invalid_data(self):
        """Test the unmarshal method of WriteData with invalid data."""
        mock_entry = MagicMock()
        mock_entry.marshal.return_value = b"valid_data"
        write_data = WriteData(entry=mock_entry)

        # Invalid data for entry unmarshalling
        invalid_data = b"\x01\x01invalid_entry_data"

        # Patch the DataEntry.unmarshal method to raise a ValueError
        with unittest.mock.patch("accumulate.models.data_entries.DataEntry.unmarshal", side_effect=ValueError("Invalid entry data")):
            with self.assertRaises(ValueError) as context:
                write_data.unmarshal(invalid_data)

            self.assertIn("Failed to unmarshal WriteData entry", str(context.exception), "Unmarshal should raise a ValueError with a proper message")

    def test_write_data_to_type(self):
        """Test the type method of WriteDataTo."""
        mock_recipient = MagicMock()  # Mock the URL to avoid dependencies
        mock_entry = MagicMock()  # Mock the DataEntry to avoid dependencies
        write_data_to = WriteDataTo(recipient=mock_recipient, entry=mock_entry)

        self.assertEqual(
            write_data_to.type(),
            TransactionType.WRITE_DATA_TO,
            "type should return TransactionType.WRITE_DATA_TO"
    )
        
    def test_issue_tokens_type(self):
        """Test the type method of IssueTokens."""
        mock_recipient = MagicMock()  # Mock the TokenRecipient to avoid dependencies
        issue_tokens = IssueTokens(to=[mock_recipient])

        self.assertEqual(
            issue_tokens.type(),
            TransactionType.ISSUE_TOKENS,
            "type should return TransactionType.ISSUE_TOKENS"
        )

    def test_burn_credits_type(self):
        """Test the type method of BurnCredits."""
        burn_credits = BurnCredits(amount=100)

        self.assertEqual(
            burn_credits.type(),
            TransactionType.BURN_CREDITS,
            "type should return TransactionType.BURN_CREDITS"
        )

    def test_transfer_credits_type(self):
        """Test the type method of TransferCredits."""
        mock_recipient = MagicMock()  # Mock the CreditRecipient to avoid dependencies
        transfer_credits = TransferCredits(to=[mock_recipient])

        self.assertEqual(
            transfer_credits.type(),
            TransactionType.TRANSFER_CREDITS,
            "type should return TransactionType.TRANSFER_CREDITS"
        )

    def test_create_key_book_type(self):
        """Test the type method of CreateKeyBook."""
        mock_url = MagicMock()  # Mock the URL to avoid dependencies
        public_key_hash = b"\x00" * 32  # Example public key hash
        create_key_book = CreateKeyBook(url=mock_url, public_key_hash=public_key_hash)

        self.assertEqual(
            create_key_book.type(),
            TransactionType.CREATE_KEY_BOOK,
            "type should return TransactionType.CREATE_KEY_BOOK"
        )

    def test_create_key_page_type(self):
        """Test the type method of CreateKeyPage."""
        mock_key = MagicMock()  # Mock the KeySpecParams to avoid dependencies
        create_key_page = CreateKeyPage(keys=[mock_key])

        self.assertEqual(
            create_key_page.type(),
            TransactionType.CREATE_KEY_PAGE,
            "type should return TransactionType.CREATE_KEY_PAGE"
        )

    def test_create_lite_token_account_type(self):
        """Test the type method of CreateLiteTokenAccount."""
        mock_url = MagicMock()  # Mock the URL to avoid dependencies
        create_lite_token_account = CreateLiteTokenAccount(token_url=mock_url)

        self.assertEqual(
            create_lite_token_account.type(),
            TransactionType.CREATE_LITE_TOKEN_ACCOUNT,
            "type should return TransactionType.CREATE_LITE_TOKEN_ACCOUNT"
        )

    def test_create_data_account_invalid_url_type(self):
        """Test CreateDataAccount with an invalid URL type."""
        with self.assertRaises(TypeError) as context:
            CreateDataAccount(url="not-a-url")  # Passing a string instead of a URL
        self.assertEqual(str(context.exception), "url must be an instance of URL.")


    def test_create_data_account_invalid_url_missing_parts(self):
        """Test CreateDataAccount with a URL missing authority or path."""
        # URL with missing authority
        mock_url_missing_authority = URL(authority=None, path="/data")

        # URL with missing path
        mock_url_missing_path = URL(authority="example.com", path=None)

        with self.assertRaises(ValueError) as context:
            CreateDataAccount(url=mock_url_missing_authority)
        self.assertIn("Invalid URL", str(context.exception))

        with self.assertRaises(ValueError) as context:
            CreateDataAccount(url=mock_url_missing_path)
        self.assertIn("Invalid URL", str(context.exception))


    def test_create_data_account_invalid_authority_type(self):
        """Test CreateDataAccount with an invalid authority type."""
        mock_url = URL(authority="example.com", path="/data")

        with self.assertRaises(TypeError) as context:
            CreateDataAccount(url=mock_url, authorities=["not-a-url"])  # Passing a string instead of a URL
        self.assertEqual(str(context.exception), "All authorities must be instances of URL.")


    def test_create_data_account_invalid_authority_url(self):
        """Test CreateDataAccount with an authority URL missing authority or path."""
        mock_url = URL(authority="example.com", path="/data")

        # Authority URL with missing authority
        mock_invalid_authority = URL(authority=None, path="/path")

        with self.assertRaises(ValueError) as context:
            CreateDataAccount(url=mock_url, authorities=[mock_invalid_authority])
        self.assertIn("Invalid authority URL", str(context.exception))

    def test_create_data_account_type(self):
        """Test the type method of CreateDataAccount."""
        mock_url = URL(authority="example.com", path="/data")

        create_data_account = CreateDataAccount(url=mock_url)
        self.assertEqual(
            create_data_account.type(),
            TransactionType.CREATE_DATA_ACCOUNT,
            "type should return TransactionType.CREATE_DATA_ACCOUNT"
        )

    def test_add_recipient_valid(self):
        """Test add_recipient with a valid URL and amount."""
        url = URL(authority="example.com", path="/account")
        amount = 100
        send_tokens = SendTokens()
        send_tokens.add_recipient(url, amount)

        self.assertEqual(len(send_tokens.recipients), 1, "Recipient should be added to the list")
        self.assertEqual(send_tokens.recipients[0].url, url, "Recipient URL should match")
        self.assertEqual(send_tokens.recipients[0].amount, amount, "Recipient amount should match")

    def test_add_recipient_invalid_amount(self):
        """Test add_recipient with an invalid amount (less than or equal to zero)."""
        url = URL(authority="example.com", path="/account")
        send_tokens = SendTokens()

        with self.assertRaises(ValueError) as context:
            send_tokens.add_recipient(url, 0)  # Amount is zero
        self.assertEqual(str(context.exception), "Amount must be greater than zero")

        with self.assertRaises(ValueError) as context:
            send_tokens.add_recipient(url, -10)  # Amount is negative
        self.assertEqual(str(context.exception), "Amount must be greater than zero")

    def test_add_recipient_create_token_recipient(self):
        """Test that add_recipient creates a valid TokenRecipient object."""
        url = URL(authority="example.com", path="/account")
        amount = 50
        send_tokens = SendTokens()

        send_tokens.add_recipient(url, amount)
        recipient = send_tokens.recipients[0]

        self.assertIsInstance(recipient, TokenRecipient, "Recipient should be an instance of TokenRecipient")
        self.assertEqual(recipient.url, url, "Recipient URL should match the provided URL")
        self.assertEqual(recipient.amount, amount, "Recipient amount should match the provided amount")

    def test_transaction_type_send_token(self):
        """Test the type method of SendTokens."""
        send_tokens = SendTokens()
        self.assertEqual(
            send_tokens.type(),
            TransactionType.SEND_TOKENS,
            "type should return TransactionType.SEND_TOKENS"
        )


    def test_invalid_url_type(self):
        """Test CreateIdentity with an invalid URL type."""
        with self.assertRaises(TypeError) as context:
            CreateIdentity(url="not-a-url")  # Passing a string instead of a URL
        self.assertEqual(str(context.exception), "url must be an instance of URL.")

    def test_url_missing_authority(self):
        """Test CreateIdentity with a URL missing the authority component."""
        mock_url = URL(authority=None, path="/identity")

        with self.assertRaises(ValueError) as context:
            CreateIdentity(url=mock_url)
        self.assertEqual(
            str(context.exception),
            f"Invalid URL: Missing authority component in {mock_url}"
        )

    def test_invalid_authority_type(self):
        """Test CreateIdentity with an invalid authority type."""
        mock_url = URL(authority="example.com", path="/identity")

        with self.assertRaises(TypeError) as context:
            CreateIdentity(url=mock_url, authorities=["not-a-url"])  # Passing a string instead of a URL
        self.assertEqual(str(context.exception), "All authorities must be instances of URL.")

    def test_invalid_authority_url(self):
        """Test CreateIdentity with an authority URL missing the authority component."""
        mock_url = URL(authority="example.com", path="/identity")
        mock_invalid_authority = URL(authority=None, path="/authority")

        with self.assertRaises(ValueError) as context:
            CreateIdentity(url=mock_url, authorities=[mock_invalid_authority])
        self.assertEqual(
            str(context.exception),
            f"Invalid authority URL: {mock_invalid_authority}"
        )

    def test_transaction_type_create_adi(self):
        """Test the type method of CreateIdentity."""
        mock_url = URL(authority="example.com", path="/identity")

        create_identity = CreateIdentity(url=mock_url)
        self.assertEqual(
            create_identity.type(),
            TransactionType.CREATE_IDENTITY,
            "type should return TransactionType.CREATE_IDENTITY"
        )


    def test_transaction_type(self):
        """Test the type method of SendTokens."""
        # Create an instance of SendTokens with no recipients
        send_tokens = SendTokens()

        # Verify the type method returns the correct TransactionType
        self.assertEqual(
            send_tokens.type(),
            TransactionType.SEND_TOKENS,
            "type should return TransactionType.SEND_TOKENS"
        )

    def test_invalid_url_type_create_TA(self):
        """Test CreateTokenAccount with an invalid URL type for `url`."""
        with self.assertRaises(TypeError) as context:
            CreateTokenAccount(url="not-a-url")  # Passing a string instead of a URL
        self.assertEqual(str(context.exception), "url must be an instance of URL.")

    def test_invalid_token_url_type_create_TA(self):
        """Test CreateTokenAccount with an invalid URL type for `token_url`."""
        with self.assertRaises(TypeError) as context:
            CreateTokenAccount(token_url="not-a-url")  # Passing a string instead of a URL
        self.assertEqual(str(context.exception), "token_url must be an instance of URL.")

    def test_transaction_type_create_TA(self):
        """Test the type method of CreateTokenAccount."""
        mock_url = URL(authority="example.com", path="/token-account")
        mock_token_url = URL(authority="issuer.com", path="/token")

        create_token_account = CreateTokenAccount(url=mock_url, token_url=mock_token_url)
        self.assertEqual(
            create_token_account.type(),
            TransactionType.CREATE_TOKEN_ACCOUNT,
            "type should return TransactionType.CREATE_TOKEN_ACCOUNT"
        )



    def test_transaction_type_CreateToken(self):
        """Test the type method of CreateToken."""
        # Mock inputs for CreateToken
        mock_url = URL(authority="issuer.example", path="/token")
        mock_symbol = "ACME"
        mock_precision = 8

        # Create an instance of CreateToken
        create_token = CreateToken(
            url=mock_url,
            symbol=mock_symbol,
            precision=mock_precision
        )

        # Verify the type method returns the correct TransactionType
        self.assertEqual(
            create_token.type(),
            TransactionType.CREATE_TOKEN,
            "type should return TransactionType.CREATE_TOKEN"
        )


    def test_transaction_type_MintTokens(self):
        """Test the type method of MintTokens."""
        # Mock inputs for MintTokens
        mock_token_url = URL(authority="issuer.example", path="/token")
        mock_recipients = []  # Empty recipients for simplicity

        # Create an instance of MintTokens
        mint_tokens = MintTokens(token_url=mock_token_url, recipients=mock_recipients)

        # Verify the type method returns the correct TransactionType
        self.assertEqual(
            mint_tokens.type(),
            TransactionType.ISSUE_TOKENS,
            "type should return TransactionType.MINT_TOKENS"
        )

    def test_missing_host_in_token_url_mint_token(self):
        """Test MintTokens with a token URL missing a host."""
        # Mock invalid token URL (empty authority)
        invalid_token_url = URL(authority="", path="/token")
        mock_recipients = []

        # Expecting a ValueError due to missing authority in token_url
        with self.assertRaises(ValueError) as context:
            MintTokens(token_url=invalid_token_url, recipients=mock_recipients)

        # Validate the exception message
        self.assertIn("Token URL authority cannot be empty", str(context.exception))


    def test_burn_tokens_type_URL(self):
        # Mock a URL instance
        mock_url = URL(authority="example.acme", path="/account")

        # Create a BurnTokens instance
        burn_tokens = BurnTokens(token_url=mock_url, amount=1000)

        # Assert that the type method returns the correct TransactionType
        self.assertEqual(burn_tokens.type(), TransactionType.BURN_TOKENS, 
                         "BurnTokens.type() did not return TransactionType.BURN_TOKENS")


    def test_invalid_url_type_TypeError(self):
        """Test that TypeError is raised when URL is not an instance of URL."""
        invalid_url = "not_a_url"  # Invalid type, not an instance of URL
        with self.assertRaises(TypeError) as context:
            CreateTokenIssuer(url=invalid_url)
        self.assertIn("url must be an instance of URL.", str(context.exception))

    def test_url_missing_authority_ValueError(self):
        """Test that ValueError is raised when URL is missing authority."""
        invalid_url = URL(authority="", path="/token")  # URL with no authority
        with self.assertRaises(ValueError) as context:
            CreateTokenIssuer(url=invalid_url)
        self.assertIn("Invalid URL: Missing authority component", str(context.exception))

    def test_debug_print_url_missing_authority_debug(self):
        """Test the exception message for missing authority."""
        invalid_url = URL(authority="", path="/token")  # URL with no authority
        with self.assertRaises(ValueError) as context:
            CreateTokenIssuer(url=invalid_url)
        self.assertIn(f"Invalid URL: Missing authority component in {invalid_url}", str(context.exception))


    def test_type_error_for_non_url_authorities_TypeError(self):
        """Test that TypeError is raised if authorities contain a non-URL instance."""
        valid_url = URL(authority="valid.example", path="/token")
        invalid_authorities = ["not_a_url", 123, None]  # Invalid authorities

        for invalid_authority in invalid_authorities:
            with self.assertRaises(TypeError) as context:
                CreateTokenIssuer(url=valid_url, authorities=[invalid_authority])
            self.assertIn("All authorities must be instances of URL", str(context.exception))

    def test_value_error_for_authorities_missing_authority_ValueError(self):
        """Test that ValueError is raised if an authority is missing an authority component."""
        valid_url = URL(authority="valid.example", path="/token")
        invalid_authority = URL(authority="", path="/invalid")

        with self.assertRaises(ValueError) as context:
            CreateTokenIssuer(url=valid_url, authorities=[invalid_authority])
        self.assertIn("Invalid authority URL", str(context.exception))

        """Test that the correct transaction type is returned."""
    def test_transaction_type_is_create_token_issuer_(self):
        """Test that the correct transaction type is returned."""
        valid_url = URL(authority="valid.example", path="/token")
        instance = CreateTokenIssuer(url=valid_url)
        self.assertEqual(instance.type(), TransactionType.CREATE_TOKEN)



    def test_url_initialization(self):
        """Test that the URL is correctly assigned during initialization."""
        mock_url = URL(authority="example.acme", path="/key-page")
        mock_operations = []
        
        transaction = UpdateKeyPage(url=mock_url, operations=mock_operations)
        
        self.assertEqual(transaction.url, mock_url)
        print(f"DEBUG: URL correctly initialized as: {transaction.url}")

    def test_operations_initialization(self):
        """Test that the operations are correctly assigned during initialization."""
        mock_url = URL(authority="example.acme", path="/key-page")
        mock_operations = [{"type": "add", "value": b"key1"}, {"type": "remove", "value": b"key2"}]
        
        transaction = UpdateKeyPage(url=mock_url, operations=mock_operations)
        
        self.assertEqual(transaction.operations, mock_operations)
        print(f"DEBUG: Operations correctly initialized as: {transaction.operations}")

    def test_transaction_type2(self):
        """Test that the transaction type is correctly returned."""
        mock_url = URL(authority="example.acme", path="/key-page")
        mock_operations = []
        
        transaction = UpdateKeyPage(url=mock_url, operations=mock_operations)
        
        self.assertEqual(transaction.type(), TransactionType.UPDATE_KEY_PAGE)
        print(f"DEBUG: Transaction type correctly returned as: {transaction.type()}")



    def test_url_data_marshal(self):
        """Test the URL marshaling with fixed size padding."""
        mock_url = URL(authority="example.acme", path="/key-page")
        transaction = UpdateKeyPage(url=mock_url, operations=[])
        
        url_data = transaction.url.marshal().ljust(32, b"\x00")
        expected_url_data = mock_url.marshal().ljust(32, b"\x00")
        
        self.assertEqual(url_data, expected_url_data)
        print(f"DEBUG: URL data marshaled as: {url_data}")

    def test_operations_data_marshal(self):
        """Test the marshaling of operations."""
        mock_url = URL(authority="example.acme", path="/key-page")
        mock_operations = [
            {"type": "add", "value": b"key1"},
            {"type": "remove", "value": b"key2"}
        ]
        transaction = UpdateKeyPage(url=mock_url, operations=mock_operations)

        operations_data = b"".join([transaction._marshal_operation(op) for op in transaction.operations])
        expected_operations_data = (
            transaction._marshal_operation({"type": "add", "value": b"key1"}) +
            transaction._marshal_operation({"type": "remove", "value": b"key2"})
        )
        
        self.assertEqual(operations_data, expected_operations_data)
        print(f"DEBUG: Operations data marshaled as: {operations_data}")

    def test_operations_length_marshal(self):
        """Test the marshaling of operations length."""
        mock_url = URL(authority="example.acme", path="/key-page")
        mock_operations = [
            {"type": "add", "value": b"key1"},
            {"type": "remove", "value": b"key2"}
        ]
        transaction = UpdateKeyPage(url=mock_url, operations=mock_operations)

        operations_data = b"".join([transaction._marshal_operation(op) for op in transaction.operations])
        operations_length = len(operations_data).to_bytes(4, "big")
        expected_length = len(operations_data).to_bytes(4, "big")
        
        self.assertEqual(operations_length, expected_length)
        print(f"DEBUG: Operations length marshaled as: {operations_length}")

    def test_marshal_combination(self):
        """Test the full marshaling process and combined output."""
        mock_url = URL(authority="example.acme", path="/key-page")
        mock_operations = [
            {"type": "add", "value": b"key1"},
            {"type": "remove", "value": b"key2"}
        ]
        transaction = UpdateKeyPage(url=mock_url, operations=mock_operations)

        marshaled_data = transaction.marshal()

        # Recreate expected marshaled data
        url_data = transaction.url.marshal().ljust(32, b"\x00")
        operations_data = b"".join([transaction._marshal_operation(op) for op in transaction.operations])
        operations_length = len(operations_data).to_bytes(4, "big")
        expected_data = url_data + operations_length + operations_data

        self.assertEqual(marshaled_data, expected_data)
        print(f"DEBUG: Full marshaled data: {marshaled_data}")

    # Tests for UpdateKeyPage
    def test_offset_initialization(self):
        """Test that the initial offset is correctly set to 0."""
        serialized_data = self.update_key_page_transaction.marshal()
        offset = 0
        self.assertEqual(offset, 0)
        print(f"DEBUG: Initial offset is {offset}")

    def test_url_data_extraction(self):
        """Test that the URL data is extracted and unmarshaled correctly."""
        serialized_data = self.update_key_page_transaction.marshal()
        offset = 0
        url_data = serialized_data[offset:offset + 32].rstrip(b"\x00")
        unmarshaled_url = URL.unmarshal(url_data)

        self.assertEqual(str(unmarshaled_url), str(self.mock_url))
        print(f"DEBUG: Extracted URL data: {url_data}")
        print(f"DEBUG: Unmarshaled URL: {unmarshaled_url}")

    def test_offset_increment_after_url(self):
        """Test that the offset is correctly incremented after reading the URL."""
        serialized_data = self.update_key_page_transaction.marshal()
        offset = 0
        offset += 32  # Simulate URL extraction
        self.assertEqual(offset, 32)
        print(f"DEBUG: Offset after reading URL is {offset}")

    def test_operations_length_extraction(self):
        """Test that the operations length is extracted correctly."""
        serialized_data = self.update_key_page_transaction.marshal()
        offset = 32  # Skip URL data
        operations_length = int.from_bytes(serialized_data[offset:offset + 4], "big")
        
        expected_operations_data = b"".join([self.update_key_page_transaction._marshal_operation(op) for op in self.mock_operations])
        self.assertEqual(operations_length, len(expected_operations_data))
        print(f"DEBUG: Extracted operations length: {operations_length}")
        print(f"DEBUG: Expected operations length: {len(expected_operations_data)}")

    def test_offset_increment_after_operations_length(self):
        """Test that the offset is correctly incremented after reading the operations length."""
        serialized_data = self.update_key_page_transaction.marshal()
        offset = 32  # Skip URL data
        offset += 4  # Simulate operations length extraction
        self.assertEqual(offset, 36)
        print(f"DEBUG: Offset after reading operations length is {offset}")

    def test_operations_data_extraction(self):
        """Test that the operations data is extracted and unmarshaled correctly."""
        serialized_data = self.update_key_page_transaction.marshal()
        offset = 32  # Skip URL data
        operations_length = int.from_bytes(serialized_data[offset:offset + 4], "big")
        offset += 4  # Move past operations length
        operations_data = serialized_data[offset:offset + operations_length]
        unmarshaled_operations = self.update_key_page_transaction._unmarshal_operations(operations_data)

        expected_operations = self.mock_operations
        self.assertEqual(unmarshaled_operations, expected_operations)
        print(f"DEBUG: Extracted operations data: {operations_data}")
        print(f"DEBUG: Unmarshaled operations: {unmarshaled_operations}")

    def test_full_unmarshal(self):
        """Test the full unmarshal process and ensure all components are correctly parsed."""
        serialized_data = self.update_key_page_transaction.marshal()
        unmarshaled_transaction = UpdateKeyPage(url=None, operations=[])
        unmarshaled_transaction.unmarshal(serialized_data)

        self.assertEqual(str(unmarshaled_transaction.url), str(self.mock_url))
        self.assertEqual(unmarshaled_transaction.operations, self.mock_operations)
        print(f"DEBUG: Fully unmarshaled transaction: URL={unmarshaled_transaction.url}, Operations={unmarshaled_transaction.operations}")

    def test_invalid_recipient_type(self):
        """Test that a TypeError is raised if recipient is not an instance of URL."""
        invalid_recipient = "not-a-url"  # Invalid recipient type (string)
        with self.assertRaises(TypeError) as context:
            AddCredits(recipient=invalid_recipient, amount=100)
        self.assertIn("recipient must be an instance of URL.", str(context.exception))
        print(f"DEBUG: Caught expected TypeError with message: {str(context.exception)}")

    def test_transaction_type_add_credits(self):
        """Test that the type method returns TransactionType.ADD_CREDITS."""
        valid_recipient = URL(authority="example.acme", path="/account")
        add_credits = AddCredits(recipient=valid_recipient, amount=100)

        self.assertEqual(
            add_credits.type(),
            TransactionType.ADD_CREDITS,
            "type() should return TransactionType.ADD_CREDITS"
        )
        print(f"DEBUG: type() returned {add_credits.type()} as expected")


    def test_transaction_type_update_account_auth(self):
        """Test that the type method returns TransactionType.UPDATE_ACCOUNT_AUTH."""
        # Create a valid URL and operations list
        account_url = URL(authority="example.acme", path="/account")
        operations = [
            {"type": "add", "value": b"new_key"},
            {"type": "remove", "value": b"old_key"}
        ]

        # Create an instance of UpdateAccountAuth
        update_account_auth = UpdateAccountAuth(account_url=account_url, operations=operations)

        # Check that the type() method returns the correct TransactionType
        self.assertEqual(
            update_account_auth.type(),
            TransactionType.UPDATE_ACCOUNT_AUTH,
            "type() should return TransactionType.UPDATE_ACCOUNT_AUTH"
        )
        print(f"DEBUG: type() returned {update_account_auth.type()} as expected")






    def test_transaction_initialization(self):
        """Test that the Transaction class initializes its attributes correctly."""
        # Mock objects for header and body
        mock_header = MagicMock()
        mock_body = MagicMock()

        # Initialize the Transaction instance
        transaction = Transaction(header=mock_header, body=mock_body)

        # Assert attributes are set correctly
        self.assertEqual(transaction.header, mock_header, "Transaction header should be correctly initialized.")
        self.assertEqual(transaction.body, mock_body, "Transaction body should be correctly initialized.")
        self.assertIsNone(transaction.hash, "Transaction hash should initially be None.")
        self.assertFalse(transaction.body64bytes, "Transaction body64bytes should initially be False.")

        print(f"DEBUG: Transaction initialized with header={transaction.header}, body={transaction.body}, "
              f"hash={transaction.hash}, body64bytes={transaction.body64bytes}")


    def test_transaction_is_user(self):
        """Test the is_user method of the Transaction class."""
        # Mock body with a valid type().is_user() method
        mock_body = MagicMock()
        mock_body.type().is_user.return_value = True  # Simulate a user transaction

        # Mock header
        mock_header = MagicMock()

        # Initialize the Transaction instance
        transaction = Transaction(header=mock_header, body=mock_body)

        # Assert that is_user returns True
        self.assertTrue(transaction.is_user(), "is_user should return True when body is a user transaction.")

        # Modify mock_body to simulate a non-user transaction
        mock_body.type().is_user.return_value = False
        self.assertFalse(transaction.is_user(), "is_user should return False when body is not a user transaction.")

        # Assert that is_user returns False when body is None
        transaction_no_body = Transaction(header=mock_header, body=None)
        self.assertFalse(transaction_no_body.is_user(), "is_user should return False when body is None.")

        print(f"DEBUG: is_user returned correct results based on body state and type().is_user().")





    def test_calculate_hash_when_hash_is_none(self):
        """Test that calculate_hash correctly computes the hash when self.hash is None."""
        # Expected hash calculation
        header_hash = hashlib.sha256(b"mock_header_data").digest()
        body_hash = b"mock_body_data"
        expected_hash = hashlib.sha256(header_hash + body_hash).digest()

        # Calculate hash
        calculated_hash = self.transaction.calculate_hash()

        # Assert that hash is correctly calculated and stored
        self.assertEqual(calculated_hash, expected_hash, "calculate_hash did not compute the expected hash.")
        self.assertEqual(self.transaction.hash, expected_hash, "Transaction hash attribute was not updated correctly.")

    def test_calculate_hash_when_hash_is_already_set(self):
        """Test that calculate_hash returns the pre-computed hash if self.hash is not None."""
        # Pre-set a mock hash
        self.transaction.hash = b"mock_precomputed_hash"

        # Call calculate_hash and ensure it doesn't recompute
        calculated_hash = self.transaction.calculate_hash()

        # Assert the returned hash is the pre-set value
        self.assertEqual(calculated_hash, b"mock_precomputed_hash", "calculate_hash should return the pre-set hash.")
        self.mock_header.marshal_binary.assert_not_called()
        self.mock_body.marshal.assert_not_called()

    def test_calculate_hash_without_body(self):
        """Test that calculate_hash computes the hash correctly when body is None."""
        # Create a transaction with no body
        transaction_without_body = Transaction(header=self.mock_header, body=None)

        # Expected hash calculation
        header_hash = hashlib.sha256(b"mock_header_data").digest()
        expected_hash = hashlib.sha256(header_hash + b"").digest()

        # Calculate hash
        calculated_hash = transaction_without_body.calculate_hash()

        # Assert that hash is correctly calculated
        self.assertEqual(calculated_hash, expected_hash, "calculate_hash did not compute the correct hash when body is None.")

    def test_get_id_with_principal(self):
        """Test that get_id returns the correct TxID when principal is set."""
        # Expected hash
        header_hash = hashlib.sha256(b"mock_header_data").digest()
        body_hash = b"mock_body_data"
        expected_hash = hashlib.sha256(header_hash + body_hash).digest()

        # Calculate the expected TxID
        expected_txid = TxID(url=URL.parse("acc://example_account"), tx_hash=expected_hash)

        # Get the transaction ID
        transaction_id = self.transaction.get_id()

        # Assert that the transaction ID matches the expected values
        self.assertEqual(transaction_id.url, expected_txid.url, "TxID URL does not match expected.")
        self.assertEqual(transaction_id.tx_hash, expected_txid.tx_hash, "TxID hash does not match expected.")


    def test_get_id_without_principal(self):
        """Test that get_id uses 'acc://unknown' as authority if principal is None."""
        # Set principal to None
        self.mock_header.principal = None

        # Expected hash
        header_hash = hashlib.sha256(b"mock_header_data").digest()
        body_hash = b"mock_body_data"
        expected_hash = hashlib.sha256(header_hash + body_hash).digest()

        # Calculate the expected TxID
        expected_txid = TxID(url=URL.parse("acc://unknown"), tx_hash=expected_hash)

        # Get the transaction ID
        transaction_id = self.transaction.get_id()

        # Assert that the transaction ID matches the expected values
        self.assertEqual(transaction_id.url, expected_txid.url, "TxID URL should be 'acc://unknown' when principal is None.")
        self.assertEqual(transaction_id.tx_hash, expected_txid.tx_hash, "TxID hash does not match expected.")

    def test_get_hash(self):
        """Test that get_hash retrieves the correct transaction hash."""
        # Expected hash
        header_hash = hashlib.sha256(b"mock_header_data").digest()
        body_hash = b"mock_body_data"
        expected_hash = hashlib.sha256(header_hash + body_hash).digest()

        # Get the hash using get_hash
        transaction_hash = self.transaction.get_hash()

        # Assert the hash is calculated and returned correctly
        self.assertEqual(transaction_hash, expected_hash, "get_hash did not return the expected transaction hash.")
        print(f"DEBUG: Retrieved transaction hash: {transaction_hash.hex()}")


    def test_body_is_64_bytes_true(self):
        """Test that body_is_64_bytes returns True when body is 64 bytes."""
        # Mock get_body_hash to return (hash, True)
        self.transaction.get_body_hash = MagicMock(return_value=(b"mock_body_hash", True))

        # Assert body_is_64_bytes returns True
        self.assertTrue(self.transaction.body_is_64_bytes(), "body_is_64_bytes should return True when the body is 64 bytes.")
        self.transaction.get_body_hash.assert_called_once()
        print("DEBUG: body_is_64_bytes returned True as expected.")

    def test_body_is_64_bytes_false(self):
        """Test that body_is_64_bytes returns False when body is not 64 bytes."""
        # Mock get_body_hash to return (hash, False)
        self.transaction.get_body_hash = MagicMock(return_value=(b"mock_body_hash", False))

        # Assert body_is_64_bytes returns False
        self.assertFalse(self.transaction.body_is_64_bytes(), "body_is_64_bytes should return False when the body is not 64 bytes.")
        self.transaction.get_body_hash.assert_called_once()
        print("DEBUG: body_is_64_bytes returned False as expected.")

    def test_calc_hash_returns_if_hash_is_not_none(self):
        """Test that calc_hash returns immediately if self.hash is already set."""
        # Set a pre-existing hash
        self.transaction.hash = b"existing_hash"

        # Call calc_hash
        self.transaction.calc_hash()

        # Assert that no new calculations were made
        self.mock_header.marshal_binary.assert_not_called()
        self.assertEqual(self.transaction.hash, b"existing_hash", "Hash should not be recomputed if it is already set.")



    def test_calc_hash_computes_header_hash(self):
        """Test that calc_hash correctly computes the header hash."""
        # Clear the hash to ensure computation
        self.transaction.hash = None

        # Call calc_hash
        self.transaction.calc_hash()

        # Verify header hash computation
        expected_header_hash = hashlib.sha256(b"mock_header_data").digest()
        self.mock_header.marshal_binary.assert_called_once()
        self.assertEqual(
            hashlib.sha256(self.mock_header.marshal_binary()).digest(),
            expected_header_hash,
            "Header hash is not computed correctly."
        )

    def test_calc_hash_computes_body_hash(self):
        """Test that calc_hash computes the body hash and sets body64bytes correctly."""
        # Clear the hash to ensure computation
        self.transaction.hash = None

        # Mock get_body_hash to return a specific hash and 64-byte flag
        with patch.object(self.transaction, "get_body_hash", return_value=(b"mock_body_hash", True)) as mock_get_body_hash:
            # Call calc_hash
            self.transaction.calc_hash()

            # Verify get_body_hash is called once
            mock_get_body_hash.assert_called_once()

            # Assert that body64bytes is set correctly
            self.assertTrue(self.transaction.body64bytes, "body64bytes should be True when the body is 64 bytes.")

            # Assert the hash matches the mocked hash computation
            header_hash = hashlib.sha256(self.mock_header.marshal_binary.return_value).digest()
            sha = hashlib.sha256()
            sha.update(header_hash)
            sha.update(b"mock_body_hash")
            expected_hash = sha.digest()

            self.assertEqual(self.transaction.hash, expected_hash, "Transaction hash is not computed correctly.")

    def test_calc_hash_combines_hashes(self):
        """Test that calc_hash combines header and body hashes correctly."""
        # Clear the hash to ensure computation
        self.transaction.hash = None

        # Call calc_hash
        self.transaction.calc_hash()

        # Combine expected header and body hashes
        expected_header_hash = hashlib.sha256(b"mock_header_data").digest()
        expected_body_hash = hashlib.sha256(b"mock_body_data").digest()  # Match mock_get_body_hash logic
        expected_combined_hash = hashlib.sha256(expected_header_hash + expected_body_hash).digest()

        # Verify combined hash
        self.assertEqual(
            self.transaction.hash,
            expected_combined_hash,
            "Combined hash (header + body) is not computed correctly."
        )

    def test_get_body_hash_with_64_bytes_body(self):
        """Test get_body_hash when the body size is exactly 64 bytes."""
        # Set the marshal return value to a 64-byte body
        self.mock_body.marshal.return_value = b"a" * 64  # 64 bytes of 'a'

        # Call the actual get_body_hash method
        body_hash, is_64_bytes = self.transaction.get_body_hash()

        # Expected hash
        expected_hash = hashlib.sha256(b"a" * 64).digest()

        # Assert the hash and is_64_bytes values
        self.assertEqual(body_hash, expected_hash, "Hash does not match expected value for 64-byte body.")
        self.assertTrue(is_64_bytes, "Expected is_64_bytes to be True when body is exactly 64 bytes.")



    def test_get_body_hash_no_body(self):
        """Test get_body_hash when there is no body."""
        # Create a transaction with no body
        transaction_without_body = Transaction(header=self.mock_header, body=None)

        # Call get_body_hash
        body_hash, is_64_bytes = transaction_without_body.get_body_hash()

        # Assert the hash and is_64_bytes values
        self.assertEqual(body_hash, b"", "Expected empty hash when body is None.")
        self.assertFalse(is_64_bytes, "Expected is_64_bytes to be False when body is None.")


    def test_get_body_hash_with_body(self):
        """Test get_body_hash when a body is present and not 64 bytes."""
        # Set the marshal return value to arbitrary data
        self.mock_body.marshal.return_value = b"mock_body_data"

        # Call the actual get_body_hash method
        body_hash, is_64_bytes = self.transaction.get_body_hash()

        # Expected hash
        expected_hash = hashlib.sha256(b"mock_body_data").digest()

        # Assert the hash and is_64_bytes values
        self.assertEqual(body_hash, expected_hash, "Hash does not match expected value for body.")
        self.assertFalse(is_64_bytes, "Expected is_64_bytes to be False when body is not 64 bytes.")

    def test_marshal_serializes_transaction(self):
        """Test the marshal method serializes the transaction correctly."""
        # Call marshal
        serialized_data = self.transaction.marshal()

        # Expected serialized format
        expected_header = b"mock_header_data"
        expected_body = b"mock_body_data"
        expected_serialized_data = (
            len(expected_header).to_bytes(2, "big") +
            expected_header +
            len(expected_body).to_bytes(2, "big") +
            expected_body
        )

        # Assert the serialized output matches the expected format
        self.assertEqual(serialized_data, expected_serialized_data, "Serialized data does not match the expected format.")



    def test_unmarshal_deserializes_transaction(self):
        """Test the unmarshal method deserializes the transaction correctly."""
        # Prepare serialized data
        header_data = b"mock_header_data"
        body_data = b"mock_body_data"
        serialized_data = (
            len(header_data).to_bytes(2, "big") +
            header_data +
            len(body_data).to_bytes(2, "big") +
            body_data
        )

        # Mock the unmarshal methods of header and body
        TransactionHeader.unmarshal = MagicMock(return_value=self.mock_header)
        self.mock_body.unmarshal = MagicMock(return_value=self.mock_body)

        # Call unmarshal
        self.transaction.unmarshal(serialized_data)

        # Assert header and body are unmarshaled correctly
        TransactionHeader.unmarshal.assert_called_once_with(header_data)
        self.mock_body.unmarshal.assert_called_once_with(body_data)
        self.assertEqual(self.transaction.header, self.mock_header, "Header was not unmarshaled correctly.")
        self.assertEqual(self.transaction.body, self.mock_body, "Body was not unmarshaled correctly.")




    def test_hash_write_data_with_entry_none(self):
        """Test hash_write_data when entry is None."""
        # Mock the transaction body
        mock_without_entry = MagicMock()
        mock_without_entry.marshal_binary.return_value = b"mock_body_data"

        # Call the function with entry as None
        result_hash = hash_write_data(mock_without_entry, None)

        # Expected hash
        hasher = hashlib.sha256()
        hasher.update(b"mock_body_data")
        hasher.update(b"\x00" * 32)
        expected_hash = hasher.digest()

        # Assert the hash matches
        self.assertEqual(result_hash, expected_hash, "Hash does not match expected value when entry is None.")
        mock_without_entry.marshal_binary.assert_called_once()



    def test_hash_write_data_with_entry(self):
        """Test hash_write_data when entry is provided."""
        # Mock the transaction body
        mock_without_entry = MagicMock()
        mock_without_entry.marshal_binary.return_value = b"mock_body_data"

        # Mock the DataEntry
        mock_entry = MagicMock()
        mock_entry.get_hash.return_value = b"mock_entry_hash"

        # Call the function with the mocked entry
        result_hash = hash_write_data(mock_without_entry, mock_entry)

        # Expected hash
        hasher = hashlib.sha256()
        hasher.update(b"mock_body_data")
        hasher.update(b"mock_entry_hash")
        expected_hash = hasher.digest()

        # Assert the hash matches
        self.assertEqual(result_hash, expected_hash, "Hash does not match expected value when entry is provided.")
        mock_without_entry.marshal_binary.assert_called_once()
        mock_entry.get_hash.assert_called_once()


    def test_transaction_result_with_details(self):
        """Test TransactionResult when details are provided."""
        # Sample details dictionary
        details = {"status": "success", "message": "Transaction completed"}
        
        # Create an instance of TransactionResult with details
        result = TransactionResult(details=details)

        # Assert that the details attribute matches the input dictionary
        self.assertEqual(result.details, details, "Details should match the input dictionary when provided.")


    def test_transaction_result_without_details(self):
        """Test TransactionResult when details is not provided."""
        # Create an instance of TransactionResult without details
        result = TransactionResult()

        # Assert that the details attribute is an empty dictionary
        self.assertEqual(result.details, {}, "Details should default to an empty dictionary when not provided.")



    def test_get_body_hash_with_normal_body(self):
        """Test get_body_hash with a body that is not 64 bytes."""
        # Set the body to return arbitrary marshaled data
        self.mock_body.marshal.return_value = b"mock_body_data"

        # Call get_body_hash
        body_hash, is_64_bytes = self.transaction.get_body_hash()

        # Expected hash
        expected_hash = hashlib.sha256(b"mock_body_data").digest()

        # Assertions
        self.assertEqual(body_hash, expected_hash, "Hash does not match expected value for normal body.")
        self.assertFalse(is_64_bytes, "Expected is_64_bytes to be False for non-64-byte body.")


    def test_get_body_hash_with_64_byte_body(self):
        """Test get_body_hash with a body that is exactly 64 bytes."""
        # Set the body to return 64 bytes of data
        self.mock_body.marshal.return_value = b"a" * 64  # 64 bytes of 'a'

        # Call get_body_hash
        body_hash, is_64_bytes = self.transaction.get_body_hash()

        # Expected hash
        expected_hash = hashlib.sha256(b"a" * 64).digest()

        # Assertions
        self.assertEqual(body_hash, expected_hash, "Hash does not match expected value for 64-byte body.")
        self.assertTrue(is_64_bytes, "Expected is_64_bytes to be True for 64-byte body.")


    def test_get_body_hash_with_empty_body(self):
        """Test get_body_hash when body is empty."""
        # Set the body to return empty marshaled data
        self.mock_body.marshal.return_value = b""

        # Call get_body_hash
        body_hash, is_64_bytes = self.transaction.get_body_hash()

        # Expected hash
        expected_hash = hashlib.sha256(b"").digest()

        # Assertions
        self.assertEqual(body_hash, expected_hash, "Hash does not match expected value for empty body.")
        self.assertFalse(is_64_bytes, "Expected is_64_bytes to be False for empty body.")


if __name__ == "__main__":
    unittest.main()