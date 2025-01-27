# accumulate-python-client\tests\test_models\test_transactions.py


import unittest
from unittest.mock import MagicMock
from accumulate.models.enums import TransactionType
from accumulate.models.errors import AccumulateError, ErrorCode
from accumulate.models.data_entries import AccumulateDataEntry
from accumulate.models.transactions import (
    TransactionStatus, WriteData, WriteDataTo, IssueTokens, BurnCredits,
    TransferCredits, CreateLiteTokenAccount, CreateKeyPage, CreateKeyBook,
    CreateDataAccount, SendTokens, CreateIdentity, CreateTokenAccount, CreateToken,
    MintTokens, BurnTokens, CreateTokenIssuer, UpdateKeyPage, AddCredits, UpdateAccountAuth, Transaction
)
from accumulate.models.general import CreditRecipient, TokenRecipient
from accumulate.utils.url import URL
import hashlib
from accumulate.models.key_management import KeySpecParams

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
        recipient = TokenRecipient(URL("mint_recipient"), 500)
        mint_tokens = MintTokens(token_url=URL("mint_url"), recipients=[recipient])

        # Marshal the object
        marshaled = mint_tokens.marshal()
        print(f"DEBUG: Marshaled MintTokens data: {marshaled.hex()}")
        self.assertIsInstance(marshaled, bytes)

        # Unmarshal the data
        unmarshaled = MintTokens(token_url=None, recipients=[]).unmarshal(marshaled)
        print(f"DEBUG: Unmarshaled MintTokens: token_url={unmarshaled.token_url}, recipients={unmarshaled.recipients}")

        # Verify unmarshaled data
        self.assertEqual(unmarshaled.token_url.marshal().decode("utf-8"), "acc://mint_url")
        self.assertEqual(len(unmarshaled.recipients), 1)
        self.assertEqual(unmarshaled.recipients[0].url.marshal().decode("utf-8"), "acc://mint_recipient")
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

    def test_transaction_type(self):
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

    def test_transaction_type(self):
        """Test the type method of CreateIdentity."""
        mock_url = URL(authority="example.com", path="/identity")

        create_identity = CreateIdentity(url=mock_url)
        self.assertEqual(
            create_identity.type(),
            TransactionType.CREATE_IDENTITY,
            "type should return TransactionType.CREATE_IDENTITY"
        )









if __name__ == "__main__":
    unittest.main()