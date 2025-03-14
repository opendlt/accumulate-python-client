# Examples

Welcome to the **Accumulate Python Client** examples section!  
This collection demonstrates **real, working examples** of common operations using the library — everything from querying accounts to managing identities and sending tokens.

> **Tip:** All example scripts are available in the [GitHub examples directory](https://github.com/opendlt/accumulate-python-client/tree/main/examples).  
> You can run these directly to see how each feature works in a real environment.

---

### Generate a Lite Token Account and Request Faucet
```python
from accumulate import AccumulateClient
from accumulate.utils.address_from import generate_ed25519_keypair
from accumulate.utils.hash_functions import LiteAuthorityForKey

# Generate keypair and derive Lite Account URL
private_key, public_key = generate_ed25519_keypair()
lite_identity = LiteAuthorityForKey(public_key, "ED25519")
lite_account = f"{lite_identity}/ACME"

client = AccumulateClient("https://testnet.accumulatenetwork.io")
print("Lite Account URL:", lite_account)
```
➡ **Full script**: [method_debug_LTA_faucet.py](https://github.com/opendlt/accumulate-python-client/blob/main/examples/method_debug_LTA_faucet.py)

---

### Query an Account
```python
from accumulate import AccumulateClient

client = AccumulateClient("https://testnet.accumulatenetwork.io")
account_url = "acc://custom-adi-name-1741948502948.acme/CTACUST"
response = client.query.get_account(account_url)
print("Account details:", response)
```
➡ **Full script**: [method_debug_query_simple.py](https://github.com/opendlt/accumulate-python-client/blob/main/examples/method_debug_query_simple.py)

---

### Prepare an AddCredits Transaction (Key Page Version)
```python
from accumulate import AccumulateClient, AddCredits

client = AccumulateClient("https://testnet.accumulatenetwork.io")
lite_account = "acc://your-lite-identity/ACME"
tx = AddCredits(client, lite_account, 10000)
print("Prepared AddCredits transaction for", lite_account)
```
➡ **Full script**: [method_debug_series-addcredits_keypage.py](https://github.com/opendlt/accumulate-python-client/blob/main/examples/method_debug_series-addcredits_keypage.py)

---

### Prepare a Basic AddCredits Transaction
```python
from accumulate import AccumulateClient, AddCredits

client = AccumulateClient("https://testnet.accumulatenetwork.io")
account_url = "acc://your-identity/ACME"
tx = AddCredits(client, account_url, 200)
print("AddCredits transaction ready for", account_url)
```
➡ **Full script**: [method_debug_series-addcredits.py](https://github.com/opendlt/accumulate-python-client/blob/main/examples/method_debug_series-addcredits.py)

---

### Create a New Identity (ADI)
```python
from accumulate import AccumulateClient, CreateIdentity

client = AccumulateClient("https://testnet.accumulatenetwork.io")
new_identity = "acc://test0001python.acme"
keybook_url = "acc://test0001python.acme/Keybook"
tx = CreateIdentity(new_identity, b"your_public_key", keybook_url)
print("Identity creation transaction prepared for", new_identity)
```
➡ **Full script**: [method_debug_series-createIdentity.py](https://github.com/opendlt/accumulate-python-client/blob/main/examples/method_debug_series-createIdentity.py)

---

### Create a Custom Token Account
```python
from accumulate import AccumulateClient, CreateTokenAccount

client = AccumulateClient("https://testnet.accumulatenetwork.io")
token_account = "acc://custom-adi-name-1741948502948.acme/CTACUST"
token_issuer = "acc://custom-adi-name-1741948502948.acme/CUST"
tx = CreateTokenAccount(url=token_account, token_url=token_issuer)
print("Custom Token Account transaction created for", token_account)
```
➡ **Full script**: [method_debug_series-createCustomTokenAccount.py](https://github.com/opendlt/accumulate-python-client/blob/main/examples/method_debug_series-createCustomTokenAccount.py)

---

### Create a Data Account Transaction
```python
from accumulate import AccumulateClient, CreateDataAccount

client = AccumulateClient("https://testnet.accumulatenetwork.io")
data_account = "acc://custom-adi-name-1741948502948.acme/Data2"
tx = CreateDataAccount(url=data_account)
print("Data Account transaction ready for", data_account)
```
➡ **Full script**: [method_debug_series-createDataAccount.py](https://github.com/opendlt/accumulate-python-client/blob/main/examples/method_debug_series-createDataAccount.py)

---

### Write Data to a Data Account
```python
from accumulate import AccumulateClient, WriteData
from accumulate.models.data_entries import DoubleHashDataEntry

client = AccumulateClient("https://testnet.accumulatenetwork.io")
data_account = "acc://custom-adi-name-1741948502948.acme/Data"

# Define a sample data payload
payload = b"This is a test data entry for Accumulate 1."
entry = DoubleHashDataEntry(data=[payload])

# Create a WriteData transaction body
tx = WriteData(entry=entry, scratch=False, write_to_state=True)
print("WriteData transaction prepared for", data_account)
```
➡ **Full script**: [new_method_debug_series-writeData.py](https://github.com/opendlt/accumulate-python-client/blob/main/examples/new_method_debug_series-writeData.py)

---

### Create a Custom Token
```python
from accumulate import AccumulateClient, CreateToken

client = AccumulateClient("https://testnet.accumulatenetwork.io")
token_url = "acc://custom-adi-name-1741948502948.acme/CUST"
tx = CreateToken(url=token_url, symbol="CUST", precision=4, supply_limit=1000000)
print("Token creation transaction prepared for", token_url)
```
➡ **Full script**: [method_debug_series-createToken.py](https://github.com/opendlt/accumulate-python-client/blob/main/examples/method_debug_series-createToken.py)

---

### Create an ADI Token Account
```python
from accumulate import AccumulateClient, CreateTokenAccount

client = AccumulateClient("https://testnet.accumulatenetwork.io")
token_account = "acc://custom-adi-name-1741948502948.acme/Tokens"
token_issuer = "acc://ACME"
tx = CreateTokenAccount(url=token_account, token_url=token_issuer)
print("Token Account creation transaction ready for", token_account)
```
➡ **Full script**: [method_debug_series-createTokenAccount.py](https://github.com/opendlt/accumulate-python-client/blob/main/examples/method_debug_series-createTokenAccount.py)

---

### Issue Custom Tokens 
```python
from accumulate import AccumulateClient, IssueTokens, TokenRecipient

client = AccumulateClient("https://testnet.accumulatenetwork.io")
recipient = TokenRecipient("acc://custom-adi-name-1741948502948.acme/CTACUST", 5270000)
tx = IssueTokens([recipient])
print("IssueTokens transaction prepared.")
```
➡ **Full script**: [method_debug_series-issueToken.py](https://github.com/opendlt/accumulate-python-client/blob/main/examples/method_debug_series-issueToken.py)

---

### Send Tokens
```python
from accumulate import AccumulateClient, SendTokens

client = AccumulateClient("https://testnet.accumulatenetwork.io")
tx = SendTokens()
tx.add_recipient("acc://0408e2065256be92207b41e72f77ef154fc242a4dec2a3e6/ACME", 11)
print("SendTokens transaction created.")
```
➡ **Full script**: [method_debug_series-sendTokens.py](https://github.com/opendlt/accumulate-python-client/blob/main/examples/method_debug_series-sendTokens.py)

---

## Full Example Directory Structure

```plaintext
examples/
├── method_debug_block_query.py                    # Query blocks and chain metadata
├── method_debug_LTA_faucet.py                     # Request ACME via faucet to a Lite Token Account (LTA)
├── method_debug_LTA_faucet_specify_account.py     # Faucet for a specifically defined account
├── method_debug_metrics_services.py              # Access network metrics and system services
├── method_debug_query_method_suite.py            # Comprehensive suite of query methods
├── method_debug_query_simple.py                  # Basic account query example
├── method_debug_search_method_examples.py        # Search accounts and data
├── method_debug_series-addcredits.py             # Add credits to Lite Token Account
├── method_debug_series-addcredits_keypage.py     # Add credits via a Key Page
├── method_debug_series-burnCustToken.py          # Burn custom tokens (destroy tokens)
├── method_debug_series-createCustomTokenAccount.py # Create custom token account (non-ACME tokens)
├── method_debug_series-createDataAccount.py      # Create a data account for storing on-chain data
├── method_debug_series-createIdentity.py         # Create an Accumulate Digital Identity (ADI)
├── method_debug_series-createKeyBook.py          # Create a Key Book to manage Key Pages
├── method_debug_series-createKeyPage.py          # Create a Key Page to hold keys
├── method_debug_series-createToken.py            # Create a new custom token (Issuer)
├── method_debug_series-createTokenAccount.py     # Create a Token Account (for ACME or Custom tokens)
├── method_debug_series-issueToken.py             # Issue (mint) custom tokens to a custom token account
├── method_debug_series-sendTokens.py             # Send tokens between accounts (ACME or Custom tokens)
├── method_debug_series-updateAuth.py             # Update account authorities
├── method_debug_series-updateKeyPage.py          # Udpate Key page with a key
├── method_debug_series-updateKeyPageDelegate.py  # Udpate Key page with a delegate
├── method_debug_series-update_auth_menu.py       # Interactive menu for numerous types account authorities Updates
├── method_debug_series-update_key_page_menu.py   # Interactive menu for numerous types of Key Page Updates
├── method_debug_series-writeData.py              # Write arbitrary data to a Data Account
```

**Browse all examples on [GitHub](https://github.com/opendlt/accumulate-python-client/tree/main/examples).**

---

## Next Steps

**Explore the [API Reference](api_reference.md)**  
**Check out more [Getting Started](getting_started.md)**  
**Learn how to [Contribute](contributing.md)**  

---

## Questions or Issues?

If you encounter any issues, please [open an issue](https://github.com/opendlt/accumulate-python-client/issues) on GitHub, or submit a pull request with improvements!
