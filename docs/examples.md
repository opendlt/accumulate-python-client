# Getting Started

Welcome to the **Accumulate Python Client**! Follow these steps to get up and running quickly.

---

## 📦 Installation

```bash
pip install accumulate-python-client
```
Note: You may need to activate your Python virtual environment before running the above command.

## ✅ Basic Usage
Here's a simple example of how to initialize the client and make a basic request:

```bash
from accumulate import AccumulateClient
```

## Initialize client
```bash
client = AccumulateClient(base_url="https://testnet.accumulatenetwork.io")
```

## Query an account
```bash
response = client.query.get_account("acc://example.acme")
print(response)
```

## 🌐 Connecting to Networks
By default, you can connect to:
### Mainnet: https://mainnet.accumulatenetwork.io
### Testnet: https://testnet.accumulatenetwork.io


# 📌 Examples

This section contains useful examples demonstrating how to use the **Accumulate Python Client**.

All full scripts can be found in the [GitHub repository](https://github.com/opendlt/accumulate-python-client/tree/main/examples).

---

## 🔍 Querying the Blockchain

### Example: Query an Account

This example demonstrates how to query an account on the **Accumulate Network**.

```python
from accumulate import AccumulateClient

# Initialize client
client = AccumulateClient(base_url="https://testnet.accumulatenetwork.io")

# Query an account
response = client.query.get_account("acc://example.acme")
print(response)
➡ Full script: query_basic_example.py

Example: Search for an Account
python
Copy
from accumulate import AccumulateClient

# Initialize client
client = AccumulateClient(base_url="https://testnet.accumulatenetwork.io")

# Search for accounts matching a name
response = client.query.search_accounts("acme")
print(response)
➡ Full script: search_method_example.py

💰 Token Transactions
Example: Send Tokens
This example shows how to send tokens from one account to another.

python
Copy
from accumulate import AccumulateClient
from accumulate.transactions import TokenTransfer

client = AccumulateClient(base_url="https://testnet.accumulatenetwork.io")

tx = TokenTransfer(
    sender="acc://sender.acme",
    recipient="acc://recipient.acme",
    amount=1000
)

response = client.transactions.submit(tx)
print(response)
➡ Full script: new_method_debug_series-sendTokens.py

🆕 Identity and Account Management
Example: Create an Identity
python
Copy
from accumulate import AccumulateClient
from accumulate.transactions import CreateIdentity

client = AccumulateClient(base_url="https://testnet.accumulatenetwork.io")

tx = CreateIdentity(
    identity="acc://newidentity.acme",
    public_key="ADDEADBEEF..."  # Replace with actual public key
)

response = client.transactions.submit(tx)
print(response)
➡ Full script: new_method_debug_series-createIdentity.py

🔑 Key Management
Example: Create a Key Page
python
Copy
from accumulate import AccumulateClient
from accumulate.transactions import CreateKeyPage

client = AccumulateClient(base_url="https://testnet.accumulatenetwork.io")

tx = CreateKeyPage(
    keys=["ADDEADBEEF...", "BEEFDEADFA..."]  # Replace with actual keys
)

response = client.transactions.submit(tx)
print(response)
➡ Full script: new_method_debug_series-createKeyPage.py

🔄 Debugging & Utilities
Example: Signer Debugging
This script helps debug transaction signing.

➡ Full script: signer_debug.py

📂 More Examples
All example scripts are available in the examples directory. If you have additional use cases you'd like to see, feel free to submit a pull request or open an issue!



# 📚 Next Steps
Explore API Reference
Check out Examples
Learn how to Contribute