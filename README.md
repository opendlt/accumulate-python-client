# Accumulate Python Client

![Accumulate](https://accumulate.network/assets/img/logo.svg)

The **Accumulate Python Client** is a robust library designed for developers to interact seamlessly with the [Accumulate Protocol](https://accumulatenetwork.io/). This library simplifies working with accounts, transactions, signatures, querying blockchain data, and more within the Accumulate blockchain ecosystem.

---

## Key Features

- **Account Management**: Effortlessly manage token accounts, lite accounts, and keybooks.
- **Transaction Handling**: Construct, sign, and submit blockchain transactions with ease.
- **Event and Data Querying**: Fetch and process data from the Accumulate blockchain.
- **Cryptographic Utilities**: Tools for signing, verifying, and working with keys and addresses.
- **Blockchain Utilities**: Support for URL parsing, data encoding, and validation.

---

## Installation

Install the library using `pip`:

```bash
pip install accumulate-python-client
```

---

## Quick Start

Here’s how to get started with the Accumulate Python Client:

```python
from accumulate.api.client import AccumulateClient

# Initialize the client
client = AccumulateClient(base_url="<Endpoint>")

Endpoints
* Testnet Endpoint: https://testnet.accumulatenetwork.io/v2
* Mainnet Endpoint: https://mainnet.accumulatenetwork.io/v2

# Query account information
response = client.query_account("acc://example_account")
print(response)
```

---

## Library Overview

The library is structured to provide modular and extensible components for various blockchain operations. Below is a high-level overview of the project structure:

### Core Structure

```plaintext
C:.
│   LICENSE                # Terms for using the library
│   pyproject.toml         # Configuration for Python dependencies, metadata, and build systems
│   README.md              # Documentation for setup, usage, and API reference
│   requirements.txt       # Python dependencies for the project
│   setup.py               # Script for packaging and installation
│
├───accumulate
│   │   __init__.py        # Initializes the main package
│   │
│   ├───api
│   │   │   client.py          # Main interface for interacting with the API
│   │   │   context.py         # Context management utilities for requests
│   │   │   endpoints.py       # Definitions and handlers for API endpoints
│   │   │   exceptions.py      # Custom error handling utilities
│   │   │   querier.py         # Utilities for querying blockchain data
│   │   │   transport.py       # Network communication layer abstraction
│   │
│   ├───models
│   │   │   AccountAuthOperations.py  # Models for operations on account authentication
│   │   │   accounts.py               # Models for account-related structures and properties
│   │   │   address.py                # Models and utilities for managing blockchain addresses
│   │   │   auth.py                   # Models for account authentication and authority management
│   │   │   base_transactions.py      # Base models for constructing transactions
│   │   │   credits.py                # Models for managing credit balances and transactions
│   │   │   data_entries.py           # Models for data entry management within the blockchain
│   │   │   enums.py                  # Enumerations for constants like transaction and query types
│   │   │   errors.py                 # Models for representing error codes and handling exceptions
│   │   │   events.py                 # Models for event-related data and blockchain subscriptions
│   │   │   faucet.py                 # Models for interacting with the Accumulate faucet
│   │   │   fee_schedule.py           # Models and utilities for defining network fee schedules
│   │   │   general.py                # General-purpose models for blockchain metadata and utilities
│   │   │   key_management.py         # Models for key management and specifications
│   │   │   node_info.py              # Models for node and network information
│   │   │   options.py                # Models for defining request options and filters
│   │   │   protocol.py               # Protocol-level constants and configurations
│   │   │   queries.py                # Models for constructing and serializing API queries
│   │   │   records.py                # Models for organizing and managing blockchain data records
│   │   │   responses.py              # Models for handling API responses
│   │   │   service.py                # Models for managing services and operations
│   │   │   signatures.py             # Models for cryptographic signatures and validation
│   │   │   submission.py             # Models for data submission to the blockchain
│   │   │   transactions.py           # Models for constructing and managing blockchain transactions
│   │   │   transaction_results.py    # Models for handling transaction results
│   │   │   txid_set.py               # Models for managing sets of transaction IDs
│   │   │   types.py                  # General-purpose utilities for shared data types and counters
│   │   │   __init__.py               # Exports all models for the `models` package
│   │
│   ├───signing
│   │   │   builder.py                # Tools for constructing transaction payloads
│   │   │   signature_handler.py      # Cryptographic signature management
│   │   │   signer.py                 # Transaction signing tools
│   │   │   timestamp.py              # Utilities for handling timestamps
│   │
│   ├───utils
│   │   │   address_parse.py          # Utilities for parsing blockchain addresses
│   │   │   encoding.py               # Tools for encoding/decoding data
│   │   │   validation.py             # Input validation utilities
│   │   │   ...                       # Additional general-purpose utilities
│
├───docs
│       api_reference.md              # Comprehensive API documentation
```

---

## Documentation

Detailed usage instructions, examples, and API references are available in the `docs` directory. Check out `docs/api_reference.md` for complete API details.

---

## License

This project is licensed under the terms of the MIT License. See the `LICENSE` file for more information.

---

## Acknowledgements

This library was developed by **Jason Gregoire** for [OpenDLT.org](https://opendlt.org), with a mission to leverage Distributed Ledger Technology (DLT) for positive global change.