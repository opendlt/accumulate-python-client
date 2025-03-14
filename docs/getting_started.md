# Getting Started

Welcome to the **Accumulate Python Client**!  
Follow these steps to **quickly install and start using** the client for interacting with the [Accumulate Protocol](https://accumulatenetwork.io/).

---

## Installation

### Prerequisites

Make sure you have the following installed:

- **Python 3.8+**
- **pip** (Python package manager)
- *(Optional)* **git** (for cloning the repo)
- *(Optional but recommended)* **virtualenv** (for isolated environments)

---

### Option 1: Install via PyPI (Recommended for most users)

Install the library directly from PyPI:

```bash
pip install accumulate-python-client
```

---

### Option 2: Install from Source (For development or latest updates)

#### 1. Clone the repository

```bash
git clone https://github.com/opendlt/accumulate-python-client.git
cd accumulate-python-client
```

#### 2. (Recommended) Create and activate a virtual environment

**On Windows:**
```bash
python -m venv venv
venv\Scripts\activate
```

**On macOS/Linux:**
```bash
python3 -m venv venv
source venv/bin/activate
```

#### 3. Install dependencies

```bash
pip install -r requirements.txt
```

---

## Network Endpoints

You can connect the client to either **Testnet** or **Mainnet** depending on your needs.

| Network  | URL                                             |
|---------|-------------------------------------------------|
| Testnet | `https://testnet.accumulatenetwork.io/v3`        |
| Mainnet | `https://mainnet.accumulatenetwork.io/v3`        |

---

## Next Steps

- Check out **[Examples](examples.md)** to see real working code.
- Explore the **[API Reference](api_reference.md)** for detailed documentation on all available methods.
- Learn how to **[Contribute](contributing.md)** to improve and extend the library.

---

## Need Help?

If you encounter issues or have questions, feel free to:
- [Open an issue](https://github.com/opendlt/accumulate-python-client/issues)
- Submit a [pull request](https://github.com/opendlt/accumulate-python-client/pulls) with improvements

---

Ready to start building on **Accumulate**? 🚀  
Happy coding!
