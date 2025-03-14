# accumulate/config.py

# Define Accumulate network base URLs (without "/v3")
# ACCUMULATE_RPC_URL = "https://testnet.accumulatenetwork.io"  # Default: Testnet

ACCUMULATE_RPC_URL = "https://mainnet.accumulatenetwork.io"  # Default: Testnet

# Optional: Add mainnet and custom options
ACCUMULATE_MAINNET_URL = "https://mainnet.accumulatenetwork.io"
ACCUMULATE_TESTNET_URL = "https://testnet.accumulatenetwork.io"
ACCUMULATE_CUSTOM_URL = None  # Set this if using a custom Accumulate node

# Function to get the active Accumulate RPC URL
def get_accumulate_rpc_url():
    """Returns the currently selected Accumulate RPC URL."""
    return ACCUMULATE_CUSTOM_URL or ACCUMULATE_RPC_URL
