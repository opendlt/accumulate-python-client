# accumulate-python-client\tests\test_models\test_service.py

import pytest
from datetime import timedelta
from accumulate.models.service import ServiceAddress, FindServiceOptions, FindServiceResult

SERVICE_ADDRESS = "0x01:argument"  # Example service address

# --- Tests for ServiceAddress ---
def test_service_address_initialization():
    """Test initializing a ServiceAddress."""
    address = ServiceAddress(service_type=1, argument="example")
    assert address.service_type == 1
    assert address.argument == "example"


def test_service_address_string_representation_with_argument():
    """Test string representation with argument."""
    address = ServiceAddress(service_type=1, argument="example")
    assert str(address) == "1:example"


def test_service_address_string_representation_without_argument():
    """Test string representation without argument."""
    address = ServiceAddress(service_type=1)
    assert str(address) == "1"


def test_service_address_to_dict():
    """Test converting ServiceAddress to a dictionary."""
    address = ServiceAddress(service_type=1, argument="example")
    expected = {"type": 1, "argument": "example"}
    assert address.to_dict() == expected


def test_service_address_from_dict():
    """Test creating a ServiceAddress from a dictionary."""
    data = {"type": 1, "argument": "example"}
    address = ServiceAddress.from_dict(data)
    assert address.service_type == 1
    assert address.argument == "example"


def test_service_address_parsing():
    """Test parsing a service address string into a ServiceAddress object."""
    service_address = ServiceAddress.parse_service_address(SERVICE_ADDRESS)
    assert isinstance(service_address, ServiceAddress)
    assert service_address.type == 0x01
    assert service_address.argument == "argument"


def test_service_address_unpacking():
    """Test unpacking a service address string into its components."""
    unpacked = ServiceAddress.unpack_address(SERVICE_ADDRESS)
    assert unpacked["type"] == 0x01
    assert unpacked["argument"] == "argument"


def test_service_address_invalid():
    """Test parsing an invalid service address."""
    invalid_addresses = [
        "",                     # Empty string
        "invalid_address",      # Missing ':' separator
        "0x01:",                # Missing argument
        ":argument",            # Missing service type
    ]
    for invalid_address in invalid_addresses:
        with pytest.raises(ValueError, match="Invalid service address"):
            ServiceAddress.parse_service_address(invalid_address)


# --- Tests for FindServiceOptions ---
def test_find_service_options_initialization():
    """Test initializing FindServiceOptions."""
    options = FindServiceOptions(network="mainnet")
    assert options.network == "mainnet"
    assert options.service is None
    assert options.known is None
    assert options.timeout is None


def test_find_service_options_to_dict_without_service():
    """Test converting FindServiceOptions to a dictionary without service."""
    options = FindServiceOptions(network="mainnet", known=True, timeout=timedelta(seconds=30))
    expected = {
        "network": "mainnet",
        "service": None,
        "known": True,
        "timeout": 30.0,
    }
    assert options.to_dict() == expected


def test_find_service_options_to_dict_with_service():
    """Test converting FindServiceOptions to a dictionary with service."""
    service = ServiceAddress(service_type=1, argument="example")
    options = FindServiceOptions(network="mainnet", service=service, known=True, timeout=timedelta(seconds=30))
    expected = {
        "network": "mainnet",
        "service": {"type": 1, "argument": "example"},
        "known": True,
        "timeout": 30.0,
    }
    assert options.to_dict() == expected


def test_find_service_options_from_dict_without_service():
    """Test creating FindServiceOptions from a dictionary without service."""
    data = {
        "network": "mainnet",
        "known": True,
        "timeout": 30.0,
    }
    options = FindServiceOptions.from_dict(data)
    assert options.network == "mainnet"
    assert options.service is None
    assert options.known is True
    assert options.timeout == timedelta(seconds=30)


def test_find_service_options_from_dict_with_service():
    """Test creating FindServiceOptions from a dictionary with service."""
    data = {
        "network": "mainnet",
        "service": {"type": 1, "argument": "example"},
        "known": True,
        "timeout": 30.0,
    }
    options = FindServiceOptions.from_dict(data)
    assert options.network == "mainnet"
    assert options.service.service_type == 1
    assert options.service.argument == "example"
    assert options.known is True
    assert options.timeout == timedelta(seconds=30)


# --- Tests for FindServiceResult ---
def test_find_service_result_initialization():
    """Test initializing FindServiceResult."""
    result = FindServiceResult(peer_id="peer1", status="active", addresses=["addr1", "addr2"])
    assert result.peer_id == "peer1"
    assert result.status == "active"
    assert result.addresses == ["addr1", "addr2"]


def test_find_service_result_to_dict():
    """Test converting FindServiceResult to a dictionary."""
    result = FindServiceResult(peer_id="peer1", status="active", addresses=["addr1", "addr2"])
    expected = {
        "peer_id": "peer1",
        "status": "active",
        "addresses": ["addr1", "addr2"],
    }
    assert result.to_dict() == expected


def test_find_service_result_from_dict():
    """Test creating FindServiceResult from a dictionary."""
    data = {
        "peer_id": "peer1",
        "status": "active",
        "addresses": ["addr1", "addr2"],
    }
    result = FindServiceResult.from_dict(data)
    assert result.peer_id == "peer1"
    assert result.status == "active"
    assert result.addresses == ["addr1", "addr2"]


# --- Tests for ServiceAddress ---
def test_service_address_parsing():
    """
    Test parsing a service address string into a ServiceAddress object.
    """
    service_address = ServiceAddress.parse_service_address(SERVICE_ADDRESS)
    assert isinstance(service_address, ServiceAddress)
    assert service_address.type == 0x01
    assert service_address.argument == "argument"


def test_service_address_unpacking():
    """
    Test unpacking a service address string into its components.
    """
    unpacked = ServiceAddress.unpack_address(SERVICE_ADDRESS)
    assert unpacked["type"] == 0x01
    assert unpacked["argument"] == "argument"


def test_service_address_invalid():
    """
    Test parsing an invalid service address.
    """
    invalid_addresses = [
        "",                     # Empty string
        "invalid_address",      # Missing ':' separator
        "0x01:",                # Missing argument
        ":argument",            # Missing service type
    ]
    for invalid_address in invalid_addresses:
        with pytest.raises(ValueError, match="Invalid service address"):
            ServiceAddress.parse_service_address(invalid_address)




if __name__ == "__main__":
    unittest.main()
