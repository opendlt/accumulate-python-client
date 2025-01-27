# accumulate-python-client\tests\test_models\test_types.py

import pytest
import json
import hashlib
from datetime import datetime, timedelta
from accumulate.models.types import (
    AtomicUint,
    AtomicSlice,
    LastStatus,
    PeerAddressStatus,
    PeerServiceStatus,
    PeerNetworkStatus,
    PeerStatus,
    NetworkState,
    NetworkConfigRequest,
    NetworkConfigResponse,
    PartitionList,
    PartitionListResponse,
    SeedList,
    SeedListResponse,
    MessageType,
    Message,
    TransactionMessage,
    SignatureMessage,
    serialize,
    deserialize,
)


def test_atomic_uint():
    """Test AtomicUint class."""
    atomic = AtomicUint(5)
    assert atomic.load() == 5

    atomic.increment()
    assert atomic.load() == 6

    atomic.store(10)
    assert atomic.load() == 10


def test_atomic_slice():
    """Test AtomicSlice class."""
    slice = AtomicSlice()
    slice.add(1)
    slice.add(2)
    assert slice.compare([1, 2]) is True
    assert slice.compare([2, 3]) is False


def test_last_status():
    """Test LastStatus class."""
    status = LastStatus()
    assert status.since_attempt() == timedelta.max
    assert status.since_success() == timedelta.max

    status.did_attempt()
    assert isinstance(status.since_attempt(), timedelta)

    status.did_succeed()
    assert isinstance(status.since_success(), timedelta)
    assert status.failed.load() == 0



def test_peer_address_status():
    """Test PeerAddressStatus class."""
    peer1 = PeerAddressStatus("address1")
    peer2 = PeerAddressStatus("address2")
    peer3 = PeerAddressStatus("ADDRESS1")

    assert peer1.compare(peer2) is False
    assert peer1.compare(peer3) is True


def test_peer_service_status():
    """Test PeerServiceStatus class."""
    service1 = PeerServiceStatus("service1")
    service2 = PeerServiceStatus("service2")
    service3 = PeerServiceStatus("SERVICE1")

    assert service1.compare(service2) is False
    assert service1.compare(service3) is True


def test_peer_network_status():
    """Test PeerNetworkStatus class."""
    network1 = PeerNetworkStatus("network1")
    network2 = PeerNetworkStatus("network2")
    network3 = PeerNetworkStatus("NETWORK1")

    assert network1.compare(network2) is False
    assert network1.compare(network3) is True


def test_peer_status():
    """Test PeerStatus class."""
    peer = PeerStatus("peer1")
    peer.unmarshal_json('{"ID": "peer2", "addresses": [], "networks": []}')
    assert peer.id == "peer2"


def test_network_state():
    """Test NetworkState class."""
    state = NetworkState("testnet", "1.0.0", "commit123", True)
    assert state.network == "testnet"
    assert state.version == "1.0.0"
    assert state.commit == "commit123"
    assert state.is_test_net is True


def test_network_config_request():
    """Test NetworkConfigRequest class."""
    request = NetworkConfigRequest("testnet", sign=True)
    assert request.network == "testnet"
    assert request.sign is True


def test_network_config_response():
    """Test NetworkConfigResponse class."""
    state = NetworkState("testnet", "1.0.0", "commit123", True)
    response = NetworkConfigResponse(state, "signature123")
    assert response.network_state == state
    assert response.signature == "signature123"


def test_partition_list():
    """Test PartitionList class."""
    partitions = PartitionList(["partition1", "partition2"])
    assert partitions.partitions == ["partition1", "partition2"]


def test_partition_list_response():
    """Test PartitionListResponse class."""
    response = PartitionListResponse(["partition1"], "signature123")
    assert response.partitions == ["partition1"]
    assert response.signature == "signature123"


def test_seed_list():
    """Test SeedList class."""
    seed_list = SeedList(8080, "type1", ["address1", "address2"])
    assert seed_list.base_port == 8080
    assert seed_list.type == "type1"
    assert seed_list.addresses == ["address1", "address2"]


def test_seed_list_response():
    """Test SeedListResponse class."""
    seed_list = SeedList(8080, "type1", ["address1", "address2"])
    response = SeedListResponse(seed_list, "signature123")
    assert response.seed_list == seed_list
    assert response.signature == "signature123"


def test_message_type_enum():
    """Test MessageType enum."""
    assert MessageType.TRANSACTION.value == "transaction"
    assert MessageType.SIGNATURE.value == "signature"


def test_message():
    """Test Message class."""
    msg = Message(1, "status", {"key": "value"})
    expected_hash = hashlib.sha256(json.dumps(msg.__dict__).encode()).hexdigest()
    assert msg.get_hash() == expected_hash


def test_transaction_message():
    """Test TransactionMessage class."""
    msg = TransactionMessage(1, {"id": "tx1"})
    assert msg.get_id() == "tx1"


def test_signature_message():
    """Test SignatureMessage class."""
    msg = SignatureMessage(1, {"signature": "sig1"})
    assert msg.get_signature() == "sig1"


def test_serialize_deserialize():
    """Test serialize and deserialize helpers."""
    obj = {"key": "value"}
    serialized = serialize(obj)
    deserialized = deserialize(serialized, dict)
    assert deserialized == obj
