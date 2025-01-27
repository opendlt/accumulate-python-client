# accumulate-python-client\accumulate\models\types.py 

from datetime import datetime, timedelta, timezone
from typing import List, Optional, Dict, Any
import json
import hashlib
from enum import Enum


# ========================== Helper Classes ==========================
class AtomicUint:
    """Thread-safe atomic counter."""
    def __init__(self, value: int = 0):
        self.value = value

    def increment(self):
        self.value += 1

    def store(self, value: int):
        self.value = value

    def load(self) -> int:
        return self.value


class AtomicSlice:
    """Thread-safe list management."""
    def __init__(self):
        self.items = []

    def add(self, item: Any):
        self.items.append(item)

    def compare(self, other: List[Any]) -> bool:
        """Compare the items with another list."""
        return self.items == other
    

# ========================== Core Models ==========================
from datetime import datetime, timezone

class LastStatus:
    def __init__(self):
        self.success: Optional[datetime] = None
        self.attempt: Optional[datetime] = None
        self.failed = AtomicUint()

    def did_attempt(self):
        self.attempt = datetime.now(timezone.utc)

    def did_succeed(self):
        self.success = datetime.now(timezone.utc)
        self.failed.store(0)

    def since_attempt(self) -> timedelta:
        if not self.attempt:
            return timedelta.max
        return datetime.now(timezone.utc) - self.attempt

    def since_success(self) -> timedelta:
        if not self.success:
            return timedelta.max
        return datetime.now(timezone.utc) - self.success



class PeerAddressStatus:
    def __init__(self, address: str):
        self.address = address
        self.last = LastStatus()

    def compare(self, other):
        return self.address.lower() == other.address.lower()


class PeerServiceStatus:
    def __init__(self, address: str):
        self.address = address
        self.last = LastStatus()

    def compare(self, other):
        return self.address.lower() == other.address.lower()


class PeerNetworkStatus:
    def __init__(self, name: str):
        self.name = name
        self.services = AtomicSlice()

    def compare(self, other):
        return self.name.lower() == other.name.lower()


class PeerStatus:
    def __init__(self, peer_id: str):
        self.id = peer_id
        self.addresses = AtomicSlice()
        self.networks = AtomicSlice()

    def compare(self, other):
        return self.id == other.id

    def unmarshal_json(self, data: str):
        json_data = json.loads(data)
        self.id = json_data.get("ID")
        self.addresses = AtomicSlice()
        self.networks = AtomicSlice()


# ========================== API Types ==========================
class NetworkState:
    def __init__(self, network: str, version: str, commit: str, is_test_net: bool):
        self.network = network
        self.version = version
        self.commit = commit
        self.version_is_known = True
        self.is_test_net = is_test_net


class NetworkConfigRequest:
    def __init__(self, network: str, sign: bool = False):
        self.network = network
        self.sign = sign


class NetworkConfigResponse:
    def __init__(self, network_state: NetworkState, signature: Optional[str] = None):
        self.network_state = network_state
        self.signature = signature


class PartitionList:
    def __init__(self, partitions: List[str]):
        self.partitions = partitions


class PartitionListResponse:
    def __init__(self, partitions: List[str], signature: Optional[str] = None):
        self.partitions = partitions
        self.signature = signature


class SeedList:
    def __init__(self, base_port: int, seed_type: str, addresses: List[str]):
        self.base_port = base_port
        self.type = seed_type
        self.addresses = addresses


class SeedListResponse:
    def __init__(self, seed_list: SeedList, signature: Optional[str] = None):
        self.seed_list = seed_list
        self.signature = signature


# ========================== Message Models ==========================
class MessageType(Enum):
    TRANSACTION = "transaction"
    SIGNATURE = "signature"
    BLOCK_ANCHOR = "block_anchor"
    NETWORK_UPDATE = "network_update"


class Message:
    def __init__(self, msg_id: int, status: str, content: Optional[Dict] = None):
        self.msg_id = msg_id
        self.status = status
        self.content = content

    def get_hash(self) -> str:
        return hashlib.sha256(json.dumps(self.__dict__).encode()).hexdigest()


class TransactionMessage(Message):
    def __init__(self, msg_id: int, transaction: Dict):
        super().__init__(msg_id, "transaction", transaction)

    def get_id(self):
        return self.content.get("id")


class SignatureMessage(Message):
    def __init__(self, msg_id: int, signature: Dict):
        super().__init__(msg_id, "signature", signature)

    def get_signature(self):
        return self.content.get("signature")


# ========================== Serialization Helpers ==========================
def serialize(obj) -> str:
    return json.dumps(obj, default=lambda o: o.__dict__)


def deserialize(data: str, cls):
    return cls(**json.loads(data))

