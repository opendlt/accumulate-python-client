# accumulate-python-client\accumulate\models\node_info.py

from dataclasses import dataclass, field
from typing import List, Optional
from accumulate.models.service import ServiceAddress


@dataclass
class NodeInfo:
    """
    Represents information about a network node.
    """
    peer_id: str  # Equivalent to PeerID in Go, representing the node's unique ID
    network: str  # The name of the network (e.g., "mainnet" or "testnet")
    services: List[ServiceAddress]  # The services the node provides
    version: str  # The software version of the node
    commit: str  # The commit hash of the software version

    @classmethod
    def from_dict(cls, data: dict) -> "NodeInfo":
        """
        Deserialize a dictionary into a NodeInfo object.
        """
        return cls(
            peer_id=data.get("peer_id", ""),
            network=data.get("network", ""),
            services=[ServiceAddress.from_dict(svc) for svc in data.get("services", [])],
            version=data.get("version", ""),
            commit=data.get("commit", ""),
        )

    def to_dict(self) -> dict:
        """
        Serialize a NodeInfo object into a dictionary.
        """
        return {
            "peer_id": self.peer_id,
            "network": self.network,
            "services": [service.to_dict() for service in self.services],
            "version": self.version,
            "commit": self.commit,
        }
