# accumulate-python-client\accumulate\models\service.py

from dataclasses import dataclass
from typing import List, Optional
from datetime import timedelta


@dataclass
class ServiceAddress:
    """
    Represents a service address with type and argument.
    """
    service_type: int  # Type of the service, represented as an integer
    argument: Optional[str] = None  # Optional argument for the service

    @property
    def type(self) -> int:
        """Alias for service_type."""
        return self.service_type

    def __str__(self) -> str:
        """
        Returns {type}:{argument}, or {type} if the argument is empty.
        """
        base = hex(self.service_type)[2:] if isinstance(self.service_type, int) else str(self.service_type)
        return f"{base}:{self.argument}" if self.argument else base

    def to_dict(self) -> dict:
        """
        Converts the object to a dictionary.
        """
        return {"type": self.service_type, "argument": self.argument}

    @staticmethod
    def from_dict(data: dict) -> "ServiceAddress":
        """
        Creates a ServiceAddress from a dictionary.
        """
        return ServiceAddress(data["type"], data.get("argument"))

    @staticmethod
    def parse_service_address(address: str) -> "ServiceAddress":
        """
        Parses a string into a ServiceAddress.

        :param address: A string representing the service address in the format {type}:{argument}.
        :return: A ServiceAddress instance.
        :raises ValueError: If the format is invalid.
        """
        if not address or ":" not in address:
            raise ValueError("Invalid service address: Missing ':' separator or empty string")

        parts = address.split(":", maxsplit=1)
        if len(parts) < 2 or not parts[0] or not parts[1]:
            raise ValueError("Invalid service address: Missing type or argument")

        service_type = int(parts[0], 16) if parts[0].startswith("0x") else int(parts[0])
        return ServiceAddress(service_type=service_type, argument=parts[1])

    @staticmethod
    def unpack_address(address: str) -> dict:
        """
        Simulates unpacking of an address string for its components.

        :param address: A string representing the service address.
        :return: A dictionary containing type and argument of the service address.
        :raises ValueError: If the address cannot be parsed.
        """
        try:
            service_address = ServiceAddress.parse_service_address(address)
            return {
                "type": service_address.type,
                "argument": service_address.argument,
            }
        except Exception as e:
            raise ValueError(f"Failed to parse address: {e}")



@dataclass
class FindServiceOptions:
    """
    Represents options for finding a service in the Accumulate network.
    """
    network: str  # network name
    service: Optional[ServiceAddress] = None  # service address to search for
    known: Optional[bool] = None  # Restrict results to known peers
    timeout: Optional[timedelta] = None  #  timeout for querying the DHT

    def to_dict(self) -> dict:
        """
        Serialize a FindServiceOptions object into a dictionary.
        Removes `timeout` if it is None to prevent JSON-RPC errors.
        """
        params = {
            "network": self.network,
            "service": self.service.to_dict() if self.service else None,
            "known": self.known,
        }

        # Only include timeout if it is set
        if self.timeout is not None:
            params["timeout"] = self.timeout.total_seconds()

        return params


    @classmethod
    def from_dict(cls, data: dict) -> "FindServiceOptions":
        """
        Deserialize a dictionary into a FindServiceOptions object.
        """
        return cls(
            network=data.get("network", ""),
            service=ServiceAddress.from_dict(data["service"]) if "service" in data else None,
            known=data.get("known"),
            timeout=timedelta(seconds=data["timeout"]) if "timeout" in data else None,
        )


@dataclass
class FindServiceResult:
    """
    Represents the result of a service search in the Accumulate network.
    """
    peer_id: str  # unique ID of the peer providing the service
    status: str  # status of the known peer
    addresses: List[str]  # list of addresses associated with the service

    def to_dict(self) -> dict:
        """
        Serialize a FindServiceResult object into a dictionary.
        """
        return {
            "peer_id": self.peer_id,
            "status": self.status,
            "addresses": self.addresses,
        }

    @classmethod
    def from_dict(cls, data: dict) -> "FindServiceResult":
        """
        Deserialize a dictionary into a FindServiceResult object.
        """
        return cls(
            peer_id=data.get("peer_id", ""),
            status=data.get("status", ""),
            addresses=data.get("addresses", []),
        )
