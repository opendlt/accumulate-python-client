# accumulate-python-client\accumulate\utils\eip712.py

import hashlib
import json
import struct
from typing import Any, Dict, List, Optional, Union
from eth_utils import keccak
from eth_typing import HexStr

class TypeField:
    def __init__(self, name: str, typ: str):
        self.name = name
        self.type = typ


class TypeDefinition:
    def __init__(self, name: str, fields: List[TypeField]):
        self.name = name
        self.fields = fields

    def resolve(self, data: Dict[str, Any]) -> "ResolvedStruct":
        resolved_fields = {}
        for field in self.fields:
            value = data.get(field.name)
            if value is None:
                raise ValueError(f"Missing required field: {field.name}")
            resolved_fields[field.name] = ResolvedValue(field.type, value)
        return ResolvedStruct(self.name, resolved_fields)


class ResolvedStruct:
    def __init__(self, type_name: str, fields: Dict[str, "ResolvedValue"]):
        self.type_name = type_name
        self.fields = fields

    def hash(self, types: Dict[str, List[TypeField]]) -> bytes:
        # Generate the hash of the struct using EIP-712 hashing rules
        type_hash = keccak(self.encode_type(types))
        field_hashes = b"".join(
            field.hash(types) for field in self.fields.values()
        )
        return keccak(type_hash + field_hashes)

    def encode_type(self, types: Dict[str, List[TypeField]]) -> bytes:
        # Encode the type structure as a string
        encoded = f"{self.type_name}("
        encoded += ",".join(
            f"{field.type} {field.name}" for field in types[self.type_name]
        )
        encoded += ")"
        return encoded.encode()


class ResolvedValue:
    def __init__(self, eth_type: str, value: Any):
        self.eth_type = eth_type
        self.value = value

    def hash(self, types: Dict[str, List[TypeField]]) -> bytes:
        if self.eth_type == "string":
            return keccak(self.value.encode())
        elif self.eth_type == "uint256":
            return self._uint256_to_bytes(self.value)
        elif self.eth_type == "address":
            return self._address_to_bytes(self.value)
        elif self.eth_type == "bytes32":
            return self._bytes32_to_bytes(self.value)
        else:
            raise ValueError(f"Unsupported EIP-712 type: {self.eth_type}")

    def _uint256_to_bytes(self, value: int) -> bytes:
        return value.to_bytes(32, "big")

    def _address_to_bytes(self, address: str) -> bytes:
        # Remove 0x prefix and pad to 32 bytes
        address = address[2:] if address.startswith("0x") else address
        return bytes.fromhex(address).rjust(32, b"\x00")

    def _bytes32_to_bytes(self, value: HexStr) -> bytes:
        value = value[2:] if value.startswith("0x") else value
        return bytes.fromhex(value).ljust(32, b"\x00")


class EIP712Domain:
    def __init__(self, name: str, version: str, chain_id: int):
        self.name = name
        self.version = version
        self.chain_id = chain_id

    def hash(self) -> bytes:
        # Hash the EIP-712 domain structure
        type_hash = keccak(b"EIP712Domain(string name,string version,uint256 chainId)")
        name_hash = keccak(self.name.encode())
        version_hash = keccak(self.version.encode())
        chain_id_bytes = self.chain_id.to_bytes(32, "big")
        return keccak(type_hash + name_hash + version_hash + chain_id_bytes)


class AccumulateEIP712Domain(EIP712Domain):
    @classmethod
    def from_network(cls, network_name: str) -> "AccumulateEIP712Domain":
        chain_id = eth_chain_id(network_name)
        return cls(name=network_name, version="1", chain_id=chain_id)


class EIP712Message:
    def __init__(self, domain: EIP712Domain, message: ResolvedStruct, types: Dict[str, List[TypeField]]):
        self.domain = domain
        self.message = message
        self.types = types

    def hash(self) -> bytes:
        domain_hash = self.domain.hash()
        message_hash = self.message.hash(self.types)
        return keccak(b"\x19\x01" + domain_hash + message_hash)


def create_eip712_message(
    domain_data: Dict[str, Any],
    message_data: Dict[str, Any],
    type_definitions: Dict[str, List[TypeField]],
) -> EIP712Message:
    domain = EIP712Domain(
        name=domain_data["name"],
        version=domain_data["version"],
        chain_id=domain_data["chainId"],
    )
    message_type = type_definitions["Transaction"]
    resolved_message = TypeDefinition("Transaction", message_type).resolve(
        message_data
    )
    return EIP712Message(domain, resolved_message, type_definitions)


def eth_chain_id(network_name: str) -> int:
    """
    Returns the Ethereum chain ID for an Accumulate network name

    :param network_name: The name of the network (e.g., "mainnet")
    :return: The Ethereum chain ID
    """
    if network_name.lower() == "mainnet":
        return 281  # 0x119

    network_name = network_name.lower()
    network_hash = hashlib.sha256(network_name.encode()).digest()
    network_id = int.from_bytes(network_hash[-2:], "big")
    return 281 | (network_id << 16)


def marshal_eip712(transaction: Dict[str, Any], signature: Dict[str, Any]) -> Dict[str, Any]:
    """
    Creates the EIP-712 JSON message for a transaction and signature

    :param transaction: The transaction object
    :param signature: The signature object
    :return: Serialized EIP-712 JSON message
    """
    serialized_tx = {
        "header": transaction.get("header", {}),
        "signature": signature.get("metadata", {}),
    }

    body = transaction.get("body", {})
    body_type = transaction.get("type")
    if body and body_type:
        serialized_tx[body_type] = body

    return serialized_tx


def hash_eip712(transaction: Dict[str, Any], signature: Dict[str, Any]) -> bytes:
    """
    Hashes an EIP-712 transaction and signature

    :param transaction: The transaction object
    :param signature: The signature object
    :return: SHA-256 hash of the EIP-712 message
    """
    eip712_message = marshal_eip712(transaction, signature)
    eip712_json = json.dumps(eip712_message, separators=(',', ':')).encode()
    return hashlib.sha256(eip712_json).digest()
