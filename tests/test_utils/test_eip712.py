# accumulate-python-client\tests\test_utils\test_eip712.pyimport pytest

import pytest
from eth_utils import keccak
from accumulate.utils.eip712 import (
    TypeField, TypeDefinition, ResolvedStruct, ResolvedValue, EIP712Domain,
    AccumulateEIP712Domain, EIP712Message, create_eip712_message, eth_chain_id,
    marshal_eip712, hash_eip712
)

# Test TypeField
def test_type_field():
    field = TypeField(name="test_field", typ="uint256")
    assert field.name == "test_field"
    assert field.type == "uint256"

# Test TypeDefinition
def test_type_definition():
    fields = [TypeField(name="test_field", typ="uint256")]
    type_def = TypeDefinition(name="TestType", fields=fields)

    data = {"test_field": 42}
    resolved_struct = type_def.resolve(data)

    assert resolved_struct.type_name == "TestType"
    assert "test_field" in resolved_struct.fields
    assert resolved_struct.fields["test_field"].value == 42

    # Test missing required field
    with pytest.raises(ValueError, match="Missing required field: test_field"):
        type_def.resolve({})  # Missing required field

# Test ResolvedStruct
def test_resolved_struct():
    fields = [TypeField(name="test_field", typ="uint256")]
    types = {"TestType": fields}
    resolved_struct = ResolvedStruct(
        type_name="TestType",
        fields={"test_field": ResolvedValue("uint256", 42)}
    )

    assert resolved_struct.hash(types) is not None
    assert resolved_struct.encode_type(types) == b"TestType(uint256 test_field)"

# Test ResolvedValue
def test_resolved_value():
    value_uint256 = ResolvedValue("uint256", 42)
    assert value_uint256.hash({}) == b"\x00" * 31 + b"\x2a"

    value_address = ResolvedValue("address", "0x1234567890abcdef1234567890abcdef12345678")
    assert value_address.hash({}).hex().endswith("1234567890abcdef1234567890abcdef12345678")

    value_bytes32 = ResolvedValue("bytes32", "0xabcdef" + "0" * 58)
    assert value_bytes32.hash({}) == bytes.fromhex("abcdef" + "00" * 29)

    # Test unsupported type
    with pytest.raises(ValueError, match="Unsupported EIP-712 type: unsupported_type"):
        ResolvedValue("unsupported_type", "value").hash({})

# Test EIP712Domain
def test_eip712_domain():
    domain = EIP712Domain(name="Accumulate", version="1", chain_id=281)
    assert domain.hash() is not None

# Test AccumulateEIP712Domain
def test_accumulate_eip712_domain():
    domain = AccumulateEIP712Domain.from_network("mainnet")
    assert domain.name == "mainnet"
    assert domain.version == "1"
    assert domain.chain_id == 281

# Test EIP712Message
def test_eip712_message():
    domain = EIP712Domain(name="Accumulate", version="1", chain_id=281)
    fields = [TypeField(name="test_field", typ="uint256")]
    types = {"TestType": fields}
    message = ResolvedStruct(
        type_name="TestType",
        fields={"test_field": ResolvedValue("uint256", 42)}
    )

    eip712_message = EIP712Message(domain, message, types)
    assert eip712_message.hash() is not None

# Test create_eip712_message
def test_create_eip712_message():
    domain_data = {"name": "Accumulate", "version": "1", "chainId": 281}
    message_data = {"test_field": 42}
    type_definitions = {
        "Transaction": [TypeField(name="test_field", typ="uint256")]
    }

    eip712_message = create_eip712_message(domain_data, message_data, type_definitions)
    assert eip712_message.domain.name == "Accumulate"
    assert eip712_message.message.type_name == "Transaction"

# Test eth_chain_id
def test_eth_chain_id():
    chain_id_mainnet = eth_chain_id("mainnet")
    assert chain_id_mainnet == 281

    chain_id_testnet = eth_chain_id("testnet")
    assert chain_id_testnet != 281  # Ensure different hash

# Test marshal_eip712
def test_marshal_eip712():
    transaction = {
        "header": {"nonce": 1},
        "body": {"to": "0x123", "amount": 100},
        "type": "Transfer"
    }
    signature = {"metadata": {"sig_type": "ecdsa"}}
    eip712_json = marshal_eip712(transaction, signature)

    assert "header" in eip712_json
    assert eip712_json["header"]["nonce"] == 1
    assert eip712_json["Transfer"]["to"] == "0x123"

# Test hash_eip712
def test_hash_eip712():
    transaction = {
        "header": {"nonce": 1},
        "body": {"to": "0x123", "amount": 100},
        "type": "Transfer"
    }
    signature = {"metadata": {"sig_type": "ecdsa"}}
    hashed = hash_eip712(transaction, signature)

    assert isinstance(hashed, bytes)
    assert len(hashed) == 32
