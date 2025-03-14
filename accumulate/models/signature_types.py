# accumulate-python-client\accumulate\models\signature_types.py

from enum import Enum

class SignatureType(Enum):
    """Cryptographic signature algorithms using string identifiers."""
    UNKNOWN = 0x00
    LEGACY_ED25519 = 0x01
    ED25519 = 0x02
    RCD1 = 0x03
    RECEIPT = 0x04
    PARTITION = 0x05
    SET = 0x06
    REMOTE = 0x07
    BTC = 0x08
    BTC_LEGACY = 0x09
    ETH = 0x0A
    DELEGATED = 0x0B
    INTERNAL = 0x0C
    AUTHORITY = 0x0D
    RSA_SHA256 = 0x0E
    ECDSA_SHA256 = 0x0F
    TYPED_DATA = 0x10

    @classmethod
    def from_value(cls, value):
        """Retrieve an enum instance by its value."""
        for item in cls:
            if item.value == value:
                return item
        raise ValueError(f"Invalid SignatureType value: {value}")

    def to_rpc_format(self) -> str:
        """Convert SignatureType to the expected string format for JSON-RPC."""
        mapping = {
            SignatureType.UNKNOWN: "unknown",
            SignatureType.LEGACY_ED25519: "legacyEd25519",
            SignatureType.ED25519: "ed25519",
            SignatureType.RCD1: "rcd1",
            SignatureType.RECEIPT: "receipt",
            SignatureType.PARTITION: "partition",
            SignatureType.SET: "set",
            SignatureType.REMOTE: "remote",
            SignatureType.BTC: "btc",
            SignatureType.BTC_LEGACY: "btcLegacy",
            SignatureType.ETH: "eth",
            SignatureType.DELEGATED: "delegated",
            SignatureType.INTERNAL: "internal",
            SignatureType.AUTHORITY: "authority",
            SignatureType.RSA_SHA256: "rsaSha256",
            SignatureType.ECDSA_SHA256: "ecdsaSha256",
            SignatureType.TYPED_DATA: "typedData",
        }
        return mapping[self]
