# C:\Accumulate_Stuff\accumulate-python-client\accumulate\models\signature_types.py

from enum import Enum


class SignatureType(Enum):
    """Cryptographic signature algorithms."""
    UNKNOWN = 0
    ED25519 = 1
    LEGACY_ED25519 = 2
    ECDSA_SHA256 = 3
    RSA_SHA256 = 4
    RCD1 = 5
    BTC = 6
    BTCLegacy = 7
    ETH = 8
    RECEIPT = 9
    PARTITION = 10
    REMOTE = 11
    DELEGATED = 12
    AUTHORITY = 13
    TYPED_DATA = 14

