# accumulate-python-client\accumulate\models\faucet.py

import hashlib
from datetime import datetime, timezone
from typing import Union
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from accumulate.models.signatures import ED25519Signature, LegacyED25519Signature, RCD1Signature, Signature
from accumulate.utils.hash_functions import LiteAuthorityForKey
from accumulate.models.signature_types import SignatureType


class Faucet:
    """Represents the Accumulate faucet account."""

    ACME_FAUCET_AMOUNT = 10
    ACME_FAUCET_BALANCE = 200_000_000

    # Generate the faucet key using a fixed seed
    FAUCET_SEED = hashlib.sha256(b"faucet").digest()
    FAUCET_KEY = Ed25519PrivateKey.from_private_bytes(FAUCET_SEED[:32])

    def __init__(self):
        """Initialize the Faucet."""
        self.faucet_url = self._generate_faucet_url()

    def _generate_faucet_url(self) -> str:
        """
        Generate the faucet URL using the public key.

        :return: A string representing the faucet URL.
        """
        public_key = self.public_key()
        return f"{LiteAuthorityForKey(public_key, SignatureType.ED25519)}/ACME"

    def public_key(self) -> bytes:
        """
        Get the public key of the faucet.

        :return: The public key as bytes.
        """
        return self.FAUCET_KEY.public_key().public_bytes(
            encoding=Encoding.PEM,  # Use PEM for portability
            format=PublicFormat.SubjectPublicKeyInfo  # Standard format for public keys
        )

    def signer(self) -> "FaucetSigner":
        """
        Create a new faucet signer with the current timestamp.

        :return: A FaucetSigner instance.
        """
        return FaucetSigner(int(datetime.now(timezone.utc).timestamp() * 1e9))


class FaucetSigner:
    """Handles signing for the faucet."""

    def __init__(self, timestamp: int):
        """
        Initialize the FaucetSigner.

        :param timestamp: The timestamp to use for signing.
        """
        self.timestamp = timestamp

    def version(self) -> int:
        """
        Get the version of the signer.

        :return: Version as an integer.
        """
        return 1

    def set_public_key(self, sig: Signature) -> None:
        """
        Set the public key for a given signature.

        :param sig: The signature object to update.
        :raises ValueError: If the signature type is unsupported.
        """
        if isinstance(sig, (LegacyED25519Signature, ED25519Signature, RCD1Signature)):
            sig.public_key = Faucet.FAUCET_KEY.public_key().public_bytes(
                encoding=Encoding.PEM,
                format=PublicFormat.SubjectPublicKeyInfo
            )
        else:
            raise ValueError(f"Cannot set the public key on {type(sig).__name__}")

    def sign(self, sig: Signature, sig_md_hash: bytes, message: bytes) -> None:
        """
        Sign the message with the faucet key.

        :param sig: The signature object to update.
        :param sig_md_hash: The metadata hash for the signature.
        :param message: The message to sign.
        :raises ValueError: If the signature type is unsupported.
        """
        if isinstance(sig, (LegacyED25519Signature, ED25519Signature, RCD1Signature)):
            signature = Faucet.FAUCET_KEY.sign(message)
            sig.signature = signature
        else:
            raise ValueError(f"Cannot sign {type(sig).__name__} with a key.")
