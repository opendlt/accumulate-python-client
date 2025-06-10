# accumulate-python-client\tests\test_signing\test_signer.py 
import json
from types import SimpleNamespace
import pytest
import hashlib
from unittest.mock import Mock, AsyncMock
from cryptography.hazmat.primitives.serialization import load_pem_private_key
from accumulate.signing.signer import Signer, MetadataEncodingError
from accumulate.models.signature_types import SignatureType
from accumulate.utils.url import URL
from eth_keys import keys as eth_keys
from eth_keys.exceptions import BadSignature
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa, ec, ed25519
from cryptography.hazmat.primitives.asymmetric.ec import derive_private_key, SECP256K1
from cryptography.hazmat.primitives.asymmetric.padding import PKCS1v15



# helper for a 32‐byte ed25519 private scalar
def _random_scalar():
    return b"\x01" * 32

# Helper functions to generate keys
def generate_ed25519_keys():
    private_key = ed25519.Ed25519PrivateKey.generate()
    public_key = private_key.public_key()
    private_bytes = private_key.private_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PrivateFormat.Raw,
        encryption_algorithm=serialization.NoEncryption(),
    )
    public_bytes = public_key.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    return private_bytes, public_bytes

def generate_eth_keys():
    private_key = eth_keys.PrivateKey(hashlib.sha256(b"test_key").digest())
    return private_key.to_bytes(), private_key.public_key.to_bytes()

@pytest.fixture
def signer():
    """Fixture to provide a fresh Signer instance for each test."""
    return Signer()

def test_set_public_key_ed25519(signer):
    private_key, _ = generate_ed25519_keys()
    signature = {"type": SignatureType.ED25519}
    signer.set_public_key(signature, private_key)
    # Expect the key to be stored under "publicKey"
    assert "publicKey" in signature

def test_set_public_key_eth(signer):
    """Test setting public key for Ethereum."""
    private_key, _ = generate_eth_keys()
    signature = {"type": SignatureType.ETH}
    signer.set_public_key(signature, private_key)
    # Assert the ETH address is included
    assert "eth_address" in signature
    assert isinstance(signature["eth_address"], str)

def test_set_public_key_unsupported(signer):
    private_key = b"\x00" * 32
    signature = {"type": SignatureType.UNKNOWN}
    with pytest.raises(ValueError, match="Cannot set the public key for"):
        signer.set_public_key(signature, private_key)

@pytest.mark.asyncio
async def test_sign_transaction_ed25519(signer):
    private_key, _ = generate_ed25519_keys()
    message = b"Test message"
    txn_header = Mock()
    txn_header.timestamp = 1234567890
    # Set keys normally (ED25519)
    signer.set_keys(private_key)
    signature = await signer.sign_transaction(SignatureType.ED25519, message, txn_header)
    assert "signature" in signature

@pytest.mark.asyncio
async def test_sign_transaction_eth(signer):
    # For ETH, override get_private_key and get_public_key to bypass ed25519 conversion.
    private_key, public_key = generate_eth_keys()
    signer.get_private_key = lambda: private_key
    signer.get_public_key = lambda: public_key
    # Also, manually set the internal key state so that checks pass.
    signer._private_key = private_key  
    signer._public_key = public_key
    message = b"Test message"
    txn_header = Mock()
    txn_header.timestamp = 1234567890
    signature = await signer.sign_transaction(SignatureType.ETH, message, txn_header)
    assert "signature" in signature
    # The returned dictionary should include common keys.
    assert "publicKey" in signature
    assert "signer" in signature

@pytest.mark.asyncio
async def test_sign_transaction_unsupported(signer):
    # Set dummy keys so that we pass the key-check.
    dummy_key, _ = generate_ed25519_keys()
    signer.set_keys(dummy_key)
    message = b"Test message"
    txn_header = Mock()
    txn_header.timestamp = 1234567890
    with pytest.raises(ValueError, match="Unsupported signature type: SignatureType.UNKNOWN"):
        await signer.sign_transaction(SignatureType.UNKNOWN, message, txn_header)

def test_sign_rcd1(signer):
    private_key, _ = generate_ed25519_keys()
    message = b"Test RCD1 message"
    signature = signer.sign_rcd1(private_key, message)
    assert "signature" in signature

def test_verify_rcd1_valid(signer):
    private_key, public_key = generate_ed25519_keys()
    message = b"Test RCD1 message"
    signature_hex = signer.sign_rcd1(private_key, message)["signature"]
    signature_bytes = bytes.fromhex(signature_hex)
    assert signer.verify_rcd1(public_key, signature_bytes, message) is True

def test_verify_rcd1_invalid(signer):
    private_key, public_key = generate_ed25519_keys()
    message = b"Test RCD1 message"
    signature = b"\x00" * 64
    assert signer.verify_rcd1(public_key, signature, message) is False

def test_sha256_concat(signer):
    data1 = b"Test data 1"
    data2 = b"Test data 2"
    result = signer.sha256_concat(data1, data2)
    assert isinstance(result, bytes)
    assert result == hashlib.sha256(data1 + data2).digest()

def test_calculate_metadata_hash(signer):
    public_key = b"\x01" * 32
    timestamp = 1234567890
    signer_url = "acc://example.acme"
    version = 1
    metadata_hash = signer.calculate_metadata_hash(public_key, timestamp, signer_url, version, SignatureType.ED25519.value)
    assert isinstance(metadata_hash, bytes)

def test_calculate_signature_hash(signer):
    signature = Mock()
    signature.marshal_binary = Mock(return_value=b"Test signature data")
    result = signer.calculate_signature_hash(signature)
    assert isinstance(result, bytes)
    assert result == hashlib.sha256(b"Test signature data").digest()

def test_set_public_key_btclegacy():
    """Test setting public key for BTCLegacy signature type should raise an error."""
    signer_instance = Signer()
    signature = {"type": SignatureType.BTC_LEGACY}
    private_key = b"\x01" * 32
    with pytest.raises(ValueError, match="Cannot set the public key for SignatureType.BTC_LEGACY"):
        signer_instance.set_public_key(signature, private_key)

def test_set_public_key_rsa_sha256():
    """Test setting public key for RSA_SHA256 signature type."""
    signer_instance = Signer()
    signature = {"type": SignatureType.RSA_SHA256}
    private_key_obj = rsa.generate_private_key(
        public_exponent=65537, key_size=2048, backend=default_backend()
    )
    private_key = private_key_obj.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    signer_instance.set_public_key(signature, private_key)
    assert "publicKey" in signature
    assert isinstance(signature["publicKey"], str)
    pem_bytes = bytes.fromhex(signature["publicKey"])
    assert b"BEGIN PUBLIC KEY" in pem_bytes

def test_set_public_key_ecdsa_sha256():
    """Test setting public key for ECDSA_SHA256 signature type."""
    signer_instance = Signer()
    signature = {"type": SignatureType.ECDSA_SHA256}
    private_key = b"\x01" * 32  # Mock 256-bit private key
    signer_instance.set_public_key(signature, private_key)
    assert "publicKey" in signature
    assert isinstance(signature["publicKey"], str)
    pem_bytes = bytes.fromhex(signature["publicKey"])
    assert b"BEGIN PUBLIC KEY" in pem_bytes

@pytest.mark.asyncio
async def test_sign_transaction_btc():
    """Test signing a transaction with BTC signature type."""
    signer_instance = Signer()
    dummy_key = b"\x01" * 32
    # Set keys normally for BTC.
    signer_instance.set_keys(dummy_key)
    message = b"test_message"
    txn_header = Mock()
    txn_header.timestamp = 1234567890
    result = await signer_instance.sign_transaction(SignatureType.BTC, dummy_key, txn_header)
    assert "signature" in result

@pytest.mark.asyncio
async def test_sign_transaction_rsa_sha256():
    """Test signing a transaction with RSA_SHA256 signature type."""
    signer_instance = Signer()
    private_key_obj = rsa.generate_private_key(
        public_exponent=65537, key_size=2048, backend=default_backend()
    )
    private_key = private_key_obj.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    # Override get_private_key to return our RSA PEM.
    signer_instance.get_private_key = lambda: private_key
    # Manually set _private_key and _public_key using the RSA key.
    rsa_public = private_key_obj.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    signer_instance._private_key = True  # Dummy truthy value to pass the check
    signer_instance._public_key = rsa_public
    message = b"test_message"
    txn_header = Mock()
    txn_header.timestamp = 1234567890
    result = await signer_instance.sign_transaction(SignatureType.RSA_SHA256, message, txn_header)
    assert "signature" in result
    # Expect the RSA signature to be returned as a hex string.
    assert isinstance(result["signature"], str)

@pytest.mark.asyncio
async def test_sign_transaction_ecdsa_sha256():
    """Test signing a transaction with ECDSA_SHA256 signature type."""
    signer_instance = Signer()
    dummy_key = b"\x01" * 32
    signer_instance.set_keys(dummy_key)
    signer_instance.get_private_key = lambda: dummy_key
    message = b"test_message"
    txn_header = Mock()
    txn_header.timestamp = 1234567890
    result = await signer_instance.sign_transaction(SignatureType.ECDSA_SHA256, dummy_key, txn_header)
    assert "signature" in result

def test_btc_address():
    """Test calculating a BTC address from the public key."""
    from accumulate.utils.hash_functions import btc_address
    public_key = b"\x02" * 33  # Mock compressed public key
    result = btc_address(public_key)
    assert isinstance(result, str)

def test_eth_address():
    """Test calculating an ETH address from the public key."""
    from accumulate.utils.hash_functions import eth_address
    public_key = b"\x04" * 65
    result = eth_address(public_key)
    assert isinstance(result, str)

@pytest.mark.asyncio
async def test_select_signer_known_and_unknown(monkeypatch):
     dummy_key = _random_scalar()
     fake_client = object()
     # first, known type
     async def fake_process(url, client):
         return {"url": "acc://foo.acme", "signer_type": "ED25519", "signer_version": 7}
     monkeypatch.setattr(
         "accumulate.utils.validation.process_signer_url",
         fake_process,
     )
     signer = await Signer.select_signer(URL.parse("acc://foo.acme"), dummy_key, client=fake_client)
     assert signer.url.authority == "acc://foo.acme"
     assert signer._signer_version == 7
     assert signer._signature_type == SignatureType.ED25519

     # now unknown type falls back to ED25519
     async def fake_process2(url, client):
         return {"url": "acc://bar.acme", "signer_type": "NO_SUCH", "signer_version": 3}
     monkeypatch.setattr(
        "accumulate.utils.validation.process_signer_url",
        fake_process2,
    )
     signer2 = await Signer.select_signer(URL.parse("acc://bar.acme"), dummy_key, client=fake_client)
     assert signer2.url.authority == "acc://bar.acme"
     assert signer2._signer_version == 3
     assert signer2._signature_type == SignatureType.ED25519

def test_set_keys_mismatch_64_bytes():
    # derive_public from scalar won't match the dummy half
    bad = b"\x02" * 32 + b"\x03" * 32
    s = Signer()
    with pytest.raises(ValueError, match="Derived public key does not match computed public key"):
        s.set_keys(bad)


def test_get_public_and_private_key_branches():
    s = Signer()
    # no keys at all
    with pytest.raises(ValueError, match="Public key has not been set"):
        s.get_public_key()
    with pytest.raises(ValueError, match="Private key has not been set"):
        s.get_private_key()
    # only private set
    s._private_key = ed25519.Ed25519PrivateKey.generate()
    # should regenerate public
    pub = s.get_public_key()
    assert isinstance(pub, bytes)
    # now private exists
    priv = s.get_private_key()
    assert isinstance(priv, bytes)


@pytest.mark.asyncio
async def test_get_signer_version_and_setter():
    s = Signer()
    with pytest.raises(ValueError, match="Signer URL is missing"):
        await s.get_signer_version()
    s.url = URL.parse("acc://x.acme")
    s._signer_version = 42
    assert (await s.get_signer_version()) == 42
    s.set_signer_version(17)
    assert s._signer_version == 17


@pytest.mark.asyncio
async def test_sign_transaction_errors_before_signing():
    s = Signer()
    hdr = SimpleNamespace(timestamp=1)
    # no keys
    with pytest.raises(ValueError, match="Private key not set"):
        await s.sign_transaction(SignatureType.ED25519, b"", hdr)
    # only private
    s._private_key = ed25519.Ed25519PrivateKey.generate()
    with pytest.raises(ValueError, match="Public key not set"):
        await s.sign_transaction(SignatureType.ED25519, b"", hdr)
    # proper public but no timestamp
    s._public_key = s._private_key.public_key().public_bytes(
        encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw
    )
    bad_hdr = SimpleNamespace(timestamp=None)
    with pytest.raises(ValueError, match="Transaction header does not have a timestamp"):
        await s.sign_transaction(SignatureType.ED25519, b"", bad_hdr)


@pytest.mark.asyncio
async def test_sign_transaction_all_algorithms(monkeypatch):
    # prepare a signer with ed25519 keys
    raw = b"\x01" * 32
    s = Signer()
    s.set_keys(raw)
    s.url = URL.parse("acc://z.acme")
    hdr = SimpleNamespace(timestamp=99)
    data = b"msg"
    # ED25519
    out = await s.sign_transaction(SignatureType.ED25519, data, hdr)
    assert out["type"] == "ed25519"
    # BTC
    out2 = await s.sign_transaction(SignatureType.BTC, data, hdr)
    assert out2["type"] == "btc"
    # ETH
    out3 = await s.sign_transaction(SignatureType.ETH, data, hdr)
    assert out3["type"] == "eth"

    # RSA
    rsa_priv = rsa.generate_private_key(public_exponent=65537, key_size=1024)
    pem = rsa_priv.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )
    s2 = Signer()
    # override the two getters so the branch loads our PEM
    s2.get_private_key = lambda: pem
    s2.get_public_key  = lambda: rsa_priv.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    # **also** satisfy the internal presence checks:
    s2._private_key = True
    s2._public_key = True

    out4 = await s2.sign_transaction(SignatureType.RSA_SHA256, data, hdr)
    assert out4["type"] == "rsa_sha256"

    # ECDSA
    out5 = await s.sign_transaction(SignatureType.ECDSA_SHA256, data, hdr)
    assert out5["type"] == "ecdsa_sha256"
    # unsupported
    with pytest.raises(ValueError, match="Unsupported signature type"):
        await s.sign_transaction(SignatureType.UNKNOWN, data, hdr)





@pytest.mark.asyncio
async def test_sign_and_submit_transaction_remote(monkeypatch):
    # 1) If body is not a RemoteTransaction, fall through to "Signer keys not set"
    txn0 = SimpleNamespace(
        body=object(),
        header=SimpleNamespace(timestamp=1),
        get_hash=lambda: b"\x00",
        to_dict=lambda: {"foo": 1}
    )
    s = Signer()
    with pytest.raises(ValueError, match="Signer keys not set"):
        await s.sign_and_submit_transaction(AsyncMock(), txn0, SignatureType.ED25519, debug=True)

    # 2) Patch the RemoteTransaction *inside* accumulate.signing.signer
    DummyRT = type("DummyRT", (), {"allows_multisig": lambda self: False})
    monkeypatch.setattr("accumulate.signing.signer.RemoteTransaction", DummyRT)

    txn1 = SimpleNamespace(
        body=DummyRT(),
        header=SimpleNamespace(timestamp=1),
        get_hash=lambda: b"\x00",
        to_dict=lambda: {"foo": 1}
    )
    s.set_keys(b"\x01" * 32)
    with pytest.raises(ValueError, match="does not allow multisignatures"):
        await s.sign_and_submit_transaction(AsyncMock(), txn1, SignatureType.ED25519, debug=True)

    # 3) Allowed multisig but already signed
    class Dummy2(DummyRT):
        allows_multisig = lambda self: True
        get_existing_signatures = lambda self: [s.get_public_key()]

    monkeypatch.setattr("accumulate.signing.signer.RemoteTransaction", Dummy2)

    txn2 = SimpleNamespace(
        body=Dummy2(),
        header=SimpleNamespace(timestamp=1),
        get_hash=lambda: b"\x00",
        to_dict=lambda: {"foo": 1}
    )
    with pytest.raises(ValueError, match="already signed"):
        await s.sign_and_submit_transaction(AsyncMock(), txn2, SignatureType.ED25519, debug=True)

    # 4) Allowed multisig, not yet signed → debug mode
    class Dummy3(DummyRT):
        allows_multisig = lambda self: True
        get_existing_signatures = lambda self: []

    monkeypatch.setattr("accumulate.signing.signer.RemoteTransaction", Dummy3)

    txn3 = SimpleNamespace(
        body=Dummy3(),
        header=SimpleNamespace(timestamp=2),
        get_hash=lambda: b"\xAB",
        to_dict=lambda: {"bar": 2}
    )
    s2 = Signer()
    s2.set_keys(b"\x02" * 32)
    s2.url = URL.parse("acc://d.acme")
    envelope = await s2.sign_and_submit_transaction(AsyncMock(), txn3, SignatureType.ED25519, debug=True)
    assert "signatures" in envelope and "transaction" in envelope

    # 5) Submit to fake client → OK
    fake_client = AsyncMock()
    fake_client.submit.return_value = {"ok": True}
    res = await s2.sign_and_submit_transaction(fake_client, txn3, SignatureType.ED25519, debug=False)
    assert res == {"ok": True}

    # 6) Submit → fails
    fake_client2 = AsyncMock()
    fake_client2.submit.side_effect = RuntimeError("boom")
    with pytest.raises(RuntimeError):
        await s2.sign_and_submit_transaction(fake_client2, txn3, SignatureType.ED25519, debug=False)


def test_for_lite_and_parents():
    s = Signer()
    with pytest.raises(ValueError, match="must have keys set"):
        Signer.for_lite(s)
    s.set_keys(_random_scalar())
    lite = Signer.for_lite(s)
    assert isinstance(lite.url, URL)
    # is_parent_of
    assert Signer.is_parent_of(URL.parse("acc://foo"), URL.parse("acc://foo/bar"))
    assert not Signer.is_parent_of(URL.parse("acc://foo"), URL.parse("acc://bar"))


def test_encode_varint_and_metadata_hash():
    # varint negative
    with pytest.raises(ValueError):
        Signer.encode_varint(-1)
    # multi‐byte varint
    b = Signer.encode_varint(300)
    assert b == bytes([0xAC, 0x02])
    # single byte
    assert Signer.encode_varint(5) == b"\x05"
    # metadata hash deterministic size
    h = Signer.calculate_metadata_hash(b"\x01\x02", 7, "acc://x", 1, 2)
    assert isinstance(h, bytes) and len(h) == 32


def test_calculate_signature_hash_and_sha256_concat():
    class Fake:
        def marshal_binary(self): return b"foo"
    sig = Fake()
    assert Signer.calculate_signature_hash(sig) == hashlib.sha256(b"foo").digest()
    assert Signer.sha256_concat(b"a", b"b") == hashlib.sha256(b"ab").digest()


@pytest.mark.asyncio
async def test_get_signature_type_cached_and_default():
    s = Signer()
    # No _signature_type set → should default to ED25519 and cache it
    assert s._signature_type is None
    st1 = await s.get_signature_type()
    assert st1 == SignatureType.ED25519
    assert s._signature_type == SignatureType.ED25519

    # If already cached, get_signature_type just returns it
    s._signature_type = SignatureType.BTC
    st2 = await s.get_signature_type()
    assert st2 == SignatureType.BTC

@pytest.mark.asyncio
async def test_sign_wrapper_calls_sign_transaction(monkeypatch):
    s = Signer()
    # Monkey-patch sign_transaction to just echo back its args
    dummy = {"ok": True}
    fake = AsyncMock(return_value=dummy)
    monkeypatch.setattr(s, "sign_transaction", fake)

    # 1) default opts → ED25519 and default signerVersion
    res1 = await s.sign(b"hello", {})
    fake.assert_awaited_once_with(SignatureType.ED25519, b"hello", s._signer_version)
    assert res1 == dummy

    fake.reset_mock()
    # 2) custom opts
    res2 = await s.sign(b"xyz", {"signatureType": SignatureType.RSA_SHA256, "signerVersion": 42})
    fake.assert_awaited_once_with(SignatureType.RSA_SHA256, b"xyz", 42)
    assert res2 == dummy

@pytest.mark.asyncio
async def test_sign_transaction_invalid_rsa_private_key():
    # Bypass the ed25519 guards
    s = Signer()
    s._private_key = True
    s._public_key = True
    hdr = SimpleNamespace(timestamp=123)

    # Override get_private_key to return an EC key instead of RSA
    ec_priv = ec.generate_private_key(ec.SECP256K1(), default_backend())
    pem_ec = ec_priv.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption()
    )
    s.get_private_key = lambda: pem_ec
    s.get_public_key = lambda: b"00"

    with pytest.raises(ValueError, match="Invalid RSA private key"):
        await s.sign_transaction(SignatureType.RSA_SHA256, b"data", hdr)

def test_set_public_key_btc_branch(signer):
    # Cover the BTC branch of set_public_key
    private_key = b"\x05" * 32
    signature = {"type": SignatureType.BTC}
    signer.set_public_key(signature, private_key)

    assert "publicKey" in signature
    assert "btc_address" in signature

    # The publicKey should decode to a compressed EC point (33 bytes)
    pk_bytes = bytes.fromhex(signature["publicKey"])
    assert len(pk_bytes) == 33
    # And btc_address should be a non-empty string
    assert isinstance(signature["btc_address"], str) and len(signature["btc_address"]) > 0