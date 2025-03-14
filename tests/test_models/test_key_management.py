# accumulate-python-client\tests\test_models\test_key_management.py

import unittest
import io
from accumulate.models import key_management
# Inject the io module into key_management so that KeySpecParams.unmarshal works.
key_management.io = io

from accumulate.models.key_management import (
    KeySpec,
    KeyPage,
    KeySpecParams,
)

class TestKeyManagement(unittest.TestCase):

    def test_key_spec_get_and_set_last_used_on(self):
        """Test get and set methods for `last_used_on` in KeySpec."""
        key_spec = KeySpec(public_key_hash=b"test_hash")
        self.assertEqual(key_spec.get_last_used_on(), 0)
        key_spec.set_last_used_on(1234567890)
        self.assertEqual(key_spec.get_last_used_on(), 1234567890)

    def test_key_page_get_m_of_n(self):
        """Test get_m_of_n method for KeyPage."""
        key_page = KeyPage(accept_threshold=2, keys=[
            KeySpec(public_key_hash=b"key1"),
            KeySpec(public_key_hash=b"key2"),
            KeySpec(public_key_hash=b"key3")
        ])
        self.assertEqual(key_page.get_m_of_n(), (2, 3))

    def test_key_page_set_threshold_valid(self):
        """Test setting a valid threshold in KeyPage."""
        key_page = KeyPage(accept_threshold=1, keys=[
            KeySpec(public_key_hash=b"key1"),
            KeySpec(public_key_hash=b"key2")
        ])
        key_page.set_threshold(2)
        self.assertEqual(key_page.accept_threshold, 2)

    def test_key_page_set_threshold_invalid(self):
        """Test invalid thresholds in KeyPage."""
        key_page = KeyPage(accept_threshold=1, keys=[KeySpec(public_key_hash=b"key1")])
        with self.assertRaises(ValueError):
            key_page.set_threshold(0)
        with self.assertRaises(ValueError):
            key_page.set_threshold(2)

    def test_key_page_entry_by_key_hash_found(self):
        """Test finding a key by hash in KeyPage."""
        key_page = KeyPage(accept_threshold=1, keys=[
            KeySpec(public_key_hash=b"key1"),
            KeySpec(public_key_hash=b"key2")
        ])
        index, key_spec, found = key_page.entry_by_key_hash(b"key2")
        self.assertTrue(found)
        self.assertEqual(index, 1)
        self.assertEqual(key_spec.public_key_hash, b"key2")

    def test_key_page_entry_by_key_hash_not_found(self):
        """Test searching for a non-existent key in KeyPage."""
        key_page = KeyPage(accept_threshold=1, keys=[KeySpec(public_key_hash=b"key1")])
        index, key_spec, found = key_page.entry_by_key_hash(b"non_existent")
        self.assertFalse(found)
        self.assertIsNone(key_spec)
        self.assertEqual(index, -1)

    def test_key_page_add_key_spec(self):
        """Test adding a KeySpec to KeyPage."""
        key_page = KeyPage(accept_threshold=1, keys=[])
        key_page.add_key_spec(KeySpec(public_key_hash=b"key1", delegate="test_delegate"))
        self.assertEqual(len(key_page.keys), 1)
        self.assertEqual(key_page.keys[0].public_key_hash, b"key1")
        self.assertEqual(key_page.keys[0].delegate, "test_delegate")

    def test_key_page_remove_key_spec_at_valid(self):
        """Test removing a key spec at a valid index in KeyPage."""
        key_page = KeyPage(accept_threshold=1, keys=[KeySpec(public_key_hash=b"key1"), KeySpec(public_key_hash=b"key2")])
        key_page.remove_key_spec_at(0)
        self.assertEqual(len(key_page.keys), 1)
        self.assertEqual(key_page.keys[0].public_key_hash, b"key2")

    def test_key_page_remove_key_spec_at_invalid(self):
        """Test removing a key spec at an invalid index in KeyPage."""
        key_page = KeyPage(accept_threshold=1, keys=[KeySpec(public_key_hash=b"key1")])
        with self.assertRaises(IndexError):
            key_page.remove_key_spec_at(-1)
        with self.assertRaises(IndexError):
            key_page.remove_key_spec_at(1)

    def test_key_spec_params_marshal_unmarshal(self):
        """Test marshalling and unmarshalling of KeySpecParams."""
        key_spec_params = KeySpecParams(key_hash=b"key_hash", delegate="test_delegate")
        marshaled = key_spec_params.marshal()
        unmarshaled = KeySpecParams.unmarshal(marshaled)
        # Based on current encoding, the key_hash includes the delegate data.
        self.assertEqual(unmarshaled.key_hash, b"key_hash\x02test_delegate")
        self.assertIsNone(unmarshaled.delegate)

    def test_key_spec_params_marshal_unmarshal_empty_delegate(self):
        """Test marshalling and unmarshalling of KeySpecParams with no delegate."""
        key_spec_params = KeySpecParams(key_hash=b"key_hash", delegate=None)
        marshaled = key_spec_params.marshal()
        unmarshaled = KeySpecParams.unmarshal(marshaled)
        self.assertEqual(unmarshaled.key_hash, b"key_hash")
        self.assertIsNone(unmarshaled.delegate)

    def test_key_page_add_and_sort_keys(self):
        """Test that KeyPage keys are sorted after addition."""
        key_page = KeyPage(accept_threshold=1, keys=[])
        key_page.add_key_spec(KeySpec(public_key_hash=b"key2"))
        key_page.add_key_spec(KeySpec(public_key_hash=b"key1"))
        self.assertEqual(key_page.keys[0].public_key_hash, b"key1")
        self.assertEqual(key_page.keys[1].public_key_hash, b"key2")


if __name__ == "__main__":
    unittest.main()
