# accumulate-python-client\tests\test_models\test_options.py

import unittest
from datetime import timedelta
from accumulate.models.options import (
   RangeOptions,
   SubmitOptions,
   ValidateOptions,
   FaucetOptions,
   SubscribeOptions,
   ReceiptOptions,
)
from accumulate.models.service import FindServiceOptions, FindServiceResult

class TestRangeOptions(unittest.TestCase):
    def test_default_values(self):
        """Test default values for RangeOptions."""
        options = RangeOptions()
        self.assertIsNone(options.start)
        self.assertIsNone(options.count)
        self.assertIsNone(options.expand)
        self.assertFalse(options.from_end)

    def test_custom_values(self):
        """Test custom values for RangeOptions."""
        options = RangeOptions(start=10, count=20, expand=True, from_end=True)
        self.assertEqual(options.start, 10)
        self.assertEqual(options.count, 20)
        self.assertTrue(options.expand)
        self.assertTrue(options.from_end)


class TestFindServiceOptions(unittest.TestCase):
    def test_required_field(self):
        """Test that the required field `network` is set correctly."""
        options = FindServiceOptions(network="mainnet")
        self.assertEqual(options.network, "mainnet")
        self.assertIsNone(options.service)
        self.assertIsNone(options.known)
        self.assertIsNone(options.timeout)

    def test_custom_values(self):
        from accumulate.models.service import ServiceAddress
        """Test custom values for FindServiceOptions."""
        options = FindServiceOptions(
            network="testnet",
            service=ServiceAddress(service_type=123, argument=None),
            known=True,
            timeout=timedelta(seconds=5.0),
        )
        self.assertEqual(options.network, "testnet")
        self.assertEqual(options.service.to_dict(), {"type": 123, "argument": None})
        self.assertTrue(options.known)
        self.assertEqual(options.timeout, timedelta(seconds=5.0))


class TestSubmitOptions(unittest.TestCase):
    def test_default_values(self):
        """Test default values for SubmitOptions."""
        options = SubmitOptions()
        self.assertTrue(options.verify)
        self.assertTrue(options.wait)

    def test_custom_values(self):
        """Test custom values for SubmitOptions."""
        options = SubmitOptions(verify=False, wait=False)
        self.assertFalse(options.verify)
        self.assertFalse(options.wait)


class TestValidateOptions(unittest.TestCase):
    def test_default_values(self):
        """Test default values for ValidateOptions."""
        options = ValidateOptions()
        self.assertTrue(options.full)

    def test_custom_values(self):
        """Test custom values for ValidateOptions."""
        options = ValidateOptions(full=False)
        self.assertFalse(options.full)


class TestFaucetOptions(unittest.TestCase):
    def test_default_values(self):
        """Test default values for FaucetOptions."""
        options = FaucetOptions()
        self.assertIsNone(options.token)

    def test_custom_values(self):
        """Test custom values for FaucetOptions."""
        options = FaucetOptions(token="acc://example.acme/token")
        self.assertEqual(options.token, "acc://example.acme/token")


class TestSubscribeOptions(unittest.TestCase):
    def test_default_values(self):
        """Test default values for SubscribeOptions."""
        options = SubscribeOptions()
        self.assertIsNone(options.partition)
        self.assertIsNone(options.account)

    def test_custom_values(self):
        """Test custom values for SubscribeOptions."""
        options = SubscribeOptions(partition="partition1", account="acc://example.acme/account")
        self.assertEqual(options.partition, "partition1")
        self.assertEqual(options.account, "acc://example.acme/account")


class TestReceiptOptions(unittest.TestCase):
    def test_default_values(self):
        """Test default values for ReceiptOptions."""
        options = ReceiptOptions()
        self.assertFalse(options.for_any)
        self.assertIsNone(options.for_height)

    def test_custom_values(self):
        """Test custom values for ReceiptOptions."""
        options = ReceiptOptions(for_any=True, for_height=100)
        self.assertTrue(options.for_any)
        self.assertEqual(options.for_height, 100)


if __name__ == "__main__":
    unittest.main()
