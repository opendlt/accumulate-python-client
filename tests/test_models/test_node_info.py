# accumulate-python-client\tests\test_models\test_node_info.py

import unittest
from unittest.mock import patch, MagicMock
from accumulate.models.node_info import NodeInfo
from accumulate.models.service import ServiceAddress

class TestNodeInfo(unittest.TestCase):
    def setUp(self):
        """Set up mock data for NodeInfo tests."""
        self.mock_services = [
            MagicMock(ServiceAddress, to_dict=lambda: {"type": 1, "address": "service1"}),
            MagicMock(ServiceAddress, to_dict=lambda: {"type": 2, "address": "service2"}),
        ]
        self.mock_data = {
            "peer_id": "12345",
            "network": "testnet",
            "services": [{"type": 1, "address": "service1"}, {"type": 2, "address": "service2"}],
            "version": "1.0.0",
            "commit": "abc123",
        }

    def test_from_dict(self):
        """Test deserialization from a dictionary."""
        with patch("accumulate.models.service.ServiceAddress.from_dict") as mock_from_dict:
            mock_from_dict.side_effect = self.mock_services
            node_info = NodeInfo.from_dict(self.mock_data)

        self.assertEqual(node_info.peer_id, self.mock_data["peer_id"])
        self.assertEqual(node_info.network, self.mock_data["network"])
        self.assertEqual(node_info.version, self.mock_data["version"])
        self.assertEqual(node_info.commit, self.mock_data["commit"])
        self.assertEqual(len(node_info.services), len(self.mock_services))
        self.assertEqual(node_info.services[0].to_dict(), self.mock_data["services"][0])
        self.assertEqual(node_info.services[1].to_dict(), self.mock_data["services"][1])

    def test_to_dict(self):
        """Test serialization to a dictionary."""
        node_info = NodeInfo(
            peer_id="12345",
            network="testnet",
            services=self.mock_services,
            version="1.0.0",
            commit="abc123",
        )
        result = node_info.to_dict()

        self.assertEqual(result["peer_id"], "12345")
        self.assertEqual(result["network"], "testnet")
        self.assertEqual(result["version"], "1.0.0")
        self.assertEqual(result["commit"], "abc123")
        self.assertEqual(result["services"], [{"type": 1, "address": "service1"}, {"type": 2, "address": "service2"}])

    def test_empty_services(self):
        """Test NodeInfo with an empty services list."""
        data = {
            "peer_id": "67890",
            "network": "mainnet",
            "services": [],
            "version": "2.0.0",
            "commit": "def456",
        }
        node_info = NodeInfo.from_dict(data)
        self.assertEqual(node_info.peer_id, "67890")
        self.assertEqual(node_info.network, "mainnet")
        self.assertEqual(node_info.services, [])
        self.assertEqual(node_info.version, "2.0.0")
        self.assertEqual(node_info.commit, "def456")

    def test_invalid_service_data(self):
        """Test deserialization with invalid service data."""
        invalid_data = {
            "peer_id": "invalid_peer",
            "network": "invalid_net",
            "services": [{"invalid_key": "invalid_value"}],
            "version": "0.0.1",
            "commit": "invalid_commit",
        }
        with patch("accumulate.models.service.ServiceAddress.from_dict") as mock_from_dict:
            mock_from_dict.side_effect = ValueError("Invalid service data")
            with self.assertRaises(ValueError):
                NodeInfo.from_dict(invalid_data)

    def test_missing_keys(self):
        """Test deserialization with missing keys in the dictionary."""
        partial_data = {"peer_id": "partial", "network": "testnet"}
        node_info = NodeInfo.from_dict(partial_data)

        self.assertEqual(node_info.peer_id, "partial")
        self.assertEqual(node_info.network, "testnet")
        self.assertEqual(node_info.services, [])
        self.assertEqual(node_info.version, "")
        self.assertEqual(node_info.commit, "")

    def test_string_representation(self):
        """Test the string representation of NodeInfo."""
        node_info = NodeInfo(
            peer_id="12345",
            network="testnet",
            services=self.mock_services,
            version="1.0.0",
            commit="abc123",
        )
        expected_str = (
            "NodeInfo(peer_id='12345', network='testnet', services=[<MagicMock id='...'>, <MagicMock id='...'>], "
            "version='1.0.0', commit='abc123')"
        )
        self.assertIn("NodeInfo(peer_id='12345'", str(node_info))

if __name__ == "__main__":
    unittest.main()
