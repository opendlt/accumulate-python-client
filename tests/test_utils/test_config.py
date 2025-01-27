# accumulate-python-client\tests\test_utils\test_config.py

import os
from unittest.mock import patch
from accumulate.utils.config import Config

# --- Tests for Config Class ---

def test_is_testnet_true():
    """Test is_testnet when the environment variable is set to true."""
    with patch.dict(os.environ, {"ACCUMULATE_IS_TESTNET": "true"}):
        assert Config.is_testnet() is True


def test_is_testnet_false():
    """Test is_testnet when the environment variable is set to false."""
    with patch.dict(os.environ, {"ACCUMULATE_IS_TESTNET": "false"}):
        assert Config.is_testnet() is False


def test_is_testnet_not_set():
    """Test is_testnet when the environment variable is not set."""
    with patch.dict(os.environ, {}, clear=True):
        assert Config.is_testnet() is False


def test_initial_acme_oracle_testnet():
    """Test initial_acme_oracle value when in testnet mode."""
    with patch.dict(os.environ, {"ACCUMULATE_IS_TESTNET": "true"}):
        assert Config.initial_acme_oracle() == 5000


def test_initial_acme_oracle_mainnet():
    """Test initial_acme_oracle value when in mainnet mode."""
    with patch.dict(os.environ, {"ACCUMULATE_IS_TESTNET": "false"}):
        assert Config.initial_acme_oracle() == 0.50


def test_get_network_type_testnet():
    """Test get_network_type returns 'testnet' in testnet mode."""
    with patch.dict(os.environ, {"ACCUMULATE_IS_TESTNET": "true"}):
        assert Config.get_network_type() == "testnet"


def test_get_network_type_mainnet():
    """Test get_network_type returns 'mainnet' in mainnet mode."""
    with patch.dict(os.environ, {"ACCUMULATE_IS_TESTNET": "false"}):
        assert Config.get_network_type() == "mainnet"


def test_get_initial_oracle_value_testnet():
    """Test get_initial_oracle_value returns correct value in testnet mode."""
    with patch.dict(os.environ, {"ACCUMULATE_IS_TESTNET": "true"}):
        assert Config.get_initial_oracle_value() == 5000


def test_get_initial_oracle_value_mainnet():
    """Test get_initial_oracle_value returns correct value in mainnet mode."""
    with patch.dict(os.environ, {"ACCUMULATE_IS_TESTNET": "false"}):
        assert Config.get_initial_oracle_value() == 0.50
