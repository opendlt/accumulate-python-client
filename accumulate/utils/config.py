# accumulate-python-client\accumulate\utils\config.py

import os

class Config:
    """
    Configuration utility for managing environment-specific settings.
    """
    @staticmethod
    def is_testnet() -> bool:
        """
        Dynamically get the testnet status based on the environment variable.
        """
        return os.getenv("ACCUMULATE_IS_TESTNET", "false").lower() == "true"

    @staticmethod
    def initial_acme_oracle() -> float:
        """
        Dynamically get the initial ACME oracle value based on the network type.
        """
        return 5000 if Config.is_testnet() else 0.50

    @staticmethod
    def get_network_type() -> str:
        """
        Get the current network type.
        :return: 'testnet' or 'mainnet'
        """
        return "testnet" if Config.is_testnet() else "mainnet"

    @staticmethod
    def get_initial_oracle_value() -> float:
        """
        Get the initial ACME oracle value for the configured network.
        :return: The oracle value as a float.
        """
        return Config.initial_acme_oracle()
