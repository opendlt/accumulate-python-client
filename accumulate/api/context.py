# accumulate-python-client\accumulate\api\context.py

from typing import Dict, Any


class RequestContext:
    """
    Represents the context for a request, including metadata and optional cancellation tokens.
    """

    def __init__(self, metadata: Dict[str, Any] = None):
        """
        Initialize the RequestContext with optional metadata.
        :param metadata: A dictionary containing request-specific metadata.
        """
        self.metadata = metadata or {}

    def get_metadata(self, key: str) -> Any:
        """
        Retrieve a value from the context metadata.
        :param key: Metadata key.
        :return: Metadata value or None if the key does not exist.
        """
        return self.metadata.get(key)

    def set_metadata(self, key: str, value: Any):
        """
        Set a value in the context metadata.
        :param key: Metadata key.
        :param value: Metadata value.
        """
        self.metadata[key] = value
