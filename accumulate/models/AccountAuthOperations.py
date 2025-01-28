# accumulate-python-client\accumulate\models\AccountAuthOperations.py


from dataclasses import dataclass
from typing import Optional
from accumulate.utils.url import URL
from accumulate.models.enums import AccountAuthOperationType
from hashlib import sha256


class AccountAuthOperation:
    """
    Base class for account authentication operations.
    """

    def __init__(self, authority: URL):
        self.authority = authority

    def type(self) -> AccountAuthOperationType:
        """
        Return the operation type. Must be implemented by subclasses.
        """
        raise NotImplementedError("Subclasses must implement the `type` method.")

    def hash(self) -> str:
        """
        Generate a unique hash for this operation based on its attributes.
        """
        serialized = f"{self.type().name}:{self.authority}"
        return sha256(serialized.encode()).hexdigest()


class EnableAccountAuthOperation(AccountAuthOperation):
    """
    Represents an operation to enable authorization for a specific authority.

    :param authority: The URL of the authority to enable.
    """

    def __init__(self, authority: URL):
        super().__init__(authority)

    def type(self) -> AccountAuthOperationType:
        return AccountAuthOperationType.ENABLE


class DisableAccountAuthOperation(AccountAuthOperation):
    """
    Represents an operation to disable authorization for a specific authority.

    :param authority: The URL of the authority to disable.
    """

    def __init__(self, authority: URL):
        super().__init__(authority)

    def type(self) -> AccountAuthOperationType:
        return AccountAuthOperationType.DISABLE


class AddAccountAuthorityOperation(AccountAuthOperation):
    """
    Represents an operation to add an authority to an account's authorization list.

    :param authority: The URL of the authority to add.
    """

    def __init__(self, authority: URL):
        super().__init__(authority)

    def type(self) -> AccountAuthOperationType:
        return AccountAuthOperationType.ADD_AUTHORITY


class RemoveAccountAuthorityOperation(AccountAuthOperation):
    """
    Represents an operation to remove an authority from an account's authorization list.

    :param authority: The URL of the authority to remove.
    """

    def __init__(self, authority: URL):
        super().__init__(authority)

    def type(self) -> AccountAuthOperationType:
        return AccountAuthOperationType.REMOVE_AUTHORITY

