# accumulate-python-client\accumulate\models\credits.py

class CreditsAccount:
    """Represents an account with a credit balance."""

    def __init__(self, credit_balance: int = 0):
        """
        Initialize a credits account.

        :param credit_balance: Initial credit balance of the account.
        """
        self.credit_balance = credit_balance

    def get_credit_balance(self) -> int:
        """
        Get the current credit balance.

        :return: The credit balance as an integer.
        """
        return self.credit_balance

    def credit_credits(self, amount: int):
        """
        Add credits to the account.

        :param amount: The amount of credits to add.
        """
        self.credit_balance += amount

    def can_debit_credits(self, amount: int) -> bool:
        """
        Check if the account has enough credits to debit.

        :param amount: The amount to check for debiting.
        :return: True if the account can debit the amount, False otherwise.
        """
        return amount <= self.credit_balance

    def debit_credits(self, amount: int) -> bool:
        """
        Debit credits from the account.

        :param amount: The amount of credits to debit.
        :return: True if the debit was successful, False otherwise.
        """
        if not self.can_debit_credits(amount):
            return False
        self.credit_balance -= amount
        return True

