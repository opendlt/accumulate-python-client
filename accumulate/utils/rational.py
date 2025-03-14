# accumulate-python-client\accumulate\utils\rational.py

import math
from typing import Union

class Rational:
    def __init__(self, numerator: Union[int, float], denominator: Union[int, float]):
        if denominator == 0:
            raise ValueError("Denominator cannot be zero")
        self.numerator = numerator
        self.denominator = denominator

    def set(self, numerator: Union[int, float], denominator: Union[int, float]):
        """Set the numerator and denominator of the rational value"""
        if denominator == 0:
            raise ValueError("Denominator cannot be zero")
        self.numerator = numerator
        self.denominator = denominator

    def threshold(self, key_count: int) -> int:
        """
        Calculate the threshold based on the ratio and key count
        Equivalent to keyCount * numerator / denominator, rounded up
        """
        if key_count < 0:
            raise ValueError("Key count cannot be negative")
        value = key_count * self.numerator / self.denominator
        return math.ceil(value)

    def __repr__(self):
        return f"Rational({self.numerator}, {self.denominator})"

# Example Usage
if __name__ == "__main__":
    r = Rational(2, 3)
    print(f"Threshold for 10 keys: {r.threshold(10)}")  # Output: Threshold for 10 keys: 7

    r.set(1, 4)
    print(f"Threshold for 8 keys: {r.threshold(8)}")  # Output: Threshold for 8 keys: 2
