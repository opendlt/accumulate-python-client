# accumulate-python-client\tests\test_utils\test_rational.py

import pytest
from accumulate.utils.rational import Rational  # Corrected import

# --- Tests for Initialization ---
def test_rational_initialization_valid():
    """Test valid initialization of a Rational object."""
    r = Rational(2, 3)
    assert r.numerator == 2
    assert r.denominator == 3

def test_rational_initialization_zero_denominator():
    """Test initialization with a zero denominator raises an error."""
    with pytest.raises(ValueError, match="Denominator cannot be zero"):
        Rational(1, 0)

# --- Tests for Setting Values ---
def test_rational_set_valid():
    """Test setting valid numerator and denominator."""
    r = Rational(1, 2)
    r.set(3, 4)
    assert r.numerator == 3
    assert r.denominator == 4

def test_rational_set_zero_denominator():
    """Test setting a zero denominator raises an error."""
    r = Rational(1, 2)
    with pytest.raises(ValueError, match="Denominator cannot be zero"):
        r.set(1, 0)

# --- Tests for Threshold Calculation ---
def test_rational_threshold_valid():
    """Test valid threshold calculation."""
    r = Rational(2, 3)
    assert r.threshold(10) == 7  # (10 * 2) / 3 = 6.666..., rounded up to 7

def test_rational_threshold_zero_keys():
    """Test threshold calculation with zero keys."""
    r = Rational(3, 4)
    assert r.threshold(0) == 0  # (0 * 3) / 4 = 0

def test_rational_threshold_negative_keys():
    """Test threshold calculation with negative keys raises an error."""
    r = Rational(3, 4)
    with pytest.raises(ValueError, match="Key count cannot be negative"):
        r.threshold(-1)

def test_rational_threshold_rounding():
    """Test rounding behavior of the threshold calculation."""
    r = Rational(5, 2)  # Ratio 2.5
    assert r.threshold(2) == 5  # (2 * 5) / 2 = 5.0
    assert r.threshold(3) == 8  # (3 * 5) / 2 = 7.5, rounded up to 8

# --- Tests for Representation ---
def test_rational_repr():
    """Test the string representation of a Rational object."""
    r = Rational(2, 3)
    assert repr(r) == "Rational(2, 3)"
