# accumulate-python-client\tests\__init__.py

import os
import sys

# Add the root directory to the Python path to ensure test files can import the project modules
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
