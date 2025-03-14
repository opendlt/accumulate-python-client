# accumulate/utils/conversion.py

import re

def camel_to_snake(name: str) -> str:
    """Converts camelCase to snake_case."""
    return re.sub(r'(?<!^)(?=[A-Z])', '_', name).lower()
