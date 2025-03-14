# \script_signer_change.py

import re

# Path to your transactions.py file
file_path = r"\accumulate\models\transactions.py"


# Read the file contents
with open(file_path, "r") as file:
    content = file.read()

# Replace all instances of `Signer` with `"Signer"`
updated_content = re.sub(r"\bSigner\b", '"Signer"', content)

# Write back the updated content
with open(file_path, "w") as file:
    file.write(updated_content)

print(" Successfully updated all Signer references to string annotations!")
