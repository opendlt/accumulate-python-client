# \examples\txhash_debug.py

import hashlib

# Below debug for TX Hash Construction
# Given encoded transaction values (as hex strings)
transaction_header_encoded = "013b6163633a2f2f6262613663646661326633363936363536343632616230663262616633623533373632663065326666366362383564342f41434d4502adc540d28bdb16d4d99a8b218bb6404982eb72c6ed805f040beb790aab97b4de"
transaction_body_encoded = "010e023b6163633a2f2f6262613663646661326633363936363536343632616230663262616633623533373632663065326666366362383564342f41434d4503035b8d80048827"

# Convert hex strings to bytes
transaction_header_bytes = bytes.fromhex(transaction_header_encoded)
transaction_body_bytes = bytes.fromhex(transaction_body_encoded)

# Compute SHA-256 hashes of the encoded transactions
header_hash = hashlib.sha256(transaction_header_bytes).digest()
body_hash = hashlib.sha256(transaction_body_bytes).digest()

# Concatenate the two hashes
combined_hash_input = header_hash + body_hash

# Compute final SHA-256 hash of the concatenated hashes
final_transaction_hash = hashlib.sha256(combined_hash_input).hexdigest()

# Print results
print(f"Header Hash: {header_hash.hex()}")
print(f"Body Hash: {body_hash.hex()}")
print(f"Final Transaction Hash: {final_transaction_hash}")
