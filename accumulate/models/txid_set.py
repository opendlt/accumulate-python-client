# accumulate-python-client\accumulate\models\txid_set.py

from typing import List
from accumulate.models.txid import TxID


class TxIdSet:
    def __init__(self):
        self.entries: List[TxID] = []

    def add(self, txid: TxID):
        """
        Add a transaction ID to the set using a sorted insertion.
        """
        for i, entry in enumerate(self.entries):
            comparison = txid.compare(entry)
            if comparison == 0:  # Already exists
                return
            elif comparison < 0:  # Insert before
                self.entries.insert(i, txid)
                return
        # Add to the end if no earlier position was found
        self.entries.append(txid)

    def remove(self, txid: TxID):
        """
        Remove a transaction ID from the set if it exists.
        """
        for i, entry in enumerate(self.entries):
            if txid.compare(entry) == 0:
                del self.entries[i]
                return

    def contains_hash(self, hash_: bytes) -> bool:
        """
        Check if a transaction ID with the given hash exists in the set.
        """
        for entry in self.entries:
            if entry.tx_hash == hash_:  # Compare directly with the tx_hash attribute
                return True
        return False
