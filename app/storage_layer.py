from trie import HexaryTrie
import rlp

class StorageLayer:
    """
    A storage abstraction layer that separates logical objects from the underlying Merkle trie.
    """

    def __init__(self, db: dict):
        """
        Initialize the storage layer with a database.

        Args:
            db: The underlying database (e.g., LevelDB or in-memory dictionary).
        """
        self.trie = HexaryTrie(db)

    def get(self, key: str):
        """
        Retrieve a value from the storage layer.

        Args:
            key: The key to retrieve.

        Returns:
            The value associated with the key, or None if the key does not exist.
        """
        value = self.trie.get(key.encode())
        return rlp.decode(value) if value else None

    def set(self, key: str, value: dict):
        """
        Store a value in the storage layer.

        Args:
            key: The key to store the value under.
            value: The value to store.
        """
        self.trie.set(key.encode(), rlp.encode(value))

    def delete(self, key: str):
        """
        Delete a key-value pair from the storage layer.

        Args:
            key: The key to delete.
        """
        self.trie.delete(key.encode())

    def root_hash(self):
        """
        Get the current root hash of the Merkle trie.

        Returns:
            The root hash as a hex string.
        """
        root = self.trie.root_hash
        if callable(root):
            root = root()
        return root.hex() if root else "0" * 64

# Example usage
if __name__ == "__main__":
    db = {}
    storage = StorageLayer(db)

    # Set a value
    storage.set("key1", {"field": "value"})

    # Get the value
    print("Retrieved:", storage.get("key1"))

    # Delete the value
    storage.delete("key1")
    print("After deletion:", storage.get("key1"))