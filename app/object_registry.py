# object_registry.py
from threading import RLock
from typing import Dict, Any, Optional
from eth_utils import keccak
from storage_layer import StorageLayer  # Changed to absolute import
import rlp, json, logging
import time


logger = logging.getLogger("ObjectRegistry")


class ObjectRegistry:
    """
    Key-value store where keys are 32-byte object-IDs and values are RLP-encoded
    dictionaries  →   stored in a Hexary Merkle-Patricia-Trie (like Ethereum).
    """
    def __init__(self, db: Optional[dict] = None):
        self.db = db or {}            # simple in-memory db; pluggable to LevelDB later
        self.storage = StorageLayer(self.db)  # Use StorageLayer instead of direct trie access
        self._lock = RLock()

    # ─────────────────────────────────────────────────────────
    # CRUD helpers
    # ─────────────────────────────────────────────────────────
    def create(self, class_name: str, owner: str, storage_root: str = "", code_ref: str = "") -> str:
        obj_id = keccak(f"{class_name}{owner}{time.time()}".encode()).hex()
        payload = {
            "class": class_name,
            "owner": owner,
            "storage": {},
            "root": storage_root,
            "code_ref": code_ref  # New field for versioning
        }
        self.storage.set(obj_id, payload)  # Use StorageLayer
        return obj_id

    def create_with_shard(self, obj_id: str, initial_state: Dict[str, Any], shard_bits: int = 4) -> None:
        """
        Create an object and route it to the appropriate shard based on its shard key.

        Args:
            obj_id: The object ID.
            initial_state: The initial state of the object.
            shard_bits: The number of bits to use for shard determination.
        """
        shard_key = self.get_shard_key(obj_id, shard_bits)
        logger.info(f"Routing object {obj_id} to shard {shard_key}")
        self.create(obj_id, initial_state)

    def update(self, obj_id: str, delta: Dict[str, Any]) -> None:
        with self._lock:
            if not self.exists(obj_id):
                raise KeyError(obj_id)
            current = self.storage.get(obj_id)  # Use StorageLayer
            current.update(delta)
            self.storage.set(obj_id, current)  # Use StorageLayer

    def upgrade(self, obj_id: str, new_code_ref: str, owner_signature: str) -> None:
        """
        Upgrade the code reference of an object.

        Args:
            obj_id: The ID of the object to upgrade.
            new_code_ref: The new code reference (hash of the bytecode).
            owner_signature: The signature of the owner authorizing the upgrade.

        Raises:
            ValueError: If the object does not exist or the signature is invalid.
        """
        with self._lock:
            if not self.exists(obj_id):
                raise ValueError(f"Object {obj_id} does not exist")

            current = self.storage.get(obj_id)  # Use StorageLayer

            # Verify owner signature (placeholder for actual signature verification logic)
            if current["owner"] != owner_signature:  # Simplified check
                raise ValueError("Invalid owner signature")

            # Update the code reference
            current["code_ref"] = new_code_ref
            self.storage.set(obj_id, current)  # Use StorageLayer

    def get(self, obj_id: str) -> Optional[Dict[str, Any]]:
        with self._lock:
            return self.storage.get(obj_id)  # Use StorageLayer

    def get_from_shard(self, obj_id: str, shard_bits: int = 4) -> Optional[Dict[str, Any]]:
        """
        Retrieve an object from the appropriate shard based on its shard key.

        Args:
            obj_id: The object ID.
            shard_bits: The number of bits to use for shard determination.

        Returns:
            Optional[Dict[str, Any]]: The object state if it exists, otherwise None.
        """
        shard_key = self.get_shard_key(obj_id, shard_bits)
        logger.info(f"Accessing object {obj_id} from shard {shard_key}")
        return self.get(obj_id)

    def exists(self, obj_id: str) -> bool:
        return self.storage.get(obj_id) is not None  # Use StorageLayer

    # ------------------------------------------------------------------
    # Trie utilities
    # ------------------------------------------------------------------
    def root_hash(self) -> str:
        """Return the **hex string** of the current trie root."""
        return self.storage.root_hash()

    def verify_proof(self, obj_id: str, slot: str, proof: list, expected_value: Any) -> bool:
        """
        Verify a Merkle-Patricia inclusion proof for <obj_id>/<slot>.
        
        Args:
            obj_id: The object ID to verify.
            slot: The specific slot within the object to verify.
            proof: The Merkle-Patricia proof as a list of nodes.
            expected_value: The expected value at the given slot.
        
        Returns:
            bool: True if the proof is valid and matches the expected value, False otherwise.
        """
        key = obj_id.encode() if slot == "" else keccak(f"{obj_id}.{slot}".encode())
        try:
            # Decode proof nodes from hex
            proof_nodes = [bytes.fromhex(node) for node in proof]
            # Verify the proof against the trie root
            value = self.storage.get_from_proof(key, proof_nodes)  # Use StorageLayer
            return rlp.decode(value) == expected_value
        except Exception as e:
            logger.error(f"Proof verification failed: {e}")
            return False

    def get_proof(self, obj_id: str, slot: str = "", chain_id: str = "") -> list:
        """
        Return a Merkle-Patricia inclusion proof for <obj_id>/<slot>.
        If `slot` is "", we prove the whole object payload.
        Includes chain-ID in the proof for chain-specific validation.
        
        Args:
            obj_id: The object ID to prove.
            slot: The specific slot within the object to prove.
            chain_id: The chain ID for chain-specific validation.
        
        Returns:
            list: The Merkle-Patricia proof as a list of hex-encoded nodes.
        """
        key = obj_id.encode() if slot == "" else keccak(f"{obj_id}.{slot}".encode())
        proof = self.storage.get_proof(key)  # Use StorageLayer
        compact_proof = [node.hex() for node in proof]
        
        # Add chain-ID to the proof metadata
        if chain_id:
            compact_proof.insert(0, f"chain_id:{chain_id}")
        
        return compact_proof

    # snapshot / restore helpers (used by Ledger's deterministic replay)
    def snapshot(self):
        return bytes(self.storage.root_hash)

    def restore(self, root_hash: bytes):
        self.storage.root_hash = root_hash

    def get_shard_key(self, obj_id: str, shard_bits: int = 4) -> int:
        """
        Determine the shard key for an object based on the first n bits of its ID.

        Args:
            obj_id: The object ID (hex string).
            shard_bits: The number of bits to use for shard determination.

        Returns:
            int: The shard key.
        """
        if not obj_id:
            raise ValueError("Object ID cannot be empty")

        # Convert the first shard_bits/4 hex characters to an integer
        shard_key = int(obj_id[:shard_bits // 4], 16)
        return shard_key

    def assign_shard_key(self, obj_id: str, shard_bits: int = 4) -> int:
        """
        Assign a shard key to an object based on its ID.

        Args:
            obj_id: The object ID.
            shard_bits: The number of bits to use for shard determination.

        Returns:
            int: The shard key assigned to the object.
        """
        shard_key = self.get_shard_key(obj_id, shard_bits)
        logger.info(f"Assigned shard key {shard_key} to object {obj_id}")
        return shard_key

    def get_objects_by_shard(self, shard_key: int, shard_bits: int = 4) -> list:
        """
        Retrieve all objects assigned to a specific shard.

        Args:
            shard_key: The shard key to filter objects by.
            shard_bits: The number of bits used for shard determination.

        Returns:
            list: A list of object IDs belonging to the specified shard.
        """
        objects_in_shard = []
        for obj_id in self.storage.keys():  # Use StorageLayer
            if self.get_shard_key(obj_id.decode(), shard_bits) == shard_key:
                objects_in_shard.append(obj_id.decode())
        return objects_in_shard

    def set_param(self, param_path: str, value: Any) -> None:
        """
        Set a parameter in the registry under a specific path.

        Args:
            param_path: The path for the parameter (e.g., '/__param/rent_per_byte').
            value: The value to set for the parameter.
        """
        with self._lock:
            self.storage.set(param_path, value)  # Use StorageLayer

    def get_param(self, param_path: str) -> Optional[Any]:
        """
        Retrieve a parameter from the registry.

        Args:
            param_path: The path for the parameter (e.g., '/__param/rent_per_byte').

        Returns:
            The value of the parameter if it exists, otherwise None.
        """
        with self._lock:
            return self.storage.get(param_path)  # Use StorageLayer

    def calculate_rent(self, obj_id: str, rent_per_byte: int) -> int:
        """
        Calculate the rent for an object based on its size.

        Args:
            obj_id: The ID of the object.
            rent_per_byte: The rent cost per byte per block.

        Returns:
            int: The total rent for the object.
        """
        with self._lock:
            if not self.exists(obj_id):
                raise ValueError(f"Object {obj_id} does not exist")

            current = self.storage.get(obj_id)  # Use StorageLayer
            size_in_bytes = len(rlp.encode(current))
            return size_in_bytes * rent_per_byte

    def deduct_rent(self, obj_id: str, rent_per_byte: int) -> bool:
        """
        Deduct rent from an object's balance. Freeze the object if rent is unpaid.

        Args:
            obj_id: The ID of the object.
            rent_per_byte: The rent cost per byte per block.

        Returns:
            bool: True if rent was successfully deducted, False if the object is frozen.
        """
        with self._lock:
            if not self.exists(obj_id):
                raise ValueError(f"Object {obj_id} does not exist")

            current = self.storage.get(obj_id)  # Use StorageLayer
            rent = self.calculate_rent(obj_id, rent_per_byte)

            if current.get("balance", 0) < rent:
                current["frozen"] = True
                self.storage.set(obj_id, current)  # Use StorageLayer
                return False

            current["balance"] -= rent
            self.storage.set(obj_id, current)  # Use StorageLayer
            return True

    def reap_object(self, obj_id: str) -> None:
        """
        Remove a frozen object and prune its storage root from the trie.

        Args:
            obj_id: The ID of the object to reap.
        """
        with self._lock:
            if not self.exists(obj_id):
                raise ValueError(f"Object {obj_id} does not exist")

            current = self.storage.get(obj_id)  # Use StorageLayer
            if not current.get("frozen", False):
                raise ValueError(f"Object {obj_id} is not frozen and cannot be reaped")

            self.storage.delete(obj_id)  # Use StorageLayer
            logger.info(f"Object {obj_id} has been reaped and its storage root pruned.")
