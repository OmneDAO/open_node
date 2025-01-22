# merkle.py

import hashlib
import json
import logging
from typing import List, Tuple, Optional

# Configure logging for the MerkleTree module
logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG)  # Set to DEBUG for detailed trace; adjust as needed

# Create console handler with a higher log level
ch = logging.StreamHandler()
ch.setLevel(logging.INFO)  # Change to DEBUG to see detailed logs

# Create formatter and add it to the handlers
formatter = logging.Formatter('[%(asctime)s] %(levelname)s in %(module)s: %(message)s')
ch.setFormatter(formatter)

# Add the handlers to the logger
if not logger.handlers:
    logger.addHandler(ch)


class MerkleTree:
    """
    A robust and production-ready Merkle Tree implementation.
    
    Attributes:
        transactions (List[str]): List of transaction hashes.
        tree (List[List[str]]): Hierarchical levels of the Merkle Tree.
        merkle_root (Optional[str]): Cached Merkle root.
    """
    
    def __init__(self):
        """
        Initializes an empty Merkle Tree.
        """
        self.transactions: List[str] = []
        self.tree: List[List[str]] = []
        self.merkle_root: Optional[str] = None
        logger.info("MerkleTree initialized.")

    def add_transaction(self, transaction: str):
        """
        Adds a single transaction to the Merkle Tree.
        
        Args:
            transaction (str): The transaction data as a JSON string.
        """
        if not isinstance(transaction, str):
            logger.error("Transaction must be a JSON string.")
            raise ValueError("Transaction must be a JSON string.")
        
        self.transactions.append(transaction)
        logger.debug(f"Added transaction: {transaction}")
        self.merkle_root = None  # Invalidate the cached root

    def add_transactions(self, transactions: List[str]):
        """
        Adds multiple transactions to the Merkle Tree.
        
        Args:
            transactions (List[str]): A list of transaction data as JSON strings.
        """
        if not all(isinstance(tx, str) for tx in transactions):
            logger.error("All transactions must be JSON strings.")
            raise ValueError("All transactions must be JSON strings.")
        
        self.transactions.extend(transactions)
        logger.debug(f"Added {len(transactions)} transactions.")
        self.merkle_root = None  # Invalidate the cached root

    def create_tree(self):
        """
        Constructs the Merkle Tree from the current list of transactions.
        """
        if not self.transactions:
            logger.warning("No transactions to build the Merkle Tree.")
            self.tree = []
            self.merkle_root = None
            return

        # Initialize the first level (leaves)
        current_level = [self.hash_data(tx) for tx in self.transactions]
        self.tree = [current_level]
        logger.debug(f"Level 0 (leaves): {current_level}")

        # Build the tree upwards
        while len(current_level) > 1:
            upper_level = self.create_upper_level(current_level)
            self.tree.append(upper_level)
            logger.debug(f"Built upper level: {upper_level}")
            current_level = upper_level

        # Set the Merkle root
        self.merkle_root = self.tree[-1][0]
        logger.info(f"Merkle Tree created with root: {self.merkle_root}")

    def create_upper_level(self, lower_level: List[str]) -> List[str]:
        """
        Generates the next upper level of the Merkle Tree from the provided lower level.
        
        Args:
            lower_level (List[str]): The hashes of the current level.
        
        Returns:
            List[str]: The hashes of the upper level.
        """
        upper_level = []
        for i in range(0, len(lower_level), 2):
            left = lower_level[i]
            right = lower_level[i + 1] if i + 1 < len(lower_level) else left
            combined_hash = self.hash_pair(left, right)
            upper_level.append(combined_hash)
            logger.debug(f"Pair ({left}, {right}) -> {combined_hash}")
        return upper_level

    @staticmethod
    def hash_data(data: str) -> str:
        """
        Generates a SHA-256 hash for the given data.
        
        Args:
            data (str): The data to hash.
        
        Returns:
            str: The hexadecimal SHA-256 hash of the data.
        """
        return hashlib.sha256(data.encode('utf-8')).hexdigest()

    @classmethod
    def hash_pair(cls, left: str, right: str) -> str:
        """
        Hashes a pair of hashes.
        
        Args:
            left (str): The left hash.
            right (str): The right hash.
        
        Returns:
            str: The combined SHA-256 hash.
        """
        combined = left + right
        return cls.hash_data(combined)

    def get_merkle_root(self) -> Optional[str]:
        """
        Retrieves the Merkle root of the tree. If the tree hasn't been built yet, it builds the tree.
        
        Returns:
            Optional[str]: The Merkle root, or None if the tree is empty.
        """
        if self.merkle_root is None:
            logger.debug("Merkle root not cached. Building the Merkle Tree.")
            self.create_tree()
        else:
            logger.debug("Merkle root retrieved from cache.")
        return self.merkle_root

    def get_merkle_proof(self, transaction: str) -> Optional[List[Tuple[str, str]]]:
        """
        Generates a Merkle proof for a given transaction.
        
        Args:
            transaction (str): The transaction data as a JSON string.
        
        Returns:
            Optional[List[Tuple[str, str]]]: A list of tuples containing sibling hashes and their direction
                                             ('left' or 'right'). Returns None if transaction not found.
        """
        if transaction not in self.transactions:
            logger.error("Transaction not found in the Merkle Tree.")
            return None
        
        index = self.transactions.index(transaction)
        proof = []
        
        logger.debug(f"Generating Merkle proof for transaction at index {index}: {transaction}")
        
        for level in self.tree[:-1]:  # Exclude the root level
            sibling_index = index + 1 if index % 2 == 0 else index - 1
            if sibling_index < len(level):
                sibling_hash = level[sibling_index]
                direction = 'right' if index % 2 == 0 else 'left'
                proof.append((sibling_hash, direction))
                logger.debug(f"At level {self.tree.index(level)}, sibling: {sibling_hash}, direction: {direction}")
            else:
                # If no sibling, duplicate the current hash
                sibling_hash = level[index]
                direction = 'right' if index % 2 == 0 else 'left'
                proof.append((sibling_hash, direction))
                logger.debug(f"At level {self.tree.index(level)}, no sibling. Duplicated hash: {sibling_hash}, direction: {direction}")
            index = index // 2  # Move to the parent index for the next level
        
        logger.info(f"Merkle proof generated for transaction: {transaction}")
        return proof

    @staticmethod
    def verify_proof(proof: List[Tuple[str, str]], transaction: str, root: str) -> bool:
        """
        Verifies a Merkle proof for a given transaction against a provided Merkle root.
        
        Args:
            proof (List[Tuple[str, str]]): The Merkle proof as a list of (sibling_hash, direction) tuples.
            transaction (str): The transaction data as a JSON string.
            root (str): The Merkle root to verify against.
        
        Returns:
            bool: True if the proof is valid, False otherwise.
        """
        current_hash = MerkleTree.hash_data(transaction)
        logger.debug(f"Starting proof verification. Initial hash: {current_hash}")
        
        for sibling_hash, direction in proof:
            if direction == 'left':
                current_hash = MerkleTree.hash_pair(sibling_hash, current_hash)
                logger.debug(f"Combined with left sibling: {sibling_hash} -> {current_hash}")
            elif direction == 'right':
                current_hash = MerkleTree.hash_pair(current_hash, sibling_hash)
                logger.debug(f"Combined with right sibling: {sibling_hash} -> {current_hash}")
            else:
                logger.error(f"Invalid direction '{direction}' in proof.")
                return False  # Invalid direction
        
        is_valid = current_hash == root
        if is_valid:
            logger.info("Merkle proof verification succeeded.")
        else:
            logger.warning("Merkle proof verification failed.")
        return is_valid
