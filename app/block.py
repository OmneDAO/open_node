# block.py

import json
import hashlib
import logging
from typing import List, Dict, Optional
from datetime import datetime, timezone
from decimal import Decimal

from merkle import MerkleTree  # Importing the updated MerkleTree from merkle.py

# Configure logging for the Block module
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


class Block:
    """
    Represents a block in the Omne blockchain.
    """

    def __init__(
        self,
        index: int,
        previous_hash: str,
        transactions: List[Dict],
        signatures: List[Dict],
        timestamp: Optional[str] = None,
        merkle_root: Optional[str] = None,
        block_hash: Optional[str] = None,
        leader: Optional[str] = None,  # New parameter
        proof_of_effort: Optional[str] = None  # New parameter
    ):
        """
        Initializes a new Block instance.

        :param index: Position of the block in the blockchain.
        :param previous_hash: Hash of the previous block.
        :param transactions: List of transactions included in the block.
        :param signatures: List of signatures from validators.
        :param timestamp: ISO formatted timestamp. If None, current UTC time is used.
        :param merkle_root: Merkle root of the transactions. If None, it's computed.
        :param block_hash: Hash of the block. If None, it's computed.
        :param leader: The identifier of the block leader. If None, it's optional.
        :param proof_of_effort: The proof of effort associated with the block. If None, it's optional.
        """
        self.index = index
        self.timestamp = timestamp or datetime.utcnow().replace(tzinfo=timezone.utc).isoformat()
        self.previous_hash = previous_hash
        self.transactions = transactions
        self.signatures = signatures
        self.leader = leader  # Assign the leader
        self.proof_of_effort = proof_of_effort  # Assign the proof of effort
        self.merkle_tree = MerkleTree()

        try:
            # Add all transactions to the Merkle Tree
            transaction_jsons = [json.dumps(tx, sort_keys=True) for tx in self.transactions]
            self.merkle_tree.add_transactions(transaction_jsons)
            logger.debug(f"Added {len(transaction_jsons)} transactions to Merkle Tree.")

            # Create the Merkle Tree
            self.merkle_tree.create_tree()
            self.merkle_root = merkle_root or self.merkle_tree.get_merkle_root()
            logger.info(f"Merkle Root computed: {self.merkle_root}")

            # Compute the block hash
            self.hash = block_hash or self.compute_hash()
            logger.info(f"Block Hash computed: {self.hash}")

            # Final integrity check
            if not self.hash or not self.merkle_root:
                logger.error("Block is incomplete. Missing hash or Merkle root.")
                raise ValueError("Incomplete block data.")

            logger.info(f"Block {self.index} initialized successfully.")

        except Exception as e:
            logger.critical(f"Failed to initialize block {self.index}: {e}")
            raise

    def compute_merkle_root(self) -> str:
        """
        Computes the Merkle root of the transactions using the MerkleTree class.

        :return: Merkle root as a hexadecimal string.
        """
        try:
            merkle_root = self.merkle_tree.get_merkle_root()
            logger.debug(f"Computed Merkle Root: {merkle_root}")
            return merkle_root
        except Exception as e:
            logger.error(f"Error computing Merkle root: {e}")
            raise

    def compute_hash(self) -> str:
        """
        Computes the SHA-256 hash of the block's contents.

        :return: Block hash as a hexadecimal string.
        """
        try:
            block_content = json.dumps({
                "index": self.index,
                "timestamp": self.timestamp,
                "previous_hash": self.previous_hash,
                "transactions": self.transactions,
                "signatures": self.signatures,
                "merkle_root": self.merkle_root,
                "leader": self.leader,
                "proof_of_effort": self.proof_of_effort
            }, sort_keys=True).encode('utf-8')

            block_hash = hashlib.sha256(block_content).hexdigest()
            logger.debug(f"Computed Block Hash: {block_hash}")
            return block_hash
        except Exception as e:
            logger.error(f"Error computing block hash: {e}")
            raise

    def to_dict(self) -> Dict:
        """
        Converts the Block instance to a dictionary.

        :return: Dictionary representation of the block.
        """
        return {
            "index": self.index,
            "timestamp": self.timestamp,
            "previous_hash": self.previous_hash,
            "transactions": self.transactions,
            "signatures": self.signatures,
            "merkle_root": self.merkle_root,
            "hash": self.hash,
            "leader": self.leader,
            "proof_of_effort": self.proof_of_effort
        }

    @staticmethod
    def from_dict(data: Dict) -> 'Block':
        """
        Creates a Block instance from a dictionary.

        :param data: Dictionary containing block data.
        :return: Block instance.
        """
        return Block(
            index=data["index"],
            previous_hash=data["previous_hash"],
            transactions=data.get("transactions", []),
            signatures=data.get("signatures", []),
            timestamp=data.get("timestamp"),
            merkle_root=data.get("merkle_root"),
            block_hash=data.get("hash"),
            leader=data.get("leader"),
            proof_of_effort=data.get("proof_of_effort")
        )

    def verify_signatures(self, crypto_utils, account_manager) -> bool:
        """
        Verifies all signatures in the block.

        :param crypto_utils: Instance of CryptoUtils for signature verification.
        :param account_manager: Instance of AccountManager to retrieve public keys.
        :return: True if all signatures are valid, False otherwise.
        """
        try:
            for sig in self.signatures:
                validator_address = sig.get('validator_address')
                signature = sig.get('signature')

                if not validator_address or not signature:
                    logger.error(f"Invalid signature format: {sig}")
                    return False

                public_key = account_manager.get_public_key(validator_address)
                if not public_key:
                    logger.error(f"Public key not found for validator: {validator_address}")
                    return False

                message = self.hash  # Typically, the block's hash is signed
                if not crypto_utils.verify_signature(public_key, message, signature):
                    logger.error(f"Signature verification failed for validator: {validator_address}")
                    return False

            logger.debug("All block signatures verified successfully.")
            return True

        except Exception as e:
            logger.error(f"Error during signature verification: {e}")
            return False

    def add_signature(self, validator_address: str, signature: str):
        """
        Adds a new signature to the block.

        :param validator_address: Address of the validator.
        :param signature: Signature string.
        """
        try:
            self.signatures.append({
                'validator_address': validator_address,
                'signature': signature
            })
            logger.info(f"Added signature from validator: {validator_address}")

            # Recompute the block's hash after adding a signature
            self.hash = self.compute_hash()
            logger.debug(f"Block hash updated after adding signature: {self.hash}")

        except Exception as e:
            logger.error(f"Failed to add signature: {e}")
            raise

    def is_valid(self, ledger) -> bool:
        """
        Validates the block against the ledger's rules.

        :param ledger: Instance of Ledger for accessing blockchain state.
        :return: True if the block is valid, False otherwise.
        """
        try:
            # Validate previous hash
            latest_block = ledger.get_latest_block()
            if self.previous_hash != latest_block.hash:
                logger.error("Previous hash does not match the latest block's hash.")
                return False
            logger.debug("Previous hash validated successfully.")

            # Validate Merkle root
            computed_merkle_root = self.compute_merkle_root()
            if self.merkle_root != computed_merkle_root:
                logger.error("Merkle root mismatch.")
                return False
            logger.debug("Merkle root validated successfully.")

            # Validate block hash
            computed_hash = self.compute_hash()
            if self.hash != computed_hash:
                logger.error("Block hash is invalid.")
                return False
            logger.debug("Block hash validated successfully.")

            # Verify signatures
            if not self.verify_signatures(ledger.crypto_utils, ledger.account_manager):
                logger.error("Block signatures are invalid.")
                return False
            logger.debug("Block signatures validated successfully.")

            # Validate consensus-specific rules
            if not self._validate_consensus_specific_rules(ledger):
                logger.error("Block failed consensus-specific validations.")
                return False
            logger.debug("Consensus-specific rules validated successfully.")

            logger.info("Block is valid.")
            return True

        except Exception as e:
            logger.error(f"Error during block validation: {e}")
            return False

    def _validate_consensus_specific_rules(self, ledger) -> bool:
        """
        Validates consensus-specific rules for the block, such as PoS and PoE requirements.

        :param ledger: Instance of Ledger for accessing blockchain state.
        :return: True if consensus-specific validations pass, False otherwise.
        """
        try:
            # Example: Ensure that the block has enough validator signatures as per cBFT
            required_signatures = ledger.consensus_engine.get_required_signatures()
            if len(self.signatures) < required_signatures:
                logger.error(f"Insufficient signatures for cBFT. Required: {required_signatures}, Got: {len(self.signatures)}.")
                return False
            logger.debug(f"Required signatures: {required_signatures}, Obtained: {len(self.signatures)}")

            # Example: Validate PoS stake of validators who signed the block
            for sig in self.signatures:
                validator_address = sig['validator_address']
                stake = ledger.account_manager.get_stake(validator_address)
                if stake < ledger.consensus_engine.get_minimum_stake():
                    logger.error(f"Validator {validator_address} does not meet the minimum stake requirement.")
                    return False
                logger.debug(f"Validator {validator_address} has sufficient stake: {stake}.")

            # Additional consensus-specific validations can be implemented here
            logger.debug("Consensus-specific rules passed.")
            return True

        except Exception as e:
            logger.error(f"Error during consensus-specific validation: {e}")
            return False
