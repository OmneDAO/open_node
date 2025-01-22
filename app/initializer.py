# initializer.py

import logging
import json
import hashlib
import inspect
from datetime import datetime, timezone
from cryptography.fernet import Fernet
from bson.objectid import ObjectId
import secrets
from typing import List, Dict, Optional, Type

from merkle import MerkleTree
from utils import QuantumUtils
from verifier import Verifier
from permissions import PermissionManager
from staked_omc import StakedOMC
from mempool import Mempool
from account_manager import AccountManager
from dynamic_fee_calculator import DynamicFeeCalculator
from crypto_utils import CryptoUtils
from ledger import Ledger
from smart_contracts import SmartContracts


class Initializer:
    """
    Responsible for initializing the blockchain ledger, creating the genesis block,
    setting up initial transactions, and configuring validator staking agreements.
    """

    def __init__(self, ledger: Ledger, treasury_address: str, treasury_public_key: str, treasury_private_key: str):
        """
        Initializes the Initializer with necessary components and performs genesis block creation.

        :param ledger: Instance of the Ledger class managing the blockchain.
        :param treasury_address: The address of the treasury account.
        :param treasury_public_key: The public key of the treasury account.
        :param treasury_private_key: The private key of the treasury account.
        """
        self.ledger = ledger
        self.treasury_address = treasury_address
        self.treasury_public_key = treasury_public_key
        self.treasury_private_key = treasury_private_key
        self.encryption_key = Fernet.generate_key()  # In production, securely store and retrieve this key
        self.fernet = Fernet(self.encryption_key)

        # Configure logging for the Initializer
        self.logger = logging.getLogger('Initializer')
        self.logger.setLevel(logging.DEBUG)  # Set to DEBUG for detailed logs during initialization
        handler = logging.StreamHandler()
        formatter = logging.Formatter('[%(asctime)s] [%(levelname)s] [%(name)s] %(message)s')
        handler.setFormatter(formatter)
        if not self.logger.handlers:
            self.logger.addHandler(handler)

        # Connect to the ledger's database
        self.db = self._connect_to_database()

        # Initialize utilities
        self.fee_calculator = DynamicFeeCalculator()
        self.crypto_utils = CryptoUtils()

        # Proceed only if the database connection is successful
        if self.db is not None:
            try:
                self.initial_block("0" * 64)
                self.add_initial_node_to_verifier()
                self.setup_staking()
                self.serialize_and_store_class_hashes()
                self.logger.info("Initialization completed successfully.")
            except Exception as e:
                self.logger.critical(f"Initialization failed: {e}")
                raise
        else:
            self.logger.critical("Database connection failed. Initialization aborted.")
            raise ConnectionError("Unable to connect to the ledger's database.")

    def _connect_to_database(self) -> Optional:
        """
        Connects to the ledger's database.

        :return: Database connection object if successful, None otherwise.
        """
        try:
            if hasattr(self.ledger, 'db') and self.ledger.db is not None:
                self.logger.info("Connected to the ledger's database successfully.")
                return self.ledger.db
            else:
                self.logger.error("Ledger's database is not initialized. Ensure MongoDB client is provided.")
                return None
        except Exception as e:
            self.logger.error(f"Failed to connect to the ledger's database: {e}")
            return None

    def add_initial_node_to_verifier(self):
        """
        Adds the initial node to the verifier's list of nodes to participate in consensus.
        """
        if not self.ledger.node or not self.ledger.verifier:
            self.logger.error("Ledger's node or verifier is not initialized correctly.")
            return

        initial_node_dict = self.ledger.node.to_dict()
        initial_node_dict['stake_weight'] = 1  # Initial stake weight

        # Assign a steward if not already set
        if not initial_node_dict.get('steward'):
            initial_node_dict['steward'] = self.treasury_address
            self.logger.info(f"Assigned steward: {initial_node_dict['steward']}")

        # Check if the node already exists in the verifier
        existing_node = next(
            (node for node in self.ledger.verifier.nodes if node['address'] == initial_node_dict['address']),
            None
        )
        if existing_node:
            self.logger.info(f"Node {initial_node_dict['address']} already exists in verifier nodes.")
        else:
            self.ledger.verifier.nodes.append(initial_node_dict)
            self.logger.info(f"Added initial node to verifier nodes: {initial_node_dict}")

    def validate_transaction_fields(self, transaction: Dict) -> bool:
        """
        Validates that the transaction contains all required fields.

        :param transaction: The transaction dictionary to validate.
        :return: True if valid, False otherwise.
        """
        required_fields = ['hash', 'timestamp', 'sender', 'fee', 'signature', 'public_key']
        missing_fields = [field for field in required_fields if field not in transaction or transaction[field] is None]

        if missing_fields:
            self.logger.error(f"Transaction validation failed. Missing fields: {missing_fields}. Transaction: {transaction}")
            return False

        self.logger.debug(f"Transaction validated successfully: {transaction}")
        return True

    def initial_block(self, previous_hash: str = "0" * 64) -> Optional[Dict]:
        """
        Creates and adds the genesis block to the ledger.

        :param previous_hash: The hash of the previous block. Defaults to 64 zeros for the genesis block.
        :return: The genesis block dictionary if successful, None otherwise.
        """
        transactions = []

        if not self.ledger.chain:
            self.logger.info("No existing blocks found. Creating the genesis block.")

            # Initialize treasury and steward addresses
            self.ledger.omc.treasury_address = self.treasury_address
            self.ledger.node.steward = self.treasury_address

            self.logger.info(f'Treasury Wallet Address: {self.treasury_address}')
            self.logger.info(f'Treasury Wallet Public Key: {self.treasury_public_key}')

            # Mint initial coins to the treasury
            initial_supply = self.ledger.omc.initial_supply
            airdrop_amount = int(0.20 * initial_supply)
            reserves_amount = int(0.15 * initial_supply)

            self.ledger.omc.mint_coins_and_send(self.ledger.omc.treasury_address, airdrop_amount)
            self.allocate_reserves(reserves_amount)
            self.ledger.omc.debit(self.ledger.omc.treasury_address, reserves_amount)

            # Create genesis transaction
            genesis_transaction = self.create_genesis_transaction(reserves_amount)
            if not genesis_transaction:
                self.logger.error("Failed to create the genesis transaction.")
                return None

            # Add genesis transaction to the ledger's wallet and transaction list
            self.ledger.wallet.add_account({
                'address': self.treasury_address,
                'balance': initial_supply - reserves_amount,
                'withdrawals': 0
            })

            # Validate and append genesis transaction
            if self.validate_transaction_fields(genesis_transaction):
                transactions.append(genesis_transaction)
                self.logger.info("Genesis transaction added successfully.")
            else:
                self.logger.error("Genesis transaction validation failed.")
                return None

            # Setup staking transaction
            self.setup_staking_transaction(transactions, previous_hash, reserves_amount)

            # Validate all transactions before creating the genesis block
            for tx in transactions:
                if not self.validate_transaction_fields(tx):
                    self.logger.error(f"Invalid transaction detected: {tx}. Aborting genesis block creation.")
                    return None

            # Prepare the genesis block
            genesis_block = self.prepare_genesis_block(transactions, previous_hash, genesis_transaction['fee'])
            if not genesis_block or not genesis_block.get('hash'):
                self.logger.error("Genesis block creation failed due to incomplete block data.")
                return None

            # Add the genesis block to the ledger
            with self.ledger.lock:
                self.ledger.chain.append(genesis_block)
                self.logger.info(f"Genesis block created and added to the ledger: {genesis_block}")

            # Serialize and store class hashes for security
            self.serialize_and_store_class_hashes()

            return genesis_block
        else:
            self.logger.info("Ledger already contains blocks. Genesis block creation skipped.")
            return self.ledger.get_latest_block()

    def create_genesis_transaction(self, reserves_amount: int) -> Optional[Dict]:
        """
        Creates the genesis transaction for the treasury account.

        :param reserves_amount: The amount allocated to reserves.
        :return: The genesis transaction dictionary if successful, None otherwise.
        """
        genesis_transaction = {
            'address': self.treasury_address,
            'balance': self.ledger.omc.initial_supply - reserves_amount,
            'type': 'coin_creation',  # Clarified transaction type
            'timestamp': datetime.now(timezone.utc).isoformat(),
            'withdrawals': 0,
            'public_key': self.treasury_public_key,
            'fee': 0.0,
            'sender': self.treasury_address,
        }

        # Calculate transaction fee and hash
        transactions = {}
        try:
            transaction_fee, transaction_hash = self.fee_calculator.get_base_dynamic_fee(
                transaction=genesis_transaction,
                transaction_type='coin_creation',
                transactions=transactions
            )
            genesis_transaction['fee'] = transaction_fee
            genesis_transaction['hash'] = transaction_hash if isinstance(transaction_hash, str) else transaction_hash.hex()
            self.logger.debug(f"Genesis transaction after fee calculation: {genesis_transaction}")
        except Exception as e:
            self.logger.error(f"Failed to calculate fee and hash for genesis transaction: {e}")
            return None

        # Sign the genesis transaction
        try:
            genesis_transaction['signature'] = self.crypto_utils.sign_message(
                private_key=self.treasury_private_key,
                message=genesis_transaction
            )
            self.logger.debug(f"Genesis transaction after signing: {genesis_transaction}")
        except Exception as e:
            self.logger.error(f"Failed to sign genesis transaction: {e}")
            return None

        # Validate the genesis transaction
        if not self.validate_transaction_fields(genesis_transaction):
            self.logger.error("Genesis transaction validation failed after signing.")
            return None

        # Verify the signature
        if not self.crypto_utils.verify_message(
            public_key=self.treasury_public_key,
            message=genesis_transaction,
            signature=genesis_transaction['signature']
        ):
            self.logger.error("Signature verification failed for genesis transaction.")
            return None

        self.logger.info("Genesis transaction created and verified successfully.")
        return genesis_transaction

    def setup_staking(self):
        """
        Sets up initial staking agreements and includes the staking transaction in the genesis block.
        """
        # For clarity, this method orchestrates the staking transaction setup
        # The actual staking transaction is handled in `setup_staking_transaction`
        pass  # All staking setup is handled in `initial_block`

    def setup_staking_transaction(self, transactions: List[Dict], previous_hash: str, reserves_amount: int):
        """
        Sets up the staking transaction for the genesis block.

        :param transactions: List of transactions to include in the genesis block.
        :param previous_hash: The hash of the previous block.
        :param reserves_amount: The amount allocated to reserves.
        """
        min_term = 200  # Minimum staking term in blocks
        reduced_balance = int(self.ledger.omc.initial_supply * 0.05)
        contract_id = '0s' + secrets.token_hex(16)

        staking_transaction = {
            'stake_id': contract_id,
            'address': self.treasury_address,
            'amount': reduced_balance,
            'min_term': min_term,
            'node_address': None,
            'withdrawals': 0,
            'start_date': datetime.now(timezone.utc).isoformat(),
            'type': 'staking',  # Clarified transaction type
            'public_key': self.treasury_public_key,
            'timestamp': datetime.now(timezone.utc).isoformat(),
            'sender': self.treasury_address,
            'fee': 0.0
        }

        try:
            # Calculate the staking transaction fee and hash
            staking_transactions = transactions.copy()
            fee, tx_hash = self.fee_calculator.get_base_dynamic_fee(
                transaction=staking_transaction,
                transaction_type='staking',
                transactions=staking_transactions
            )
            staking_transaction['fee'] = fee
            staking_transaction['hash'] = tx_hash if isinstance(tx_hash, str) else tx_hash.hex()
            self.logger.debug(f"Staking transaction after fee calculation: {staking_transaction}")

            # Assign node address (select a validator)
            if self.ledger.verifier.nodes:
                validator_node = self.ledger.verifier.select_validator()
                if validator_node:
                    staking_transaction['node_address'] = validator_node['address']
                    self.logger.info(f"Selected validator node for staking: {validator_node['address']}")
                else:
                    self.logger.warning("No validator node selected. Assigning to treasury node.")
                    staking_transaction['node_address'] = self.treasury_address
            else:
                self.logger.warning("Verifier has no nodes. Assigning staking to treasury node.")
                staking_transaction['node_address'] = self.treasury_address

            # Update staking agreements
            staking_contract = {
                'contract_id': contract_id,
                'node_address': staking_transaction['node_address'],
                'amount': reduced_balance,
                'min_term': min_term
            }
            self.ledger.verifier.update_staking_agreements([staking_contract])
            self.logger.info(f"Staking contract created: {staking_contract}")

            # Sign the staking transaction
            staking_transaction['signature'] = self.crypto_utils.sign_message(
                private_key=self.treasury_private_key,
                message=staking_transaction
            )
            self.logger.debug(f"Staking transaction after signing: {staking_transaction}")

            # Validate the staking transaction
            if not self.validate_transaction_fields(staking_transaction):
                self.logger.error("Staking transaction validation failed.")
                return

            # Verify the staking transaction signature
            if not self.crypto_utils.verify_message(
                public_key=self.treasury_public_key,
                message=staking_transaction,
                signature=staking_transaction['signature']
            ):
                self.logger.error("Signature verification failed for staking transaction.")
                return

            # Add the staking transaction to the genesis block's transactions
            transactions.append(staking_transaction)
            self.logger.info("Staking transaction added successfully to the genesis block.")

        except Exception as e:
            self.logger.error(f"Failed to set up staking transaction: {e}")

    
    def allocate_reserves(self, amount: int):
        """
        Allocates reserve funds to the treasury.

        :param amount: The amount to allocate to reserves.
        """
        self.ledger.omc.reserves = amount
        self.logger.info(f"Allocated {amount} to reserves.")

    def serialize_and_store_class_hashes(self):
        """
        Serializes and stores hashes of critical classes for integrity verification.
        """
        if self.db is None:
            self.logger.error("Cannot serialize and store class hashes. Database connection is unavailable.")
            return

        db_collection = self.db["classes"]
        classes_to_hash = {
            'coin': self.ledger.omc.__class__,
            'quantum_utils': QuantumUtils,
            'verifier': self.ledger.verifier.__class__,
            'crypto_utils': self.crypto_utils.__class__,
            'fee_calculator': self.fee_calculator.__class__,
            'ledger': self.ledger.__class__,
            'permission_manager': PermissionManager,
            'mempool': self.ledger.mempool.__class__,
            'smart_contracts': SmartContracts
        }

        for class_name, cls in classes_to_hash.items():
            try:
                class_hash = self.create_class_hashes(cls)
                if class_hash:
                    # Check if hash already exists to prevent duplicates
                    existing_hash = db_collection.find_one({"class_name": class_name})
                    if existing_hash:
                        self.logger.info(f"Class hash for {class_name} already exists. Updating hash.")
                        db_collection.update_one(
                            {"class_name": class_name},
                            {"$set": {"hash": class_hash, "timestamp": datetime.now(timezone.utc)}}
                        )
                    else:
                        self.logger.info(f"Storing class hash for {class_name}.")
                        db_collection.insert_one({
                            "class_name": class_name,
                            "hash": class_hash,
                            "timestamp": datetime.now(timezone.utc)
                        })
                    self.logger.info(f"Stored class hash for {class_name}: {class_hash}")
                else:
                    self.logger.error(f"Class hash for {class_name} is empty. Skipping storage.")
            except Exception as e:
                self.logger.error(f"Failed to serialize and store hash for {class_name}: {e}")

        self.logger.info("All class hashes serialized and stored successfully.")

    def create_class_hashes(self, cls: Type) -> str:
        """
        Generates a SHA-256 hash based on the class's source code.

        :param cls: The class to hash.
        :return: The hexadecimal string of the class hash.
        """
        try:
            source = inspect.getsource(cls)
            class_hash = hashlib.sha256(source.encode('utf-8')).hexdigest()
            self.logger.debug(f"Class {cls.__name__} hash: {class_hash}")
            return class_hash
        except Exception as e:
            self.logger.error(f"Failed to create hash for class {cls.__name__}: {e}")
            return ""

