# ledger.py

import json
import hashlib
import logging
from datetime import datetime, timezone
from decimal import Decimal
from threading import Lock
import threading
import time
from typing import List, Dict, Optional, TYPE_CHECKING

# Use TYPE_CHECKING to prevent circular imports at runtime
if TYPE_CHECKING:
    from mempool import Mempool
    from dynamic_fee_calculator import DynamicFeeCalculator
    from consensus_engine import ConsensusEngine

# from consensus_engine import ConsensusEngine
from account_manager import AccountManager
from omc import OMC
from block import Block  # Import the Block class
from node import Node
from verifier import Verifier

class Ledger:
    """
    Manages the blockchain data structure with:
      - Concurrency locks
      - All-or-none transaction validation
      - Fork and chain reorganization handling
      - Rollback or block rejection strategies
      - Decentralized in-memory storage
      - MongoDB integration for persistent storage (optional)

    **Reward Distribution:**
      - Validator: Receives the majority of the block reward.
      - Miner: Receives a secondary portion of the block reward.
      - Treasury: Receives the least portion of the block reward.
    """

    def __init__(
        self,
        account_manager: AccountManager,
        omc: OMC,
        fee_calculator: 'DynamicFeeCalculator',
        consensus_engine: Optional['ConsensusEngine'] = None,
        mempool: Optional['Mempool'] = None,
        mongo_client=None,  # Added MongoDB client parameter
        auto_mine_interval: int = 9,  # Set to 9 minutes as per requirement
    ):
        """
        :param account_manager:   Manages user balances and staking.
        :param omc:               Coin logic (max supply, minting, etc.).
        :param fee_calculator:    DynamicFeeCalculator for handling transaction fees.
        :param consensus_engine: Reference to ConsensusEngine for consensus-specific operations.
        :param mempool:           A Mempool instance for unconfirmed transactions.
        :param mongo_client:      MongoDB client for persistent storage.
        :param auto_mine_interval: Time (minutes) for an optional background
                                     block production thread.
        """
        self.account_manager = account_manager
        self.omc = omc
        self.fee_calculator = fee_calculator
        self.consensus_engine = consensus_engine

        # Initialize Lock for thread-safe operations
        self.lock = Lock()

        # Initialize Mempool
        self.mempool = mempool
        if self.mempool:
            self.mempool.set_ledger(self)
        else:
            from mempool import Mempool  # Import here to prevent circular import
            self.mempool = Mempool(
                crypto_utils=None,  # Update accordingly if CryptoUtils is required
                fee_calculator=self.fee_calculator,
                max_size=1000,
                min_size=500,
                adjustment_interval=60,
                high_activity_threshold=100,
                low_activity_threshold=10,
                stale_time=3600
            )
            self.mempool.set_ledger(self)

        # Set auto_mine_interval early
        self.auto_mine_interval = auto_mine_interval  # Now correctly set

        # Initialize logger **before** calling methods that use it
        self.logger = logging.getLogger('Ledger')
        self.logger.info("Ledger initialized with decentralized in-memory storage.")

        # Initialize in-memory chain and block hashes
        self.chain: List[Block] = []
        self.block_hashes: set = set()

        # Initialize MongoDB client
        self.mongo_client = mongo_client
        if self.mongo_client:
            self.db = self.mongo_client["vault"]
            self.logger.info("MongoDB client initialized and connected to 'vault' database.")
        else:
            self.logger.warning("MongoDB client not provided. MongoDB integration is disabled.")

        # Initialize Node and Verifier
        self.node: Optional[Node] = None  # Will be set externally
        self.verifier: Optional[Verifier] = None  # Will be set externally

        # Initialize genesis block
        self._initialize_genesis_block()

        # Start the background mining thread
        self.mining_thread = threading.Thread(target=self._mine_new_block_periodically, daemon=True)
        self.mining_thread.start()

    # ----------------------------------------------------------------
    #  Genesis Block Initialization
    # ----------------------------------------------------------------
    def _initialize_genesis_block(self):
        """
        Creates the genesis block if the chain is empty.
        """
        if not self.chain:
            genesis_block = Block(
                index=0,
                timestamp=datetime.now(timezone.utc).isoformat(),
                previous_hash="0" * 64,
                transactions=[],
                signatures=[],
                merkle_root=self._compute_merkle_root([]),
                block_hash=self._compute_block_hash(0, "0" * 64, self._compute_merkle_root([])),
                leader=None,  # Genesis block may not have a leader
                proof_of_effort=None  # Genesis block may not have PoE
            )
            self.chain.append(genesis_block)
            self.block_hashes.add(genesis_block.hash)
            self.logger.info("[Ledger] Genesis block created.")

    # ----------------------------------------------------------------
    #  Periodic Block Production
    # ----------------------------------------------------------------
    def _mine_new_block_periodically(self):
        """
        A background thread that checks periodically if a block can be produced.
        PoS and PoE logic typically live in the consensus engine.
        This is a naive time-based trigger for demonstration.
        """
        while True:
            try:
                self._check_for_mining_opportunity()
                self.check_confirmations()  # Ensure this method exists
            except Exception as e:
                self.logger.error(f"[Ledger] Periodic mining error: {e}")
            time.sleep(self.auto_mine_interval * 60)

    def _check_for_mining_opportunity(self):
        """
        If there are verified transactions in mempool, initiate block production via ConsensusEngine.
        """
        num_verified = len(self.mempool.get_transactions())
        if num_verified > 0:
            self.logger.info(f"[Ledger] Found {num_verified} transactions. Initiating block production.")
            self.produce_block()
        else:
            self.logger.debug("[Ledger] No transactions available. Skipping block production.")

    # ----------------------------------------------------------------
    #  Block Production
    # ----------------------------------------------------------------
        def produce_block(self):
            """
            Gathers verified transactions from the mempool, uses the consensus engine
            to determine a validator and miner, builds a block, and attempts to append it to the chain.
            """
            # 1. Drain verified transactions
            transactions = self.mempool.drain_verified_transactions()
            if not transactions:
                self.logger.debug("[Ledger] No transactions to include. Aborting block creation.")
                return

            with self.lock:
                # 2. Let consensus generate randomness
                latest_block = self.get_latest_block()
                new_block = self._create_new_block(transactions, latest_block)

                randomness = self.consensus_engine.produce_randomness(new_block)
                if randomness is None:
                    self.logger.error("[Ledger] Failed to produce randomness. Aborting block creation.")
                    self.mempool.return_transactions(transactions)
                    return

                # 3. Select validator based on randomness
                selected_validator = self.consensus_engine.select_validator(randomness)
                if not selected_validator:
                    self.logger.error("[Ledger] No validator selected. Aborting block creation.")
                    self.mempool.return_transactions(transactions)
                    return

                self.logger.info(f"[Ledger] Selected validator: {selected_validator['address']}")

                # 4. Select miner based on randomness
                selected_miner = self.consensus_engine.select_miner(randomness)
                if not selected_miner:
                    self.logger.error("[Ledger] No miner selected. Aborting block creation.")
                    self.mempool.return_transactions(transactions)
                    return

                self.logger.info(f"[Ledger] Selected miner: {selected_miner['address']}")

                # 5. Collect signatures from validator and miner
                signatures_collected = self._collect_signatures(selected_validator, selected_miner, new_block)
                if not signatures_collected:
                    self.logger.error("[Ledger] Failed to collect required signatures. Aborting block creation.")
                    self.mempool.return_transactions(transactions)
                    return

                # 6. Verify signatures
                if not self.verifier.verify_signatures(new_block, new_block.signatures):
                    self.logger.error("[Ledger] Signature verification failed. Aborting block creation.")
                    self.mempool.return_transactions(transactions)
                    return

                # 7. Validate & add block
                if self._add_block(new_block):
                    self._finalize_block_transactions(new_block)
                    self.logger.info(f"[Ledger] Block {new_block.index} added with {len(transactions)} transactions.")
                else:
                    # Return transactions if block invalid
                    self.mempool.return_transactions(transactions)
                    
    def _collect_signatures(self, validator: Dict, miner: Dict, block: Block) -> bool:
        """
        Collects the validator's and miner's signatures for the block.

        :param validator: The validator's information dictionary.
        :param miner: The miner's information dictionary.
        :param block: The block to be signed.
        :return: True if both signatures are collected and verified, False otherwise.
        """
        try:
            # Serialize block data
            block_data = block.to_dict()

            # Validator signs the block
            validator_signature = self.node.sign_node_data(block_data)
            if not validator_signature:
                self.logger.error(f"Failed to collect signature from validator {validator['address']}.")
                return False

            # Miner signs the block
            miner_signature = self.node.sign_node_data(block_data)
            if not miner_signature:
                self.logger.error(f"Failed to collect signature from miner {miner['address']}.")
                return False

            # Append signatures to the block
            block.signatures.append({
                'validator_address': validator['address'],
                'signature': validator_signature
            })
            block.signatures.append({
                'miner_address': miner['address'],
                'signature': miner_signature
            })

            self.logger.debug(f"Collected signatures from validator {validator['address']} and miner {miner['address']}.")

            return True
        except Exception as e:
            self.logger.error(f"Error collecting signatures: {e}")
            return False
        
    # ----------------------------------------------------------------
    #  Creating & Adding a Block
    # ----------------------------------------------------------------
    def _create_new_block(self, transactions: List[Dict], latest_block: Optional[Block]) -> Block:
        """
        Constructs a new block with the given transactions and consensus data.

        :param transactions: List of transaction dictionaries.
        :param latest_block: The latest block in the current chain.
        :return: A new Block instance.
        """
        next_index = latest_block.index + 1 if latest_block else 0
        prev_hash = latest_block.hash if latest_block else "0" * 64

        merkle_root = self._compute_merkle_root(transactions)

        # Obtain leader and proof_of_effort from ConsensusEngine
        leader = self.consensus_engine.leader_pool[0] if self.consensus_engine.leader_pool else self.omc.treasury_address
        proof_of_effort = self.consensus_engine.vrf_outputs.get(leader, "")

        block = Block(
            index=next_index,
            previous_hash=prev_hash,
            transactions=transactions,
            signatures=[],  # Signatures will be added by the ConsensusEngine
            timestamp=datetime.now(timezone.utc).isoformat(),  # Correct timestamp format
            merkle_root=merkle_root,
            leader=leader,
            proof_of_effort=proof_of_effort
        )
        return block

    def _add_block(self, block: Block) -> bool:
        """
        Validates and adds the block to the chain if valid.
        Handles forks and chain reorganizations.

        :param block: The Block instance to add.
        :return: True if the block was added successfully, False otherwise.
        """
        if not self._validate_block_structure(block):
            self.logger.error("[Ledger] Block structure invalid.")
            return False

        if not self._validate_block_contents(block):
            self.logger.error("[Ledger] Block content invalid.")
            return False

        # Check if the block extends the current chain
        if self.chain and block.previous_hash != self.chain[-1].hash:
            self.logger.warning("[Ledger] Block does not extend the current chain. Possible fork detected.")
            # Attempt to handle fork by adopting a new chain
            return self._handle_fork(block)
        else:
            # Continuity check passed; append the block
            self.chain.append(block)
            self.block_hashes.add(block.hash)

            self.logger.info(f"[Ledger] Block {block.index} appended to the chain.")
            return True

    # ----------------------------------------------------------------
    #  Handling Forks and Chain Reorganizations
    # ----------------------------------------------------------------
    def _handle_fork(self, new_block: Block) -> bool:
        """
        Handles a fork by attempting to adopt a new chain if it's longer and valid.

        :param new_block: The new Block instance that doesn't extend the current chain.
        :return: True if the new chain was adopted, False otherwise.
        """
        self.logger.info("[Ledger] Attempting to handle a fork.")

        # Reconstruct the new chain from the new block backwards
        new_chain = [new_block]
        current_block = new_block

        while current_block.previous_hash != "0" * 64:
            # Attempt to fetch the previous block from the current chain
            prev_block = next((blk for blk in self.chain if blk.hash == current_block.previous_hash), None)
            if prev_block:
                new_chain.insert(0, prev_block)
                current_block = prev_block
            else:
                self.logger.error("[Ledger] Previous block not found in the current chain. Cannot reconstruct the new chain.")
                return False  # Cannot handle the fork without full chain

        # Validate the reconstructed chain
        if not self._validate_full_chain(new_chain):
            self.logger.error("[Ledger] New chain validation failed.")
            return False

        # Check if the new chain is longer than the current chain
        if len(new_chain) > len(self.chain):
            self.logger.info("[Ledger] New chain is longer. Adopting the new chain.")
            self.chain = new_chain.copy()
            self.block_hashes = {block.hash for block in self.chain}
            self.logger.info("[Ledger] Successfully adopted the new chain.")
            return True
        else:
            self.logger.info("[Ledger] New chain is not longer than the current chain. Ignoring the fork.")
            return False

    # ----------------------------------------------------------------
    #  Transaction Finalization (All-or-None)
    # ----------------------------------------------------------------
    def _finalize_block_transactions(self, block: Block) -> None:
        """
        Applies each transaction to the AccountManager.
        Mints block rewards and distributes them to the validator, miner, and treasury.
        Ensures that all transactions are applied atomically.

        :param block: The Block instance whose transactions are to be finalized.
        """
        total_fee = Decimal(0)

        try:
            for tx in block.transactions:
                sender = tx.get('sender')
                receiver = tx.get('receiver')
                amount = Decimal(tx.get('amount', '0'))
                fee = Decimal(tx.get('fee', '0'))

                # Validate sender's balance
                sender_balance = self.account_manager.get_account_balance(sender)
                if sender_balance < (amount + fee):
                    raise ValueError(f"Insufficient balance for sender {sender}.")

                # Debit sender
                self.account_manager.debit_account(sender, amount + fee)

                # Credit receiver
                self.account_manager.credit_account(receiver, amount)

                self.logger.debug(f"[Ledger] TX {tx['hash']} applied: {sender} -> {receiver} : {amount} OMC")

                total_fee += fee

            # Mint block reward based on total fees
            # Determine validator and miner
            validator_info = block.signatures[-1] if block.signatures else None
            validator_address = validator_info['validator_address'] if validator_info else self.omc.treasury_address

            # Select miner using ConsensusEngine
            miner_info = self.consensus_engine.select_miner()
            if not miner_info:
                self.logger.error("Failed to select a miner.")
                raise ValueError("No miner selected for block reward distribution.")

            miner_address = miner_info['address']

            # Mint rewards
            minted = self.omc.mint_for_block_fee(
                total_fee=total_fee,
                current_block_height=block.index,
                validator_address=validator_address,
                miner_address=miner_address
            )

            self.logger.info(
                f"[Ledger] Minted rewards: {minted['validator']} OMC to validator, "
                f"{minted['miner']} OMC to miner, and {minted['treasury']} OMC to treasury."
            )

        except Exception as e:
            self.logger.error(f"[Ledger] Transaction finalization failed for block {block.index}: {e}")
            # In a real-world scenario, implement rollback mechanisms if necessary
            raise e
                
    # ----------------------------------------------------------------
    #  Validation
    # ----------------------------------------------------------------
    def _validate_block_structure(self, block: Block) -> bool:
        """
        Ensures that the block contains all required fields.

        :param block: The Block instance to validate.
        :return: True if the structure is valid, False otherwise.
        """
        required_fields = [
            "index", "timestamp", "previous_hash",
            "transactions", "signatures", "merkle_root", "hash"
        ]
        block_dict = block.to_dict()
        for field in required_fields:
            if field not in block_dict:
                self.logger.error(f"[Ledger] Missing field in block: {field}")
                return False
        return True

    def _validate_block_contents(self, block: Block) -> bool:
        """
        Validates the block's hash, merkle root, and signatures.

        :param block: The Block instance to validate.
        :return: True if the contents are valid, False otherwise.
        """
        # 1. Recompute hash
        original_hash = block.hash
        recalculated = block.compute_hash()
        if original_hash != recalculated:
            self.logger.error("[Ledger] Block hash mismatch.")
            return False

        # 2. Recompute Merkle root
        recalculated_root = block.compute_merkle_root()
        if recalculated_root != block.merkle_root:
            self.logger.error("[Ledger] Merkle root mismatch.")
            return False

        # 3. Verify Signatures via Verifier
        if not self.verifier.verify_signatures(block, block.signatures):
            self.logger.error("[Ledger] Block signatures invalid.")
            return False

        # 4. Validate Transactions Before Finalization
        # Ensure that all transactions are valid and can be applied
        # This step can be expanded based on specific transaction rules
        for tx in block.transactions:
            sender = tx.get('sender')
            receiver = tx.get('receiver')
            amount = Decimal(tx.get('amount', '0'))
            fee = Decimal(tx.get('fee', '0'))

            sender_balance = self.account_manager.get_account_balance(sender)
            if sender_balance < (amount + fee):
                self.logger.error(f"[Ledger] Transaction {tx['hash']} invalid: insufficient balance for sender {sender}.")
                return False

        return True

    # ----------------------------------------------------------------
    #  Chain Validation
    # ----------------------------------------------------------------
    def validate_full_chain(self, chain_data: List[Dict]) -> bool:
        """
        Validates an entire chain provided as a list of block dictionaries.

        :param chain_data: List of block dictionaries.
        :return: True if the chain is valid, False otherwise.
        """
        chain = [Block.from_dict(block_dict) for block_dict in chain_data]
        return self._validate_full_chain(chain)

    def _validate_full_chain(self, chain: List[Block]) -> bool:
        """
        Validates an entire chain to ensure its integrity.

        :param chain: List of Block instances representing the chain.
        :return: True if the chain is valid, False otherwise.
        """
        if not chain:
            self.logger.error("[Ledger] Empty chain cannot be validated.")
            return False

        for i, block in enumerate(chain):
            # Validate block structure
            if not self._validate_block_structure(block):
                self.logger.error(f"[Ledger] Block structure invalid at index {block.index}.")
                return False

            # Validate block contents
            if not self._validate_block_contents(block):
                self.logger.error(f"[Ledger] Block contents invalid at index {block.index}.")
                return False

            # Validate continuity
            if i > 0:
                prev_block = chain[i - 1]
                if block.previous_hash != prev_block.hash:
                    self.logger.error(f"[Ledger] Continuity error between block {prev_block.index} and block {block.index}.")
                    return False

        self.logger.info("[Ledger] Full chain validation passed.")
        return True

    def adopt_new_chain(self, chain_data: List[Dict]) -> bool:
        """
        Attempts to adopt a new chain if it's longer and valid.

        :param chain_data: List of block dictionaries representing the new chain.
        :return: True if the new chain was adopted, False otherwise.
        """
        chain = [Block.from_dict(block_dict) for block_dict in chain_data]

        with self.lock:
            if self._validate_full_chain(chain):
                if len(chain) > len(self.chain):
                    self.logger.info("[Ledger] New chain is longer. Adopting the new chain.")
                    self.chain = chain.copy()
                    self.block_hashes = {block.hash for block in self.chain}
                    self.logger.info("[Ledger] Successfully adopted the new chain.")
                    return True
                else:
                    self.logger.info("[Ledger] New chain is not longer than the current chain.")
                    return False
            else:
                self.logger.error("[Ledger] New chain validation failed.")
                return False

    # ----------------------------------------------------------------
    #  Additional Helper Methods
    # ----------------------------------------------------------------
    def _compute_merkle_root(self, transactions: List[Dict]) -> str:
        """
        Computes the Merkle root of the given transactions.

        :param transactions: List of transaction dictionaries.
        :return: Merkle root as a hexadecimal string.
        """
        hashes = [tx['hash'] for tx in transactions]
        if not hashes:
            return hashlib.sha256("".encode()).hexdigest()

        while len(hashes) > 1:
            if len(hashes) % 2 != 0:
                hashes.append(hashes[-1])  # Duplicate last hash if odd number

            new_hashes = []
            for i in range(0, len(hashes), 2):
                combined = hashes[i] + hashes[i + 1]
                new_hash = hashlib.sha256(combined.encode()).hexdigest()
                new_hashes.append(new_hash)
            hashes = new_hashes

        return hashes[0]

    def _compute_block_hash(self, index: int, previous_hash: str, merkle_root: str) -> str:
        """
        Computes the hash of a block based on its contents.

        :param index: The index of the block.
        :param previous_hash: The hash of the previous block.
        :param merkle_root: The Merkle root of the block's transactions.
        :return: The computed block hash as a hexadecimal string.
        """
        block_string = f"{index}{previous_hash}{merkle_root}{datetime.now(timezone.utc).isoformat()}"
        return hashlib.sha256(block_string.encode()).hexdigest()

    # ----------------------------------------------------------------
    #  Retrieving a Block by Hash and Index
    # ----------------------------------------------------------------
    def get_block_by_hash(self, block_hash: str) -> Optional[Block]:
        """
        Public method to retrieve a block by its hash.

        :param block_hash: The hash of the block to retrieve.
        :return: Block instance if found, else None.
        """
        with self.lock:
            return next((blk for blk in self.chain if blk.hash == block_hash), None)

    def get_block_by_index(self, block_index: int) -> Optional[Block]:
        """
        Public method to retrieve a block by its index.

        :param block_index: The index of the block to retrieve.
        :return: Block instance if found, else None.
        """
        with self.lock:
            return next((blk for blk in self.chain if blk.index == block_index), None)

    def get_latest_block(self) -> Optional[Block]:
        """
        Retrieves the latest block in the chain.

        :return: The latest Block instance, or None if the chain is empty.
        """
        with self.lock:
            if self.chain:
                return self.chain[-1]
            return None

    # ----------------------------------------------------------------
    #  Signature Management
    # ----------------------------------------------------------------
    def record_block_signatures(self, block_index: int, signatures: List[Dict[str, str]]) -> None:
        """
        Stores signatures associated with a specific block index on-chain.

        :param block_index: The index of the block being signed.
        :param signatures: List of dictionaries containing 'validator_address' and 'signature'.
        """
        with self.lock:
            block = self.get_block_by_index(block_index)
            if not block:
                self.logger.error(f"[Ledger] Cannot record signatures. Block {block_index} not found.")
                return

            unique_signatures = 0
            for sig in signatures:
                if any(existing_sig['validator_address'] == sig['validator_address'] for existing_sig in block.signatures):
                    self.logger.warning(f"[Ledger] Validator {sig['validator_address']} has already signed block {block_index}. Skipping duplicate.")
                    continue
                block.signatures.append(sig)
                unique_signatures += 1

            self.logger.info(f"[Ledger] Recorded {unique_signatures} unique signatures for block {block_index} on-chain.")

    def get_block_signatures(self, block_index: int) -> List[Dict[str, str]]:
        """
        Retrieves all signatures associated with a specific block index.

        :param block_index: The index of the block whose signatures are to be retrieved.
        :return: List of dictionaries containing 'validator_address' and 'signature'.
        """
        with self.lock:
            block = self.get_block_by_index(block_index)
            if block:
                return block.signatures
            return []

    # ----------------------------------------------------------------
    #  Check Confirmations
    # ----------------------------------------------------------------
    def check_confirmations(self):
        """
        Placeholder method to check block confirmations.
        Implement logic as per your blockchain's requirements.
        """
        # Example: Verify that the latest block has the required number of confirmations
        required_confirmations = 3  # Example threshold
        latest_block = self.get_latest_block()
        if latest_block and latest_block.index < required_confirmations:
            self.logger.debug(f"[Ledger] Block {latest_block.index} has insufficient confirmations.")
            return False
        if latest_block:
            self.logger.debug(f"[Ledger] Block {latest_block.index} has sufficient confirmations.")
            return True
        self.logger.debug("[Ledger] No blocks available to check confirmations.")
        return False

    # ----------------------------------------------------------------
    #  Graceful Shutdown
    # ----------------------------------------------------------------
    def shutdown(self):
        """
        Gracefully shuts down the ledger.
        """
        self.logger.info("Shutting down Ledger.")
        # If there were persistent storage mechanisms, close connections here
        # Since we're using in-memory storage and MongoDB is managed externally, no action is required
        self.logger.info("Ledger shutdown completed.")
