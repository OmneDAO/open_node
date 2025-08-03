from datetime import datetime, timezone
import logging
from decimal import Decimal
from threading import RLock
from typing import List, Dict, Optional, TYPE_CHECKING
import hashlib

if TYPE_CHECKING:
    from mempool import Mempool
    from dynamic_fee_calculator import DynamicFeeCalculator
    from consensus_engine import ConsensusEngine

from account_manager import AccountManager
from omc import OMC
from block import Block
from node import Node
from verifier import Verifier
from staking import StakingMngr
from staked_omc import StakedOMC
from crypto_utils import CryptoUtils

logger = logging.getLogger('Ledger')


class Ledger:
    """
    Manages the blockchain data structure with:
      - Concurrency locks (RLock),
      - Atomic transaction finalization,
      - Fork and chain reorganization handling,
      - Full chain validation and adoption,
      - (Optionally) MongoDB persistence.

    Concurrency:
      - This class uses a single RLock (self.lock). 
      - The Mempool also has its own lock (mempool.lock).
      - We adopt the rule:
          "Acquire ledger.lock before calling into mempool methods."
        so we do not attempt to hold mempool.lock first and then ledger.lock.
    """

    def __init__(
        self,
        account_manager: AccountManager,
        omc: OMC,
        fee_calculator: 'DynamicFeeCalculator',
        consensus_engine: Optional['ConsensusEngine'] = None,
        mempool: Optional['Mempool'] = None,
        mongo_client=None,
        crypto_utils: Optional[CryptoUtils] = None
    ):
        self.account_manager = account_manager
        self.omc = omc
        self.fee_calculator = fee_calculator
        self.consensus_engine = consensus_engine
        self.crypto_utils = crypto_utils

        # Use an RLock so that the same thread can safely re-acquire if needed
        self.lock = RLock()

        # Initialize Mempool (create one if not provided)
        self.mempool = mempool
        if self.mempool:
            self.mempool.set_ledger(self)
        else:
            # If not provided, create a new Mempool with default parameters
            from mempool import Mempool
            self.mempool = Mempool(
                account_manager=self.account_manager,
                fee_calculator=self.fee_calculator,
                max_size=1000,
                min_size=500,
                adjustment_interval=60,
                high_activity_threshold=100,
                low_activity_threshold=10,
                stale_time=3600
            )
            self.mempool.set_ledger(self)

        self.logger = logging.getLogger('Ledger')
        self.logger.info("Ledger initialized with decentralized in-memory storage.")

        self.chain: List[Block] = []
        self.block_hashes: set = set()

        # Optional MongoDB usage
        self.mongo_client = mongo_client
        if self.mongo_client:
            self.db = self.mongo_client["vault"]
            self.logger.info("MongoDB client initialized and connected to 'vault' database.")
        else:
            self.logger.warning("MongoDB client not provided. MongoDB integration is disabled.")

        # Node + Verifier references
        self.node: Optional[Node] = None
        self.verifier: Optional[Verifier] = None

        # Staking manager / sOMC
        self.staked_omc = StakedOMC(account_manager=self.account_manager)
        self.staking_manager = StakingMngr(
            omc=self.omc,
            account_manager=self.account_manager,
            staked_omc=self.staked_omc
        )

        # Optionally auto-create a genesis block
        # self._initialize_genesis_block()

    # ----------------------------------------------------------------
    #  Genesis Block Initialization
    # ----------------------------------------------------------------
    def _initialize_genesis_block(self):
        """
        Creates the genesis block if the chain is empty.
        This is optional and depends on your flow.
        """
        if not self.chain:
            genesis_block = Block(
                index=0,
                timestamp=datetime.now(timezone.utc).isoformat(),
                previous_hash="0" * 64,
                transactions=[],
                signatures=[],
                merkle_root=self._compute_merkle_root([]),
                block_hash="0000000000000000000000000000000000000000000000000000000000000000",
                leader=None,
                proof_of_effort=None
            )
            self.chain.append(genesis_block)
            self.block_hashes.add(genesis_block.hash)
            self.logger.info("[Ledger] Genesis block created.")

    # ----------------------------------------------------------------
    #  Block Addition and Finalization
    # ----------------------------------------------------------------
    def add_block(self, block: Block) -> bool:
        """
        Adds a new block to the chain after validating its structure and contents.
        Also removes the block's transactions from the mempool if added successfully.
        """
        with self.lock:
            # Validate structure & contents
            if not self._validate_block_structure(block):
                self.logger.error("[Ledger] Block structure invalid.")
                return False

            if not self._validate_block_contents(block):
                self.logger.error("[Ledger] Block content invalid.")
                return False

            # Check continuity: new block's previous_hash must match last block's hash
            if self.chain and block.previous_hash != self.chain[-1].hash:
                self.logger.warning("[Ledger] Block does not extend the current chain. Possible fork.")
                return self.adopt_new_chain([b.to_dict() for b in self.chain] + [block.to_dict()])
            else:
                # Append to chain
                self.chain.append(block)
                self.block_hashes.add(block.hash)
                self.logger.info(f"[Ledger] Block {block.index} appended to the chain.")

                # Now that we've appended the block, remove those TXs from mempool
                if self.mempool:
                    # Remove these transactions by hash
                    self.logger.debug("[Ledger] Removing block's transactions from mempool by hash.")
                    self.mempool.remove_transactions(block.transactions)

                return True

    def validate_block(self, block: Block) -> bool:
        """
        Checks whether a block is well-formed (structure + contents).
        """
        return self._validate_block_structure(block) and self._validate_block_contents(block)

    def finalize_block(self, block: Block) -> bool:
        """
        Applies block transactions atomically (debit/credit accounts) and mints rewards.
        Called AFTER the block has been appended to the chain, typically.
        Returns True if finalization was successful, False otherwise.
        """
        try:
            with self.lock:
                self.logger.info(
                    f"[Ledger] Finalizing block {block.index} with {len(block.transactions)} transactions."
                )
                self._finalize_block_transactions(block)
            return True
        except Exception as e:
            self.logger.error(f"Block finalization failed: {e}")
            return False

    # ----------------------------------------------------------------
    #  Fork Handling and Chain Adoption
    # ----------------------------------------------------------------
    def adopt_new_chain(self, chain_data: List[Dict]) -> bool:
        """
        Attempts to adopt a new chain from peer data if it is longer and valid.
        """
        try:
            candidate_chain = [Block.from_dict(bdict) for bdict in chain_data]
            if self.validate_full_chain(chain_data) and len(candidate_chain) > len(self.chain):
                with self.lock:
                    self.chain = candidate_chain.copy()
                    self.block_hashes = {block.hash for block in self.chain}
                    self.logger.info("[Ledger] New candidate chain adopted successfully.")
                    # Optionally, you might want to re-check mempool for conflicts and remove them
                    return True
            else:
                self.logger.info("[Ledger] Candidate chain is not longer than the current chain; adoption rejected.")
                return False
        except Exception as e:
            self.logger.error(f"[Ledger] Exception during chain adoption: {e}")
            return False

    def validate_full_chain(self, chain_data: List[Dict]) -> bool:
        """
        Validates an entire candidate chain given as a list of block dictionaries.
        """
        try:
            candidate_chain = [Block.from_dict(bdict) for bdict in chain_data]
            if not candidate_chain:
                self.logger.error("[Ledger] Candidate chain is empty.")
                return False

            for i, block in enumerate(candidate_chain):
                if not self._validate_block_structure(block):
                    self.logger.error(f"[Ledger] Block structure invalid at index {block.index}.")
                    return False
                if not self._validate_block_contents(block):
                    self.logger.error(f"[Ledger] Block contents invalid at index {block.index}.")
                    return False
                if i > 0:
                    prev_block = candidate_chain[i - 1]
                    if block.previous_hash != prev_block.hash:
                        self.logger.error(
                            f"[Ledger] Chain continuity error between block {prev_block.index} and block {block.index}."
                        )
                        return False

            self.logger.info("[Ledger] Candidate chain validated successfully.")
            return True
        except Exception as e:
            self.logger.error(f"[Ledger] Exception during full chain validation: {e}")
            return False

    # ----------------------------------------------------------------
    #  Block Transaction Finalization
    # ----------------------------------------------------------------
    def _finalize_block_transactions(self, block: Block) -> None:
        """
        Actually modifies account balances for each TX in this block, then mints block rewards.
        """
        total_fee = Decimal(0)
        try:
            # For each transaction, debit sender & credit receiver
            for tx in block.transactions:
                sender = tx.get('sender')
                receiver = tx.get('receiver')
                amount = Decimal(tx.get('amount', '0'))
                fee = Decimal(tx.get('fee', '0'))

                sender_balance = self.account_manager.get_account_balance(sender)
                if sender_balance < (amount + fee):
                    raise ValueError(f"Insufficient balance for sender {sender}.")

                self.account_manager.debit_account(sender, amount + fee)
                # If no 'receiver' was set (for example, 'account_creation'), that might be a no-op
                if receiver:
                    self.account_manager.credit_account(receiver, amount)

                total_fee += fee
                self.logger.debug(
                    f"[Ledger] Finalized TX {tx['hash']} from {sender} -> {receiver}: {amount} OMC"
                )

            # Reward logic
            validator_info = block.signatures[-1] if block.signatures else None
            validator_address = self.omc.treasury_address
            if validator_info and isinstance(validator_info, dict):
                validator_address = validator_info.get('validator_address', self.omc.treasury_address)

            miner_address = self.omc.treasury_address
            if self.consensus_engine and hasattr(self.consensus_engine, 'select_miner'):
                miner_info = self.consensus_engine.select_miner() or {}
                miner_address = miner_info.get('address', self.omc.treasury_address)

            minted = self.omc.mint_for_block_fee(
                total_fee=total_fee,
                current_block_height=block.index,
                validator_address=validator_address,
                miner_address=miner_address
            )
            self.logger.info(
                f"[Ledger] Minted rewards for block {block.index}: "
                f"validator {minted['validator']} OMC, miner {minted['miner']} OMC, "
                f"treasury {minted['treasury']} OMC."
            )

        except Exception as e:
            self.logger.error(f"[Ledger] Error finalizing block {block.index}: {e}")
            raise e

    # ----------------------------------------------------------------
    #  Block Validation Helpers
    # ----------------------------------------------------------------
    def _validate_block_structure(self, block: Block) -> bool:
        required_fields = [
            "index", "timestamp", "previous_hash",
            "transactions", "signatures", "merkle_root", "hash"
        ]
        block_dict = block.to_dict()
        for field in required_fields:
            if field not in block_dict:
                self.logger.error(f"[Ledger] Block missing required field '{field}'.")
                return False
        return True

    def _validate_block_contents(self, block: Block) -> bool:
        """
        Verifies block hash, merkle root, signatures, and ensures 
        sender balances are sufficient for each transaction.
        """
        original_hash = block.hash
        # 1) Check if block hash is correct
        if block.compute_hash() != original_hash:
            self.logger.error("[Ledger] Block hash mismatch.")
            return False

        # 2) Check if merkle root is correct
        if block.compute_merkle_root() != block.merkle_root:
            self.logger.error("[Ledger] Merkle root mismatch.")
            return False

        # 3) Verify the block signatures via the Verifier
        if self.verifier and not self.verifier.verify_transactions(block, block.signatures):
            self.logger.error("[Ledger] Block signatures invalid.")
            return False

        # 4) Check each TX for sufficient funds
        for tx in block.transactions:
            sender = tx.get('sender')
            amount = Decimal(tx.get('amount', '0'))
            fee = Decimal(tx.get('fee', '0'))
            bal = self.account_manager.get_account_balance(sender)
            if bal < (amount + fee):
                self.logger.error(f"[Ledger] TX {tx['hash']} invalid; sender {sender} has insufficient funds.")
                return False

        return True

    # ----------------------------------------------------------------
    #  Utility Methods for Block Data
    # ----------------------------------------------------------------
    def get_latest_block(self) -> Optional[Block]:
        """
        Returns the last block in the chain or None if chain is empty.
        """
        with self.lock:
            return self.chain[-1] if self.chain else None

    def _compute_merkle_root(self, transactions: List[Dict]) -> str:
        """
        Simple method to compute Merkle root from TX['hash'] fields.
        """
        if not transactions:
            return hashlib.sha256(b"").hexdigest()
        leaves = [tx['hash'] for tx in transactions if 'hash' in tx]
        if not leaves:
            return hashlib.sha256(b"").hexdigest()

        # Pairwise hashing
        while len(leaves) > 1:
            if len(leaves) % 2 != 0:
                leaves.append(leaves[-1])
            new_level = []
            for i in range(0, len(leaves), 2):
                combined = leaves[i] + leaves[i+1]
                new_level.append(hashlib.sha256(combined.encode()).hexdigest())
            leaves = new_level

        return leaves[0]

    def shutdown(self):
        """
        Gracefully shuts down. If you have a separate DB or Mempool thread, 
        do the appropriate cleanup here.
        """
        self.logger.info("Shutting down Ledger.")
        # e.g. flush chain state to DB
        if self.mempool:
            self.mempool.shutdown()
        self.logger.info("Ledger shutdown complete.")
