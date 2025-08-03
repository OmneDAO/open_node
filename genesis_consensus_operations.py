"""
Genesis Consensus Operations - Network Formation and Broadcasting

This module handles genesis-specific consensus operations including:
- Network formation and initial validator setup
- Block broadcasting and synchronization
- Single-validator mode for testing
- Validator set management during bootstrap
"""

import asyncio
import logging
import threading
import time
from typing import List, Dict, Optional, Any
from datetime import datetime, timezone


class GenesisConsensusOperations:
    """
    Handles genesis-specific consensus operations that are not part of
    the core consensus algorithms. This includes network formation,
    broadcasting, and initial validator setup.
    """

    def __init__(
        self,
        consensus_core,
        network_manager,
        ledger,
        mempool,
        crypto_utils,
        vrf_utils,
        is_genesis_node: bool = False
    ):
        """
        Initialize genesis consensus operations.
        
        Args:
            consensus_core: The core consensus engine
            network_manager: Network management component
            ledger: Blockchain ledger
            mempool: Transaction mempool
            crypto_utils: Cryptographic utilities
            vrf_utils: VRF utilities
            is_genesis_node: Whether this is a genesis node
        """
        self.consensus_core = consensus_core
        self.network_manager = network_manager
        self.ledger = ledger
        self.mempool = mempool
        self.crypto_utils = crypto_utils
        self.vrf_utils = vrf_utils
        self.is_genesis_node = is_genesis_node

        # Genesis-specific state
        self.single_validator_mode = False
        self.bootstrap_completed = False
        self.initial_validators = []
        self.genesis_lock = threading.Lock()
        
        # Broadcasting state
        self.broadcast_queue = asyncio.Queue()
        self.block_broadcast_history = {}
        
        # Logger
        self.logger = logging.getLogger('GenesisConsensusOps')
        self.logger.setLevel(logging.INFO)
        handler = logging.StreamHandler()
        formatter = logging.Formatter('[%(asctime)s] [%(levelname)s] [%(name)s] %(message)s')
        handler.setFormatter(formatter)
        if not self.logger.handlers:
            self.logger.addHandler(handler)

        self.logger.info(f"GenesisConsensusOperations initialized (genesis_node: {is_genesis_node})")

    def start(self):
        """Start the genesis consensus operations."""
        self.consensus_core.running = True
        
        if self.is_genesis_node:
            self.logger.info("Starting as genesis node")
            self._initialize_genesis_network()
        else:
            self.logger.info("Starting as validator node")
            self._join_existing_network()

    def stop(self):
        """Stop the consensus engine."""
        self.consensus_core.running = False
        self.logger.info("Genesis consensus operations stopped")

    def _initialize_genesis_network(self):
        """Initialize the network as a genesis node."""
        with self.genesis_lock:
            self.single_validator_mode = True
            self.bootstrap_completed = False
            
            # Set initial validator set to just this node
            self.consensus_core.update_validator_set([self.consensus_core.validator_id])
            
            self.logger.info("Genesis network initialized in single-validator mode")
            
            # Start consensus loop
            threading.Thread(target=self._genesis_consensus_loop, daemon=True).start()

    def _join_existing_network(self):
        """Join an existing network as a validator."""
        self.logger.info("Attempting to join existing network")
        
        # Start by trying to sync with network
        self._sync_with_network()
        
        # Start consensus loop
        threading.Thread(target=self._validator_consensus_loop, daemon=True).start()

    def _genesis_consensus_loop(self):
        """Main consensus loop for genesis node."""
        self.logger.info("Starting genesis consensus loop")
        
        while self.consensus_core.running:
            try:
                # In single validator mode, we can create blocks immediately
                if self.single_validator_mode:
                    self._create_single_validator_block()
                    time.sleep(60)  # Wait before next block
                else:
                    # Full consensus mode
                    self._run_full_consensus_round()
                    
            except Exception as e:
                self.logger.error(f"Error in genesis consensus loop: {e}")
                time.sleep(5)

    def _validator_consensus_loop(self):
        """Main consensus loop for validator nodes."""
        self.logger.info("Starting validator consensus loop")
        
        while self.consensus_core.running:
            try:
                self._run_full_consensus_round()
            except Exception as e:
                self.logger.error(f"Error in validator consensus loop: {e}")
                time.sleep(5)

    def _create_single_validator_block(self):
        """Create a block in single validator mode."""
        try:
            # Get pending transactions
            transactions = self.mempool.get_pending_transactions(limit=100)
            
            if not transactions:
                self.logger.debug("No pending transactions for single validator block")
                return
            
            # Create block
            previous_hash = self.ledger.get_latest_block_hash()
            block_number = self.ledger.get_current_block_number() + 1
            timestamp = datetime.now(timezone.utc).isoformat()
            
            # In single validator mode, we don't need VRF consensus
            block_data = {
                'block_number': block_number,
                'previous_hash': previous_hash,
                'timestamp': timestamp,
                'transactions': [tx.to_dict() for tx in transactions],
                'validator': self.consensus_core.validator_id,
                'consensus_mode': 'single_validator'
            }
            
            # Create merkle root
            merkle_root = self.crypto_utils.create_merkle_root(
                [tx.get_hash() for tx in transactions]
            )
            block_data['merkle_root'] = merkle_root
            
            # Create block hash
            block_hash = self.crypto_utils.hash_block(block_data)
            block_data['hash'] = block_hash
            
            # Add block to ledger
            success = self.ledger.add_block(block_data)
            if success:
                # Remove transactions from mempool
                for tx in transactions:
                    self.mempool.remove_transaction(tx.transaction_id)
                
                self.logger.info(f"Created single validator block {block_number} with {len(transactions)} transactions")
                
                # Broadcast to any connected peers
                self._broadcast_block(block_data)
            else:
                self.logger.error("Failed to add single validator block to ledger")
                
        except Exception as e:
            self.logger.error(f"Error creating single validator block: {e}")

    def _run_full_consensus_round(self):
        """Run a full consensus round with multiple validators."""
        try:
            round_number = self.consensus_core.start_new_round()
            self.logger.info(f"Starting consensus round {round_number}")
            
            # Phase 1: VRF Commit Phase
            self._run_vrf_commit_phase()
            
            # Phase 2: VRF Reveal Phase
            self._run_vrf_reveal_phase()
            
            # Phase 3: Leader Selection
            leaders = self._select_round_leaders()
            
            # Phase 4: Block Proposal
            if self.consensus_core.validator_id in leaders:
                self._propose_block()
            
            # Phase 5: Block Voting
            self._participate_in_voting()
            
            # Phase 6: Block Finalization
            self._finalize_round()
            
        except Exception as e:
            self.logger.error(f"Error in consensus round: {e}")

    def _run_vrf_commit_phase(self):
        """Run the VRF commit phase."""
        self.consensus_core.advance_phase(self.consensus_core.ConsensusPhase.COMMIT)
        
        # Generate and broadcast VRF commit
        proof, alpha = self.consensus_core.generate_vrf_commit(self.vrf_utils)
        
        # Broadcast commit to network
        commit_message = {
            'type': 'vrf_commit',
            'round': self.consensus_core.current_round,
            'validator_id': self.consensus_core.validator_id,
            'proof': proof.hex(),
            'alpha': alpha.hex()
        }
        self._broadcast_message(commit_message)
        
        # Wait for commits or timeout
        timeout_time = time.time() + 30
        while (time.time() < timeout_time and 
               len(self.consensus_core.vrf_commits) < self.consensus_core.required_commits):
            time.sleep(0.1)

    def _run_vrf_reveal_phase(self):
        """Run the VRF reveal phase."""
        self.consensus_core.advance_phase(self.consensus_core.ConsensusPhase.REVEAL)
        
        # Broadcast VRF reveal
        reveal = self.consensus_core.get_vrf_reveal(self.consensus_core.current_round)
        if reveal:
            reveal_message = {
                'type': 'vrf_reveal',
                'round': self.consensus_core.current_round,
                'validator_id': self.consensus_core.validator_id,
                'proof': reveal['proof'].hex(),
                'alpha': reveal['alpha'].hex()
            }
            self._broadcast_message(reveal_message)
        
        # Wait for reveals or timeout
        timeout_time = time.time() + 30
        while (time.time() < timeout_time and 
               len(self.consensus_core.vrf_reveals) < self.consensus_core.required_reveals):
            time.sleep(0.1)

    def _select_round_leaders(self) -> List[str]:
        """Select leaders for the current round."""
        # Aggregate VRF randomness
        randomness = self.consensus_core.aggregate_randomness(self.consensus_core.current_round)
        
        if not randomness:
            self.logger.warning("No randomness available for leader selection")
            return []
        
        # Get stake weights (simplified - in practice would query from ledger)
        stake_weights = {validator_id: 1.0 for validator_id in self.consensus_core.validator_set}
        
        # Select leaders based on VRF and stake
        leaders = self.consensus_core.select_leaders(stake_weights)
        
        self.logger.info(f"Selected leaders for round {self.consensus_core.current_round}: {leaders}")
        return leaders

    def _propose_block(self):
        """Propose a block as a leader."""
        try:
            self.logger.info("Proposing block as leader")
            
            # Get pending transactions
            transactions = self.mempool.get_pending_transactions(limit=100)
            
            # Create block proposal
            previous_hash = self.ledger.get_latest_block_hash()
            block_number = self.ledger.get_current_block_number() + 1
            timestamp = datetime.now(timezone.utc).isoformat()
            
            block_data = {
                'block_number': block_number,
                'previous_hash': previous_hash,
                'timestamp': timestamp,
                'transactions': [tx.to_dict() for tx in transactions],
                'validator': self.consensus_core.validator_id,
                'round': self.consensus_core.current_round,
                'vrf_proof': self.consensus_core.vrf_reveals.get(self.consensus_core.validator_id, {}).get('proof', b'').hex()
            }
            
            # Create merkle root
            merkle_root = self.crypto_utils.create_merkle_root(
                [tx.get_hash() for tx in transactions]
            )
            block_data['merkle_root'] = merkle_root
            
            # Create block hash
            block_hash = self.crypto_utils.hash_block(block_data)
            block_data['hash'] = block_hash
            
            # Store as pending block
            self.consensus_core.pending_block = block_data
            
            # Broadcast block proposal
            proposal_message = {
                'type': 'block_proposal',
                'round': self.consensus_core.current_round,
                'block': block_data
            }
            self._broadcast_message(proposal_message)
            
        except Exception as e:
            self.logger.error(f"Error proposing block: {e}")

    def _participate_in_voting(self):
        """Participate in block voting."""
        if not self.consensus_core.pending_block:
            self.logger.warning("No pending block to vote on")
            return
        
        # Verify the pending block
        is_valid = self._verify_block(self.consensus_core.pending_block)
        
        # Cast vote
        vote_message = {
            'type': 'block_vote',
            'round': self.consensus_core.current_round,
            'block_hash': self.consensus_core.pending_block['hash'],
            'vote': 'approve' if is_valid else 'reject',
            'validator_id': self.consensus_core.validator_id
        }
        self._broadcast_message(vote_message)
        
        # Wait for votes
        timeout_time = time.time() + 30
        while (time.time() < timeout_time and 
               len(self.consensus_core.block_votes) < self.consensus_core.required_votes):
            time.sleep(0.1)

    def _finalize_round(self):
        """Finalize the consensus round."""
        if not self.consensus_core.pending_block:
            self.logger.warning("No pending block to finalize")
            return
        
        # Count votes
        approve_votes = sum(1 for vote in self.consensus_core.block_votes.values() 
                          if vote.get('vote') == 'approve')
        
        if approve_votes >= self.consensus_core.required_votes:
            # Block approved - add to ledger
            success = self.ledger.add_block(self.consensus_core.pending_block)
            if success:
                # Remove transactions from mempool
                for tx_data in self.consensus_core.pending_block['transactions']:
                    self.mempool.remove_transaction(tx_data['transaction_id'])
                
                self.logger.info(f"Block {self.consensus_core.pending_block['block_number']} finalized and added to ledger")
                
                # Broadcast finalized block
                self._broadcast_block(self.consensus_core.pending_block)
            else:
                self.logger.error("Failed to add approved block to ledger")
        else:
            self.logger.warning(f"Block rejected - only {approve_votes} approval votes out of {self.consensus_core.required_votes} required")

    def _verify_block(self, block: Dict) -> bool:
        """Verify a proposed block."""
        try:
            # Basic block validation
            if not all(key in block for key in ['block_number', 'previous_hash', 'timestamp', 'transactions']):
                return False
            
            # Verify previous hash
            if block['previous_hash'] != self.ledger.get_latest_block_hash():
                return False
            
            # Verify block number
            if block['block_number'] != self.ledger.get_current_block_number() + 1:
                return False
            
            # Verify transactions
            for tx_data in block['transactions']:
                if not self._verify_transaction(tx_data):
                    return False
            
            return True
            
        except Exception as e:
            self.logger.error(f"Error verifying block: {e}")
            return False

    def _verify_transaction(self, tx_data: Dict) -> bool:
        """Verify a transaction in a block."""
        # Basic transaction validation
        return all(key in tx_data for key in ['transaction_id', 'from_address', 'to_address', 'amount'])

    def _broadcast_message(self, message: Dict):
        """Broadcast a message to the network."""
        try:
            if self.network_manager:
                self.network_manager.broadcast_message(message)
            else:
                self.logger.debug(f"No network manager available for broadcasting: {message['type']}")
        except Exception as e:
            self.logger.error(f"Error broadcasting message: {e}")

    def _broadcast_block(self, block: Dict):
        """Broadcast a finalized block to the network."""
        try:
            # Store in broadcast history
            self.block_broadcast_history[block['hash']] = {
                'block': block,
                'timestamp': time.time()
            }
            
            # Broadcast to network
            block_message = {
                'type': 'new_block',
                'block': block
            }
            self._broadcast_message(block_message)
            
            self.logger.info(f"Broadcasted block {block['block_number']} (hash: {block['hash'][:16]}...)")
            
        except Exception as e:
            self.logger.error(f"Error broadcasting block: {e}")

    def _sync_with_network(self):
        """Sync with the existing network."""
        self.logger.info("Syncing with network...")
        
        try:
            # Request latest blocks from peers
            if self.network_manager:
                sync_request = {
                    'type': 'sync_request',
                    'latest_block': self.ledger.get_current_block_number()
                }
                self.network_manager.broadcast_message(sync_request)
            
            # Wait for sync to complete
            time.sleep(10)
            
            self.logger.info("Network sync completed")
            
        except Exception as e:
            self.logger.error(f"Error syncing with network: {e}")

    def enable_single_validator_mode(self):
        """Enable single validator mode for testing."""
        with self.genesis_lock:
            self.single_validator_mode = True
            self.consensus_core.update_validator_set([self.consensus_core.validator_id])
            self.logger.info("Enabled single validator mode")

    def disable_single_validator_mode(self):
        """Disable single validator mode."""
        with self.genesis_lock:
            self.single_validator_mode = False
            self.logger.info("Disabled single validator mode")

    def add_validator_to_network(self, validator_id: str):
        """Add a new validator to the network."""
        with self.genesis_lock:
            if validator_id not in self.consensus_core.validator_set:
                new_validator_set = self.consensus_core.validator_set + [validator_id]
                self.consensus_core.update_validator_set(new_validator_set)
                
                # If we were in single validator mode, exit it
                if self.single_validator_mode and len(new_validator_set) > 1:
                    self.single_validator_mode = False
                    self.logger.info("Exiting single validator mode due to new validator")
                
                self.logger.info(f"Added validator {validator_id} to network")

    def get_genesis_status(self) -> Dict:
        """Get the current genesis operation status."""
        return {
            'is_genesis_node': self.is_genesis_node,
            'single_validator_mode': self.single_validator_mode,
            'bootstrap_completed': self.bootstrap_completed,
            'validator_count': len(self.consensus_core.validator_set),
            'current_round': self.consensus_core.current_round,
            'current_phase': self.consensus_core.current_phase.name
        }
