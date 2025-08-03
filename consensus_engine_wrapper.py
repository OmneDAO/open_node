"""
ConsensusEngine Wrapper - Compatibility Layer

This module provides a compatibility wrapper that maintains the same API
as the original ConsensusEngine while using the separated core and genesis
components internally.
"""

import logging
from typing import List, Dict, Optional, Tuple, Any
from datetime import datetime, timezone
import threading
import time

from consensus_engine_core import ConsensusEngineCore, ConsensusPhase
from genesis_consensus_operations import GenesisConsensusOperations


class ConsensusEngine:
    """
    Compatibility wrapper for the separated consensus architecture.
    
    This class maintains the same public API as the original ConsensusEngine
    while delegating to the appropriate separated components internally.
    """

    def __init__(
        self,
        validator_id: str,
        network_manager=None,
        ledger=None,
        mempool=None,
        crypto_utils=None,
        vrf_utils=None,
        validator_set: List[str] = None,
        min_validators: int = 4,
        block_interval_minutes: int = 9,
        randao_commit_duration: int = 30,
        randao_reveal_duration: int = 30,
        poef_task_difficulty: int = 4,
        poef_task_iterations: int = 100000,
        poef_adjustment_interval: int = 100,
        num_leaders: int = 3,
        single_validator_mode: bool = False,
        is_genesis_node: bool = False
    ):
        """
        Initialize the consensus engine wrapper.
        """
        # Initialize core consensus engine
        self.core = ConsensusEngineCore(
            validator_id=validator_id,
            validator_set=validator_set or [validator_id],
            min_validators=min_validators,
            block_interval_minutes=block_interval_minutes,
            randao_commit_duration=randao_commit_duration,
            randao_reveal_duration=randao_reveal_duration,
            poef_task_difficulty=poef_task_difficulty,
            poef_task_iterations=poef_task_iterations,
            poef_adjustment_interval=poef_adjustment_interval,
            num_leaders=num_leaders
        )

        # Initialize genesis operations
        self.genesis_ops = GenesisConsensusOperations(
            consensus_core=self.core,
            network_manager=network_manager,
            ledger=ledger,
            mempool=mempool,
            crypto_utils=crypto_utils,
            vrf_utils=vrf_utils,
            is_genesis_node=is_genesis_node
        )

        # Store references to external components
        self.network_manager = network_manager
        self.ledger = ledger
        self.mempool = mempool
        self.crypto_utils = crypto_utils
        self.vrf_utils = vrf_utils

        # Compatibility properties
        self.validator_id = validator_id
        self.validator_set = self.core.validator_set
        self.min_validators = min_validators
        self.single_validator_mode = single_validator_mode
        self.is_genesis_node = is_genesis_node

        # Set single validator mode if requested
        if single_validator_mode:
            self.genesis_ops.enable_single_validator_mode()

        # Logger
        self.logger = logging.getLogger('ConsensusEngine')
        self.logger.setLevel(logging.INFO)
        handler = logging.StreamHandler()
        formatter = logging.Formatter('[%(asctime)s] [%(levelname)s] [%(name)s] %(message)s')
        handler.setFormatter(formatter)
        if not self.logger.handlers:
            self.logger.addHandler(handler)

        self.logger.info(f"ConsensusEngine wrapper initialized for validator {validator_id}")

    # === Core Consensus Delegation Methods ===

    @property
    def running(self) -> bool:
        """Check if consensus is running."""
        return self.core.running

    @running.setter
    def running(self, value: bool):
        """Set running state."""
        self.core.running = value

    @property
    def current_phase(self) -> ConsensusPhase:
        """Get current consensus phase."""
        return self.core.current_phase

    @property
    def current_round(self) -> int:
        """Get current consensus round."""
        return self.core.current_round

    @property
    def consensus_lock(self):
        """Get consensus lock."""
        return self.core.consensus_lock

    @property
    def vrf_commits(self) -> Dict:
        """Get VRF commits."""
        return self.core.vrf_commits

    @property
    def vrf_reveals(self) -> Dict:
        """Get VRF reveals."""
        return self.core.vrf_reveals

    @property
    def leader_pool(self) -> List[str]:
        """Get leader pool."""
        return self.core.leader_pool

    @property
    def pending_block(self):
        """Get pending block."""
        return self.core.pending_block

    @pending_block.setter
    def pending_block(self, value):
        """Set pending block."""
        self.core.pending_block = value

    @property
    def block_votes(self) -> Dict:
        """Get block votes."""
        return self.core.block_votes

    def update_validator_set(self, new_validator_set: List[str]) -> None:
        """Update the validator set."""
        self.core.update_validator_set(new_validator_set)
        self.validator_set = self.core.validator_set

    def aggregate_randomness(self, round_number: int) -> Optional[str]:
        """Aggregate VRF randomness."""
        return self.core.aggregate_randomness(round_number)

    def select_leaders(self, stake_weights: Dict[str, float]) -> List[str]:
        """Select consensus leaders."""
        return self.core.select_leaders(stake_weights)

    def perform_proof_of_effort(self, vrf_hex: str, difficulty: int) -> str:
        """Perform proof of effort."""
        return self.core.perform_proof_of_effort(vrf_hex, difficulty)

    def verify_proof_of_effort(self, proof: str, difficulty: int) -> bool:
        """Verify proof of effort."""
        return self.core.verify_proof_of_effort(proof, difficulty)

    def adjust_poef_difficulty(self, average_block_time: float) -> None:
        """Adjust PoE difficulty."""
        self.core.adjust_poef_difficulty(average_block_time)

    def receive_vrf_commit(self, round_number: int, validator_id: str, proof: bytes, alpha: bytes) -> bool:
        """Process VRF commit."""
        return self.core.receive_vrf_commit(round_number, validator_id, proof, alpha)

    def receive_vrf_reveal(self, validator_id: str, proof: bytes, alpha: bytes) -> bool:
        """Process VRF reveal."""
        return self.core.receive_vrf_reveal(validator_id, proof, alpha)

    def get_vrf_reveal(self, round_number: int) -> Optional[Dict]:
        """Get VRF reveal."""
        return self.core.get_vrf_reveal(round_number)

    def generate_vrf_commit(self) -> Tuple[bytes, bytes]:
        """Generate VRF commit."""
        return self.core.generate_vrf_commit(self.vrf_utils)

    def verify_leader(self, leader: str) -> bool:
        """Verify leader."""
        return self.core.verify_leader(leader, self.vrf_utils)

    def start_new_round(self) -> int:
        """Start new consensus round."""
        return self.core.start_new_round()

    def reset_round_state(self):
        """Reset round state."""
        self.core.reset_round_state()

    def get_current_phase(self) -> ConsensusPhase:
        """Get current phase."""
        return self.core.get_current_phase()

    def get_current_round(self) -> int:
        """Get current round."""
        return self.core.get_current_round()

    def get_leader_pool(self) -> List[str]:
        """Get leader pool."""
        return self.core.get_leader_pool()

    def calculate_dynamic_difficulty(self, active_validator_count: int) -> int:
        """Calculate dynamic difficulty."""
        return self.core.calculate_dynamic_difficulty(active_validator_count)

    # === Genesis Operations Delegation Methods ===

    def start(self):
        """Start the consensus engine."""
        self.genesis_ops.start()

    def stop(self):
        """Stop the consensus engine."""
        self.genesis_ops.stop()

    def enable_single_validator_mode(self):
        """Enable single validator mode."""
        self.single_validator_mode = True
        self.genesis_ops.enable_single_validator_mode()

    def disable_single_validator_mode(self):
        """Disable single validator mode."""
        self.single_validator_mode = False
        self.genesis_ops.disable_single_validator_mode()

    def add_validator_to_network(self, validator_id: str):
        """Add validator to network."""
        self.genesis_ops.add_validator_to_network(validator_id)
        self.validator_set = self.core.validator_set

    def get_genesis_status(self) -> Dict:
        """Get genesis status."""
        return self.genesis_ops.get_genesis_status()

    # === Compatibility Methods for Existing Code ===

    def get_validator_set(self) -> List[str]:
        """Get current validator set."""
        return self.validator_set.copy()

    def is_validator_active(self, validator_id: str) -> bool:
        """Check if validator is active."""
        return validator_id in self.validator_set

    def get_consensus_state(self) -> Dict[str, Any]:
        """Get comprehensive consensus state."""
        return {
            'validator_id': self.validator_id,
            'validator_set': self.validator_set,
            'current_round': self.current_round,
            'current_phase': self.current_phase.name,
            'leader_pool': self.leader_pool,
            'single_validator_mode': self.single_validator_mode,
            'is_genesis_node': self.is_genesis_node,
            'running': self.running,
            'vrf_commits_count': len(self.vrf_commits),
            'vrf_reveals_count': len(self.vrf_reveals),
            'block_votes_count': len(self.block_votes),
            'has_pending_block': self.pending_block is not None,
            'min_validators': self.min_validators
        }

    def process_network_message(self, message: Dict) -> bool:
        """Process incoming network message."""
        try:
            message_type = message.get('type')
            
            if message_type == 'vrf_commit':
                return self.receive_vrf_commit(
                    message['round'],
                    message['validator_id'],
                    bytes.fromhex(message['proof']),
                    bytes.fromhex(message['alpha'])
                )
            elif message_type == 'vrf_reveal':
                return self.receive_vrf_reveal(
                    message['validator_id'],
                    bytes.fromhex(message['proof']),
                    bytes.fromhex(message['alpha'])
                )
            elif message_type == 'block_proposal':
                self.pending_block = message['block']
                return True
            elif message_type == 'block_vote':
                self.block_votes[message['validator_id']] = message
                return True
            else:
                self.logger.warning(f"Unknown message type: {message_type}")
                return False
                
        except Exception as e:
            self.logger.error(f"Error processing network message: {e}")
            return False

    def broadcast_to_validators(self, message: Dict) -> None:
        """Broadcast message to all validators."""
        if self.network_manager:
            self.network_manager.broadcast_message(message)
        else:
            self.logger.debug("No network manager available for broadcasting")

    def get_network_status(self) -> Dict:
        """Get network connectivity status."""
        if self.network_manager:
            return {
                'connected_peers': getattr(self.network_manager, 'connected_peers', []),
                'network_active': getattr(self.network_manager, 'is_active', False)
            }
        else:
            return {
                'connected_peers': [],
                'network_active': False
            }

    def finalize_block(self, block: Dict) -> bool:
        """Finalize a consensus block."""
        try:
            if self.ledger:
                success = self.ledger.add_block(block)
                if success and self.mempool:
                    # Remove transactions from mempool
                    for tx_data in block.get('transactions', []):
                        self.mempool.remove_transaction(tx_data.get('transaction_id'))
                return success
            return False
        except Exception as e:
            self.logger.error(f"Error finalizing block: {e}")
            return False

    # === Backward Compatibility Properties ===

    @property
    def block_interval_minutes(self) -> int:
        """Get block interval."""
        return self.core.block_interval_minutes

    @property
    def randao_commit_duration(self) -> int:
        """Get RANDAO commit duration."""
        return self.core.randao_commit_duration

    @property
    def randao_reveal_duration(self) -> int:
        """Get RANDAO reveal duration."""
        return self.core.randao_reveal_duration

    @property
    def poef_task_difficulty(self) -> int:
        """Get PoE task difficulty."""
        return self.core.poef_task_difficulty

    @property
    def poef_task_iterations(self) -> int:
        """Get PoE task iterations."""
        return self.core.poef_task_iterations

    @property
    def num_leaders(self) -> int:
        """Get number of leaders."""
        return self.core.num_leaders

    def __getattr__(self, name):
        """
        Fallback for any attributes not explicitly defined.
        First try core, then genesis_ops.
        """
        if hasattr(self.core, name):
            return getattr(self.core, name)
        elif hasattr(self.genesis_ops, name):
            return getattr(self.genesis_ops, name)
        else:
            raise AttributeError(f"'{self.__class__.__name__}' object has no attribute '{name}'")
