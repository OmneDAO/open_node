"""
ConsensusEngine Core - Pure Consensus Algorithms

This module contains the core consensus algorithms that must be identical
across all node types for nexum validation. Genesis and network formation
operations are handled by separate classes.
"""

import hashlib
import logging
import threading
import time
from typing import List, Dict, Optional, Tuple
from datetime import datetime, timezone
from enum import Enum
import asyncio


class ConsensusPhase(Enum):
    COMMIT = 0
    PREPARE = 1
    PROPOSE = 2
    VOTE = 3
    FINALIZE = 4


class ConsensusEngineCore:
    """
    Pure consensus engine containing only essential consensus algorithms.
    
    This class contains the mathematical and cryptographic consensus logic
    that must be identical across all node types. Network operations and
    genesis-specific functionality are handled by separate components.
    """

    def __init__(
        self,
        validator_id: str,
        validator_set: List[str],
        min_validators: int = 4,
        block_interval_minutes: int = 9,
        randao_commit_duration: int = 30,
        randao_reveal_duration: int = 30,
        poef_task_difficulty: int = 4,
        poef_task_iterations: int = 100000,
        poef_adjustment_interval: int = 100,
        num_leaders: int = 3
    ):
        """
        Initialize the pure consensus engine core.
        """
        self.validator_id = validator_id
        self.validator_set = validator_set
        self.min_validators = min_validators
        self.block_interval_minutes = block_interval_minutes
        self.randao_commit_duration = randao_commit_duration
        self.randao_reveal_duration = randao_reveal_duration
        self.poef_task_difficulty = poef_task_difficulty
        self.poef_task_iterations = poef_task_iterations
        self.poef_adjustment_interval = poef_adjustment_interval
        self.num_leaders = num_leaders

        # Core consensus state
        self.consensus_lock = threading.Lock()
        self.running = False
        self.current_phase = ConsensusPhase.COMMIT
        self.current_round = 0
        self.phase_start_time = time.time()
        self.vrf_commits = {}
        self.vrf_reveals = {}
        self.pending_block = None
        self.block_votes = {}
        self.PHASE_TIMEOUT = 60
        
        # Leader selection state
        self.leader_pool: List[str] = []
        self.current_randomness: Optional[str] = None

        # Calculate required thresholds
        self.required_commits = max(2, len(validator_set) // 2)
        self.required_reveals = max(2, len(validator_set) // 2)
        self.required_votes = max(2, len(validator_set) // 2)

        # Logger
        self.logger = logging.getLogger('ConsensusEngineCore')
        self.logger.setLevel(logging.INFO)
        handler = logging.StreamHandler()
        formatter = logging.Formatter('[%(asctime)s] [%(levelname)s] [%(name)s] %(message)s')
        handler.setFormatter(formatter)
        if not self.logger.handlers:
            self.logger.addHandler(handler)

        self.logger.info(f"ConsensusEngineCore initialized for validator {validator_id}")

    def update_validator_set(self, new_validator_set: List[str]) -> None:
        """Update the validator set and recalculate thresholds"""
        with self.consensus_lock:
            self.validator_set = new_validator_set
            self.required_commits = max(2, len(new_validator_set) // 2)
            self.required_reveals = max(2, len(new_validator_set) // 2)
            self.required_votes = max(2, len(new_validator_set) // 2)
            self.logger.info(f"Updated validator set: {len(new_validator_set)} validators")

    def aggregate_randomness(self, round_number: int) -> Optional[str]:
        """
        Collect VRF outputs from all active validators and aggregate into a single
        SHA-256 random seed.
        """
        self.logger.info(f"Aggregating VRF outputs for round {round_number}")
        collected = []

        for validator_id in self.validator_set:
            reveal = self.vrf_reveals.get(validator_id)
            if reveal:
                collected.append(reveal['proof'])
            else:
                self.logger.warning(f"Validator {validator_id} did not submit VRF reveal")

        if collected:
            concatenated = b''.join(collected)
            self.current_randomness = hashlib.sha256(concatenated).hexdigest()
            self.logger.info(f"Aggregated randomness: {self.current_randomness}")
            return self.current_randomness
        else:
            self.logger.error("No VRF reveals collected; randomness not generated")
            self.current_randomness = None
            return None

    def select_leaders(self, stake_weights: Dict[str, float]) -> List[str]:
        """
        Select leaders based on stake weights and VRF randomness.
        
        Args:
            stake_weights: Dictionary mapping validator_id to stake weight (0.0 to 1.0)
            
        Returns:
            List of selected leader validator IDs
        """
        self.leader_pool = []
        
        if not self.validator_set:
            self.logger.error("No validators in validator set")
            return []

        # Create weighted list of validators with VRF influence
        weighted_validators = []
        for validator_id in self.validator_set:
            base_weight = stake_weights.get(validator_id, 0.0)
            
            # Add VRF influence if available
            reveal = self.vrf_reveals.get(validator_id)
            if reveal and self.current_randomness:
                # Use VRF proof to influence weight
                vrf_bytes = reveal['proof']
                vrf_influence = int.from_bytes(vrf_bytes[:4], 'big') / (2**32)
                weight = (base_weight + vrf_influence) / 2
            else:
                weight = base_weight
            
            weighted_validators.append((validator_id, weight))

        # Sort by weight descending
        weighted_validators.sort(key=lambda x: x[1], reverse=True)

        # Select top N leaders
        for i in range(min(self.num_leaders, len(weighted_validators))):
            self.leader_pool.append(weighted_validators[i][0])

        self.logger.info(f"Selected leaders: {self.leader_pool}")
        return self.leader_pool.copy()

    def calculate_dynamic_difficulty(self, active_validator_count: int) -> int:
        """
        Calculate dynamic PoE difficulty based on network conditions.
        """
        base_difficulty = self.poef_task_difficulty
        
        # Adjust based on number of active validators
        validator_factor = active_validator_count / self.min_validators
        difficulty = int(base_difficulty * validator_factor)
        
        # Ensure difficulty stays within reasonable bounds
        return max(2, min(difficulty, 8))

    def perform_proof_of_effort(self, vrf_hex: str, difficulty: int) -> str:
        """
        Perform PoE puzzle with the given VRF input and difficulty.
        """
        nonce = 0
        target = '0' * difficulty
        start_time = time.time()
        
        while nonce < self.poef_task_iterations:
            # Check for timeout
            if time.time() - start_time > 30:  # 30 second timeout
                return ''
                
            data = f"{vrf_hex}-{nonce}".encode('utf-8')
            h = hashlib.sha256(data).hexdigest()
            if h.startswith(target):
                self.logger.debug(f"PoE success: nonce={nonce}, hash={h}")
                return h
            nonce += 1
            
        return ''

    def verify_proof_of_effort(self, proof: str, difficulty: int) -> bool:
        """
        Verify PoE proof with the given difficulty.
        """
        if not proof:
            return False
            
        target = '0' * difficulty
        return proof.startswith(target)

    def adjust_poef_difficulty(self, average_block_time: float) -> None:
        """
        Adjust PoE difficulty based on average block time.
        """
        desired_time = 60  # target block time in seconds
        
        if average_block_time < desired_time * 0.9:
            self.poef_task_difficulty += 1
            self.logger.info(f"Increasing PoE difficulty to {self.poef_task_difficulty}")
        elif average_block_time > desired_time * 1.1 and self.poef_task_difficulty > 1:
            self.poef_task_difficulty -= 1
            self.logger.info(f"Decreasing PoE difficulty to {self.poef_task_difficulty}")
        else:
            self.logger.info("PoE difficulty remains unchanged")

    def receive_vrf_commit(self, round_number: int, validator_id: str, proof: bytes, alpha: bytes) -> bool:
        """
        Process a VRF commit from a validator.
        """
        try:
            # Verify we're in the commit phase
            if self.current_phase != ConsensusPhase.COMMIT:
                self.logger.warning(f"Received VRF commit in wrong phase: {self.current_phase}")
                return False
                
            # Verify the round number matches
            if round_number != self.current_round:
                self.logger.warning(f"Received VRF commit for wrong round: {round_number} != {self.current_round}")
                return False
                
            # Verify the validator is in the validator set
            if validator_id not in self.validator_set:
                self.logger.warning(f"Received VRF commit from unknown validator: {validator_id}")
                return False
                
            # Verify we haven't already received a commit from this validator
            if validator_id in self.vrf_commits:
                self.logger.warning(f"Received duplicate VRF commit from validator: {validator_id}")
                return False
                
            # Store the commit
            self.vrf_commits[validator_id] = {
                'proof': proof,
                'alpha': alpha
            }
            
            self.logger.info(f"Received VRF commit from validator {validator_id} for round {round_number}")
            
            # Check if we have enough commits to proceed
            if len(self.vrf_commits) >= self.required_commits:
                self.logger.info("Received enough VRF commits, transitioning to reveal phase")
                self.current_phase = ConsensusPhase.REVEAL
                
            return True
            
        except Exception as e:
            self.logger.error(f"Error processing VRF commit: {str(e)}")
            return False

    def receive_vrf_reveal(self, validator_id: str, proof: bytes, alpha: bytes) -> bool:
        """
        Process a VRF reveal from a validator.
        """
        if validator_id not in self.validator_set:
            self.logger.warning(f"Received VRF reveal from unknown validator {validator_id}")
            return False
            
        if self.current_phase != ConsensusPhase.REVEAL:
            self.logger.warning(f"Received VRF reveal from {validator_id} outside of reveal phase")
            return False
            
        try:
            self.vrf_reveals[validator_id] = {
                "validator_id": validator_id,
                "proof": proof,
                "alpha": alpha
            }
            self.logger.info(f"Processed VRF reveal from validator {validator_id}")
            return True
            
        except Exception as e:
            self.logger.error(f"Error processing VRF reveal from {validator_id}: {e}")
            return False

    def get_vrf_reveal(self, round_number: int) -> Optional[Dict]:
        """
        Get the VRF reveal for the current validator in a given round.
        """
        if round_number != self.current_round:
            self.logger.warning(f"Requested VRF reveal for round {round_number}, but current round is {self.current_round}")
            return None
            
        if self.current_phase != ConsensusPhase.REVEAL:
            self.logger.warning(f"Requested VRF reveal outside of reveal phase")
            return None
            
        reveal = self.vrf_reveals.get(self.validator_id)
        if not reveal:
            self.logger.warning(f"No VRF reveal available for validator {self.validator_id} in round {round_number}")
            return None
            
        return reveal

    def generate_vrf_commit(self, vrf_utils) -> Tuple[bytes, bytes]:
        """
        Generate a VRF commit for the current round.
        """
        try:
            alpha = f"{self.current_round}:{self.validator_id}".encode()
            proof = vrf_utils.prove(alpha.hex())
            self.vrf_reveals[self.validator_id] = {'proof': proof, 'alpha': alpha}
            return proof, alpha
        except Exception as e:
            self.logger.error(f"Error generating VRF commit: {e}")
            return b'0' * 32, b'0' * 32

    def verify_leader(self, leader: str, vrf_utils) -> bool:
        """
        Verify if a validator is a valid leader for block proposal.
        """
        if leader not in self.leader_pool:
            self.logger.warning(f"Validator {leader} is not in the leader pool")
            return False
            
        reveal = self.vrf_reveals.get(leader)
        if not reveal:
            self.logger.warning(f"No VRF reveal found for leader {leader}")
            return False
            
        try:
            # Basic VRF proof verification would go here
            # In practice, this would verify against the leader's public key
            return True
        except Exception as e:
            self.logger.error(f"Error verifying VRF proof: {e}")
            return False

    def start_new_round(self) -> int:
        """
        Start a new consensus round.
        """
        with self.consensus_lock:
            self.current_round += 1
            self.current_phase = ConsensusPhase.COMMIT
            self.phase_start_time = time.time()
            
            # Clear state from previous round
            self.vrf_commits.clear()
            self.vrf_reveals.clear()
            self.block_votes.clear()
            self.pending_block = None
            self.leader_pool.clear()
            
            self.logger.info(f"Started consensus round {self.current_round}")
            return self.current_round

    def reset_round_state(self):
        """Reset the state for a new round."""
        self.vrf_commits.clear()
        self.vrf_reveals.clear()
        self.leader_pool.clear()
        self.pending_block = None

    def get_current_phase(self) -> ConsensusPhase:
        """Get the current consensus phase."""
        return self.current_phase

    def get_current_round(self) -> int:
        """Get the current consensus round."""
        return self.current_round

    def get_leader_pool(self) -> List[str]:
        """Get the current leader pool."""
        return self.leader_pool.copy()

    def get_phase_duration(self) -> float:
        """Get how long the current phase has been running."""
        return time.time() - self.phase_start_time

    def should_timeout_phase(self) -> bool:
        """Check if the current phase should timeout."""
        return self.get_phase_duration() > self.PHASE_TIMEOUT

    def advance_phase(self, new_phase: ConsensusPhase) -> None:
        """Advance to a new consensus phase."""
        self.current_phase = new_phase
        self.phase_start_time = time.time()
        self.logger.info(f"Advanced to phase {new_phase}")

    def is_validator_in_set(self, validator_id: str) -> bool:
        """Check if a validator is in the current validator set."""
        return validator_id in self.validator_set

    def get_required_threshold(self, threshold_type: str) -> int:
        """Get the required threshold for a given consensus operation."""
        if threshold_type == "commits":
            return self.required_commits
        elif threshold_type == "reveals":
            return self.required_reveals
        elif threshold_type == "votes":
            return self.required_votes
        else:
            return 0
