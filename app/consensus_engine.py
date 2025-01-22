# consensus_engine.py

import hashlib
import logging
import threading
import time
from typing import List, Dict, Optional, Tuple
from datetime import datetime, timezone
import random

import requests  # Ensure this is imported for HTTP requests

from vrf_utils import VRFUtils  # Import VRFUtils
from crypto_utils import CryptoUtils  # For other cryptographic operations
from block import Block  # Assumed Block class definition
from omc import OMC  # Assumed OMC class managing validators and rewards
from ledger import Ledger  # Assumed Ledger class managing blockchain
from account_manager import AccountManager  # Assumed AccountManager class
from alpha_generator import AlphaGenerator  # Import AlphaGenerator

# ----------------------------------------------------------------
#  ConsensusEngine Class Definition
# ----------------------------------------------------------------

class ConsensusEngine:
    """
    Implements the Hybrid PoS-PoE Consensus Mechanism with RANDAO and cBFT.
    Handles RANDAO commit/reveal phases, Proof of Effort tasks, cBFT message flows,
    leader selection, and block proposal.
    """

    def __init__(self, 
                 ledger: Ledger, 
                 omc: OMC,
                 account_manager: AccountManager,
                 vrf_utils: VRFUtils,  # Instance of VRFUtils
                 blockchain,  # Reference to the blockchain instance
                 randao_commit_duration: int = 60,  # seconds
                 randao_reveal_duration: int = 60,  # seconds
                 poef_task_difficulty: int = 4,  # Number of leading zeros required in PoE proof
                 poef_task_iterations: int = 100000,  # Maximum nonce attempts for PoE
                 poef_adjustment_interval: int = 100,  # Adjust difficulty every 100 blocks
                 num_leaders: int = 3):  # Number of leaders per round
        """
        :param ledger: Reference to the Ledger instance.
        :param omc: Reference to the OMC instance.
        :param account_manager: Reference to the AccountManager instance.
        :param vrf_utils: Instance of VRFUtils for VRF operations.
        :param blockchain: Reference to the Blockchain instance.
        :param randao_commit_duration: Duration of the RANDAO commit phase in seconds.
        :param randao_reveal_duration: Duration of the RANDAO reveal phase in seconds.
        :param poef_task_difficulty: Number of leading zeros required in PoE proof.
        :param poef_task_iterations: Maximum number of nonce attempts for PoE task.
        :param poef_adjustment_interval: Number of blocks after which PoE difficulty is adjusted.
        :param num_leaders: Number of leaders to select per consensus round.
        """
        self.ledger = ledger
        self.omc = omc
        self.account_manager = account_manager
        self.vrf_utils = vrf_utils
        self.blockchain = blockchain  # Assign blockchain reference

        self.network_manager = None  # To be set via set_network_manager

        # RANDAO parameters
        self.randao_commit_duration = randao_commit_duration
        self.randao_reveal_duration = randao_reveal_duration

        # PoE parameters
        self.poef_task_difficulty = poef_task_difficulty
        self.poef_task_iterations = poef_task_iterations
        self.poef_adjustment_interval = poef_adjustment_interval

        # Consensus state
        self.vrf_outputs: Dict[str, Tuple[bytes, bytes]] = {}  # validator_id: (beta, proof)
        self.current_randomness: Optional[str] = None
        self.consensus_round: int = 1  # Start from Round 1
        self.leader_pool: List[str] = []
        self.num_leaders = num_leaders

        # Phase control
        self.randao_commit_phase = True  # Start with commit phase
        self.phase_in_progress = False    # Flag to prevent overlapping phases
        self.consensus_lock = threading.Lock()

        # cBFT state
        self.pre_votes: Dict[str, bool] = {}  # validator_id: pre_vote
        self.pre_commits: Dict[str, bool] = {}  # validator_id: pre_commit

        # Initialize logger
        self.logger = logging.getLogger('ConsensusEngine')
        self.logger.setLevel(logging.INFO)
        handler = logging.StreamHandler()
        formatter = logging.Formatter('[%(asctime)s] [%(levelname)s] [%(name)s] %(message)s')
        handler.setFormatter(formatter)
        if not self.logger.handlers:
            self.logger.addHandler(handler)

        # Initialize AlphaGenerator
        self.alpha_generator = AlphaGenerator(blockchain=self.blockchain)

        # Start the consensus routine externally via start_consensus_routine
        self.logger.info("ConsensusEngine initialized.")

    def set_network_manager(self, network_manager):
        """
        Sets the NetworkManager instance for the ConsensusEngine.
        
        :param network_manager: Instance of NetworkManager.
        """
        self.network_manager = network_manager
        self.logger.info("NetworkManager has been set in ConsensusEngine.")
        
    def start_consensus_routine(self):
        """
        Starts the main consensus routine, such as leader selection.
        Runs in a separate thread.
        """
        self.consensus_thread = threading.Thread(target=self._consensus_loop, daemon=True)
        self.consensus_thread.start()
        self.logger.info("Consensus routine started.")

    def _consensus_loop(self):
        """
        The main loop handling RANDAO commit and reveal phases.
        """
        while True:
            try:
                with self.consensus_lock:
                    if not self.phase_in_progress:
                        if self.randao_commit_phase:
                            self.logger.info(f"Starting RANDAO Commit Phase for Round {self.consensus_round}.")
                            self._start_randao_commit(self.consensus_round)
                        else:
                            self.logger.info(f"Starting RANDAO Reveal Phase for Round {self.consensus_round}.")
                            self._start_randao_reveal(self.consensus_round)

                # Sleep to prevent tight looping; adjust as needed
                time.sleep(1)
            except Exception as e:
                self.logger.error(f"Error in consensus loop: {e}")
                time.sleep(5)  # Wait before retrying to prevent tight loop

    def _start_randao_commit(self, round_number: int):
        """
        Initiates the RANDAO commit phase where validators commit their VRF outputs.
        
        :param round_number: The current round number.
        """
        self.phase_in_progress = True
        self.randao_commit_phase = True
        self.vrf_outputs = {}  # Reset VRF outputs for this round

        # Start a timer to end the commit phase after the specified duration
        commit_timer = threading.Timer(self.randao_commit_duration, self._end_randao_commit, args=[round_number])
        commit_timer.start()

        # Generate alpha using AlphaGenerator
        alpha = self.alpha_generator.generate_alpha(round_number)
        self.logger.debug(f"ConsensusEngine: Generated alpha: {alpha}")

        # Generate VRF proof
        try:
            proof = self.vrf_utils.prove(alpha)
            self.logger.info(f"ConsensusEngine: VRF proof generated successfully.")
            # Store VRF output
            self.vrf_outputs[self.ledger.node.address] = (proof, proof)  # Assuming beta and proof are the same
            # Broadcast the VRF output to other validators
            if self.network_manager:
                self.network_manager.broadcast_vrf_output(self.ledger.node.address, proof)
            else:
                self.logger.warning("NetworkManager not set. Cannot broadcast VRF output.")
        except Exception as e:
            self.logger.error(f"ConsensusEngine: VRF proof generation failed: {e}")

    def _end_randao_commit(self, round_number: int):
        """
        Ends the RANDAO commit phase and transitions to the reveal phase.
        
        :param round_number: The current round number.
        """
        with self.consensus_lock:
            self.phase_in_progress = False
            self.randao_commit_phase = False
            self.logger.info(f"RANDAO Commit Phase ended for Round {round_number}.")

    def _start_randao_reveal(self, round_number: int):
        """
        Initiates the RANDAO reveal phase where validators reveal their committed VRF outputs.
        Aggregates the outputs to generate collective randomness.
        
        :param round_number: The current round number.
        """
        self.phase_in_progress = True
        self.randao_commit_phase = False
        self.logger.info(f"Starting RANDAO Reveal Phase for Round {round_number}.")

        # Start a timer to end the reveal phase after the specified duration
        reveal_timer = threading.Timer(self.randao_reveal_duration, self._end_randao_reveal, args=[round_number])
        reveal_timer.start()

        # Request VRF outputs from other validators
        if self.network_manager:
            self.network_manager.request_vrf_outputs(round_number)
        else:
            self.logger.warning("NetworkManager not set. Cannot request VRF outputs.")

        # Include own VRF output
        try:
            beta, proof = self.vrf_outputs.get(self.ledger.node.address, (None, None))
            if beta and proof:
                # Broadcast the VRF output (if not already done)
                self.network_manager.broadcast_vrf_output(self.ledger.node.address, proof)
            else:
                self.logger.error("Own VRF output is missing. Cannot reveal.")
        except Exception as e:
            self.logger.error(f"ConsensusEngine: Error revealing own VRF output: {e}")

    def _end_randao_reveal(self, round_number: int):
        """
        Ends the RANDAO reveal phase and transitions to randomness aggregation.
        
        :param round_number: The current round number.
        """
        with self.consensus_lock:
            self.phase_in_progress = False
            self.logger.info(f"RANDAO Reveal Phase ended for Round {round_number}.")

            # Aggregate VRF outputs to generate randomness
            self._aggregate_randomness(round_number)

            # Transition back to commit phase for the next round
            self.consensus_round += 1
            self.randao_commit_phase = True

    def _aggregate_randomness(self, round_number: int):
        """
        Aggregates VRF outputs from all validators to generate collective randomness.
        
        :param round_number: The current round number.
        """
        validators = self.omc.get_active_validators()  # Assuming this returns a list of validator IDs (e.g., addresses)
        collected_proofs = []

        for validator in validators:
            vrf_output = self.vrf_outputs.get(validator)
            if vrf_output:
                proof = vrf_output[1]  # Assuming proof is at index 1
                # Retrieve the validator's public key
                public_key_pem = self._get_validator_public_key(validator)
                if not public_key_pem:
                    self.logger.warning(f"Could not retrieve public key for validator {validator}. Skipping VRF verification.")
                    continue

                # Generate alpha using AlphaGenerator (ensure it's consistent)
                alpha = self.alpha_generator.generate_alpha(round_number)
                is_valid = self.vrf_utils.vrf_verify(seed=alpha, proof=proof, public_key_pem=public_key_pem)
                if is_valid:
                    collected_proofs.append(proof)
                    self.logger.debug(f"Validator {validator} VRF Output verified.")
                else:
                    self.logger.warning(f"Validator {validator} provided invalid VRF proof.")
            else:
                self.logger.warning(f"Validator {validator} did not submit VRF output for Round {round_number}.")

        # Aggregate VRF proofs to generate randomness
        if collected_proofs:
            # Example aggregation: concatenate all proofs and hash them
            aggregated = b''.join(collected_proofs)
            self.current_randomness = hashlib.sha256(aggregated).hexdigest()
            self.logger.info(f"Aggregated Randomness for Round {round_number}: {self.current_randomness}")
            self._select_leaders()
        else:
            self.logger.error(f"No valid VRF proofs collected for Round {round_number}. Consensus failed.")

    def _get_validator_public_key(self, validator_id: str) -> Optional[str]:
        """
        Retrieves the public key of a validator by querying their public_key endpoint.
        
        :param validator_id: The identifier of the validator (e.g., address).
        :return: The public key in PEM format if retrieved successfully, else None.
        """
        if not self.network_manager:
            self.logger.error("NetworkManager not set. Cannot retrieve validator public keys.")
            return None

        # Assuming there's a way to map validator_id to their network URL
        # For example, via OMC or another service
        validator_url = self.omc.get_validator_url(validator_id)
        if not validator_url:
            self.logger.error(f"Validator URL not found for validator {validator_id}.")
            return None

        vrf_endpoint = f"{validator_url}/api/peer/public_key"
        try:
            response = requests.get(vrf_endpoint, timeout=5)
            if response.status_code == 200:
                public_key_pem = response.json().get('public_key')
                if public_key_pem:
                    self.logger.debug(f"Retrieved public key for validator {validator_id}.")
                    return public_key_pem
                else:
                    self.logger.warning(f"No public key found in response from validator {validator_id}.")
                    return None
            else:
                self.logger.error(f"Failed to retrieve public key from {validator_id}. Status Code: {response.status_code}")
                return None
        except requests.exceptions.RequestException as e:
            self.logger.error(f"Error retrieving public key from {validator_id}: {e}")
            return None

    # ----------------------------------------------------------------
    #  LEADER SELECTION
    # ----------------------------------------------------------------
    def _select_leaders(self):
        """
        Selects leaders based on the aggregated randomness.
        """
        if not self.current_randomness:
            self.logger.error("No randomness available for leader selection.")
            return

        validators = self.omc.get_active_validators()
        num_leaders = min(self.num_leaders, len(validators))

        if num_leaders == 0:
            self.logger.error("No active validators available for leader selection.")
            return

        # Convert aggregated randomness to integer
        randomness_int = int(self.current_randomness, 16)

        # Derive a sortable value for each validator based on their VRF proof
        validator_scores = {}
        for validator, (beta, proof) in self.vrf_outputs.items():
            # Ensure public_key_pem is available
            public_key_pem = self._get_validator_public_key(validator)
            if not public_key_pem:
                self.logger.warning(f"Cannot compute score for validator {validator} without public key.")
                continue

            # Example scoring mechanism: hash(alpha + proof) and interpret as integer
            score_input = self.alpha_generator.generate_alpha(self.consensus_round).encode() + proof
            score = int(hashlib.sha256(score_input).hexdigest(), 16)
            validator_scores[validator] = score

        # Sort validators based on their scores in descending order
        sorted_validators = sorted(validator_scores.items(), key=lambda item: item[1], reverse=True)

        # Select top N leaders
        self.leader_pool = [validator for validator, score in sorted_validators[:num_leaders]]
        self.logger.info(f"Selected Leaders for Round {self.consensus_round}: {self.leader_pool}")

        # Initiate Proof of Effort for selected leaders
        for leader in self.leader_pool:
            threading.Thread(target=self._handle_proof_of_effort, args=(leader,), daemon=True).start()

    # ----------------------------------------------------------------
    #  PROOF OF EFFORT (PoE) HANDLING
    # ----------------------------------------------------------------
    def _handle_proof_of_effort(self, leader: str):
        """
        Handles the Proof of Effort task for a selected leader.
        """
        self.logger.info(f"Leader {leader} is performing Proof of Effort.")
        vrf_output = self.vrf_outputs.get(leader)
        if not vrf_output:
            self.logger.error(f"Leader {leader} has no VRF output.")
            return

        proof = vrf_output[1]

        # Perform Proof of Effort
        poe_proof = self._perform_proof_of_effort(proof.hex())
        is_valid = self._verify_proof_of_effort(poe_proof)

        if is_valid:
            self.logger.info(f"Leader {leader} provided a valid Proof of Effort.")
            # Leader can now propose a block
            self._propose_block(leader, poe_proof)
        else:
            self.logger.warning(f"Leader {leader} failed to provide a valid Proof of Effort.")
            # Penalize the leader by slashing their stake
            self.omc.slash_validator(leader)

    def _perform_proof_of_effort(self, vrf_output_hex: str) -> str:
        """
        Performs the Proof of Effort task by finding a nonce that satisfies the difficulty criteria.

        :param vrf_output_hex: The hexadecimal string of the VRF proof.
        :return: The PoE proof (hash) if successful, else an empty string.
        """
        nonce = 0
        target = '0' * self.poef_task_difficulty

        while nonce < self.poef_task_iterations:
            data = f"{vrf_output_hex}-{nonce}".encode('utf-8')
            hash_result = hashlib.sha256(data).hexdigest()
            if hash_result.startswith(target):
                self.logger.debug(f"PoE success for nonce {nonce}: {hash_result}")
                return hash_result
            nonce += 1

        self.logger.debug(f"PoE failed after {self.poef_task_iterations} iterations for VRF Proof: {vrf_output_hex}")
        return ''

    def _verify_proof_of_effort(self, proof: str) -> bool:
        """
        Verifies the Proof of Effort by checking if it meets the difficulty criteria.

        :param proof: The PoE proof to verify.
        :return: True if valid, False otherwise.
        """
        if not proof:
            return False
        target = '0' * self.poef_task_difficulty
        return proof.startswith(target)

    # ----------------------------------------------------------------
    #  BLOCK PROPOSAL AND VALIDATION
    # ----------------------------------------------------------------
    def _propose_block(self, leader: str, proof: str):
        """
        Leader proposes a new block after successful PoE.

        :param leader: The leader's identifier.
        :param proof: The PoE proof.
        """
        if not self.ledger:
            self.logger.error("Ledger not set in ConsensusEngine. Cannot propose block.")
            return

        # Collect transactions from mempool
        transactions = self.ledger.mempool.get_transactions_for_block()

        if not transactions:
            self.logger.warning("No transactions available to include in the new block.")
            return

        # Get the latest block; handle genesis block if necessary
        previous_block = self.ledger.get_latest_block()
        if not previous_block:
            # Create genesis block
            previous_hash = '0' * 64  # Example: 64 zeros for genesis
            self.logger.info("No previous blocks found. Creating genesis block.")
        else:
            previous_hash = previous_block.hash

        # Create a new block
        new_block = Block(
            index=(previous_block.index + 1) if previous_block else 1,
            previous_hash=previous_hash,
            transactions=transactions,
            signatures=[],  # Signatures will be added by the ConsensusEngine or validators
            timestamp=datetime.now(timezone.utc).isoformat(),
            leader=leader,
            proof_of_effort=proof
        )

        # Validate and add the block to the ledger
        with self.ledger.lock:
            if self.ledger.validate_block(new_block):
                self.ledger.add_block(new_block)
                self.ledger.mempool.remove_transactions(transactions)
                self.logger.info(f"Block {new_block.index} proposed by {leader} added to the ledger.")
                # Broadcast the new block to peers
                if self.network_manager:
                    self.network_manager.broadcast_block(new_block.to_dict(), exclude_peer_url=None)
                else:
                    self.logger.warning("NetworkManager not set. Cannot broadcast the new block.")
                # Reward the leader
                self.omc.reward_validator(leader, new_block.index)
                # Adjust PoE difficulty if needed
                if new_block.index % self.poef_adjustment_interval == 0:
                    self._adjust_poef_difficulty()
            else:
                self.logger.warning(f"Block {new_block.index} proposed by {leader} is invalid.")
                # Optionally, slash or penalize the leader
                self.omc.slash_validator(leader)

    # ----------------------------------------------------------------
    #  POE DIFFICULTY ADJUSTMENT
    # ----------------------------------------------------------------
    def _adjust_poef_difficulty(self):
        """
        Adjusts the PoE task difficulty based on the average block time.
        """
        if not self.ledger:
            self.logger.error("Ledger not set in ConsensusEngine. Cannot adjust PoE difficulty.")
            return

        average_block_time = self.ledger.calculate_average_block_time(last_n_blocks=self.poef_adjustment_interval)
        desired_block_time = 60  # seconds

        if average_block_time < desired_block_time * 0.9:
            self.poef_task_difficulty += 1
            self.logger.info(f"Increased PoE difficulty to {self.poef_task_difficulty}.")
        elif average_block_time > desired_block_time * 1.1 and self.poef_task_difficulty > 1:
            self.poef_task_difficulty -= 1
            self.logger.info(f"Decreased PoE difficulty to {self.poef_task_difficulty}.")
        else:
            self.logger.info("PoE difficulty remains unchanged.")

    # ----------------------------------------------------------------
    #  VALIDATOR MANAGEMENT
    # ----------------------------------------------------------------
    def receive_vrf_output(self, validator_id: str, proof: bytes) -> bool:
        """
        Allows validators to submit their VRF outputs during the commit phase.

        :param validator_id: The identifier of the validator.
        :param proof: The VRF proof bytes.
        :return: True if accepted, False otherwise.
        """
        with self.consensus_lock:
            if self.randao_commit_phase:
                if not self.omc:
                    self.logger.error("OMC not set in ConsensusEngine. Cannot verify validators.")
                    return False
                active_validators = self.omc.get_active_validators()
                if validator_id in active_validators:
                    # Retrieve the alpha for this round
                    alpha = self.alpha_generator.generate_alpha(self.consensus_round)
                    # Retrieve the validator's public key
                    public_key_pem = self._get_validator_public_key(validator_id)
                    if not public_key_pem:
                        self.logger.warning(f"Public key for validator {validator_id} not found. Cannot verify VRF proof.")
                        return False
                    is_valid = self.vrf_utils.vrf_verify(seed=alpha, proof=proof, public_key_pem=public_key_pem)
                    if is_valid:
                        self.vrf_outputs[validator_id] = (proof, proof)  # Assuming beta and proof are same
                        self.logger.info(f"Received and verified VRF output from {validator_id}.")
                        return True
                    else:
                        self.logger.warning(f"Invalid VRF proof from {validator_id}.")
                        return False
                else:
                    self.logger.warning(f"Validator {validator_id} is not active.")
            else:
                self.logger.warning(f"Not in RANDAO commit phase. Cannot accept VRF output from {validator_id}.")
        return False

    def receive_vrf_output_external(self, validator_id: str, proof: bytes) -> bool:
        """
        Allows validators to submit their VRF outputs during the commit phase via external means.

        :param validator_id: The identifier of the validator.
        :param proof: The VRF proof bytes.
        :return: True if accepted, False otherwise.
        """
        return self.receive_vrf_output(validator_id, proof)

    # ----------------------------------------------------------------
    #  SHUTDOWN METHOD
    # ----------------------------------------------------------------
    def shutdown(self):
        """
        Gracefully shuts down the consensus engine.
        """
        self.logger.info("Shutting down ConsensusEngine.")
        # Implement any necessary cleanup here
        # For example, setting a flag to stop the consensus loop
        # Currently, the loop runs infinitely; consider adding a termination condition
        # Example:
        # self.running = False
        # self.consensus_thread.join()
        pass  # Placeholder for actual shutdown logic
