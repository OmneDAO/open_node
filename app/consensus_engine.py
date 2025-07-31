import hashlib
import logging
import threading
import time
from typing import List, Dict, Optional, Tuple
from datetime import datetime, timezone

import requests  # only if needed for network calls

from vrf_utils import VRFUtils
from crypto_utils import CryptoUtils
from block import Block
from omc import OMC
from ledger import Ledger
from account_manager import AccountManager
from alpha_generator import AlphaGenerator
from staking import StakingMngr


class ConsensusEngine:
    """
    Implements a Hybrid PoS-PoE consensus mechanism with:
      - Fixed block intervals,
      - RANDAO commit/reveal for randomness,
      - Proof of Effort (PoE) puzzle for leader to solve,
      - Basic PoS (staking) references for active validators.

    Concurrency & Locking:
      - This class has its own self.consensus_lock that it uses for orchestrating
        the consensus round scheduling (the `_round_scheduler_loop`).
      - When performing a final block proposal, we also acquire `ledger.lock` 
        inside `_propose_block(...)` to validate/add the block.
      - The Mempool has its own lock. We rely on the approach of:
            "Acquire ledger.lock -> then call mempool methods (like remove_transactions)."
        so we do not attempt to hold mempool.lock first and then ledger.lock.
      - This ordering ensures no lock‐order inversions.
    """

    def __init__(
        self,
        ledger: Ledger,
        omc: OMC,
        account_manager: AccountManager,
        vrf_utils: VRFUtils,
        blockchain,  # typically the ledger or a chain reference
        staking_manager: StakingMngr,
        block_interval_minutes: int = 9,
        randao_commit_duration: int = 30,
        randao_reveal_duration: int = 30,
        poef_task_difficulty: int = 4,
        poef_task_iterations: int = 100000,
        poef_adjustment_interval: int = 100,
        num_leaders: int = 3
    ):
        self.ledger = ledger
        self.omc = omc
        self.account_manager = account_manager
        self.vrf_utils = vrf_utils
        self.blockchain = blockchain
        self.staking_manager = staking_manager

        # Core parameters
        self.block_interval_minutes = block_interval_minutes
        self.randao_commit_duration = randao_commit_duration
        self.randao_reveal_duration = randao_reveal_duration

        self.poef_task_difficulty = poef_task_difficulty
        self.poef_task_iterations = poef_task_iterations
        self.poef_adjustment_interval = poef_adjustment_interval
        self.num_leaders = num_leaders

        self.network_manager = None

        # VRF / randomness state
        self.vrf_outputs: Dict[str, Tuple[bytes, bytes]] = {}
        self.current_randomness: Optional[str] = None
        self.consensus_round: int = 1

        self.leader_pool: List[str] = []
        self.randao_commit_phase = True
        self.phase_in_progress = False

        # This lock controls the entire consensus round scheduling
        # so that only one round at a time can proceed
        self.consensus_lock = threading.Lock()

        # cBFT placeholders
        self.pre_votes: Dict[str, bool] = {}
        self.pre_commits: Dict[str, bool] = {}

        # Logging setup
        self.logger = logging.getLogger('ConsensusEngine')
        self.logger.setLevel(logging.INFO)
        handler = logging.StreamHandler()
        formatter = logging.Formatter('[%(asctime)s] [%(levelname)s] [%(name)s] %(message)s')
        handler.setFormatter(formatter)
        if not self.logger.handlers:
            self.logger.addHandler(handler)

        # For alpha generation used in VRF
        self.alpha_generator = AlphaGenerator(blockchain=self.blockchain)

        self.logger.info("ConsensusEngine initialized.")

        # Background thread that triggers a consensus round every block_interval_minutes
        self.round_scheduler_thread = threading.Thread(
            target=self._round_scheduler_loop, daemon=True
        )
        self.round_scheduler_thread.start()

    def set_network_manager(self, network_manager):
        """
        Sets the external network manager for broadcasting blocks, peer discovery, etc.
        """
        self.network_manager = network_manager
        self.logger.info("NetworkManager set in ConsensusEngine.")

    def _round_scheduler_loop(self):
        """
        Sleeps for `block_interval_minutes` and attempts a new consensus round if
        the mempool has any transactions.
        """
        while True:
            time.sleep(self.block_interval_minutes * 60)
            num_txs = len(self.ledger.mempool.get_transactions())
            if num_txs == 0:
                self.logger.info("No transactions in mempool; skipping round.")
                continue

            self.logger.info(
                f"{num_txs} transactions in mempool. Starting consensus round {self.consensus_round}."
            )
            self._run_single_round()

    def _run_single_round(self):
        """
        Encapsulates a single consensus round:
          1) RANDAO commit (VRF commit)
          2) Wait commit_duration
          3) RANDAO reveal
          4) Aggregate randomness
          5) Select leaders
          6) PoE puzzle by top leader
          7) Propose block
        """
        with self.consensus_lock:
            # 1) RANDAO commit
            self.logger.info(f"Starting RANDAO commit for round {self.consensus_round}.")
            self.vrf_outputs.clear()
            alpha = self.alpha_generator.generate_alpha(self.consensus_round)
            try:
                proof = self.vrf_utils.prove(alpha)
                # Store VRF output under the local node address
                local_node_address = self.ledger.node.address
                self.vrf_outputs[local_node_address] = (proof, proof)
                self.logger.info("Local VRF proof generated.")
            except Exception as e:
                self.logger.error(f"VRF proof generation failed: {e}")
                return

            # 2) Wait commit_duration
            time.sleep(self.randao_commit_duration)

            # 3) RANDAO reveal
            self.logger.info(f"Starting RANDAO reveal for round {self.consensus_round}.")
            time.sleep(self.randao_reveal_duration)

            # 4) Aggregate the randomness
            self._aggregate_randomness(self.consensus_round)
            if not self.current_randomness:
                self.logger.error("Randomness aggregation failed; aborting round.")
                return

            # 5) Select leaders
            self._select_leaders()
            if not self.leader_pool:
                self.logger.error("No leader selected; round aborted.")
                return

            top_leader = self.leader_pool[0]

            # 6) PoE puzzle
            self._handle_proof_of_effort(top_leader)

            # Round done; increment
            self.consensus_round += 1
            self.logger.info(
                f"Consensus round completed. Moving to round {self.consensus_round}."
            )

    def _aggregate_randomness(self, round_number: int):
        """
        Collect VRF outputs from all active validators and aggregate into a single
        SHA-256 random seed.
        """
        self.logger.info(f"Aggregating VRF outputs for round {round_number}.")
        validators = self.omc.get_active_validators()
        collected = []

        for v in validators:
            vrf_out = self.vrf_outputs.get(v)
            if vrf_out:
                # second element is the reveal
                collected.append(vrf_out[1])
            else:
                self.logger.warning(f"Validator {v} did not submit VRF output.")

        if collected:
            concatenated = b''.join(collected)
            self.current_randomness = hashlib.sha256(concatenated).hexdigest()
            self.logger.info(f"Aggregated randomness: {self.current_randomness}")
        else:
            self.logger.error("No VRF proofs collected; randomness not generated.")
            self.current_randomness = None

    def _select_leaders(self):
        """
        Sort active validators by a hash (randomness + address) to pick top N leaders.
        """
        if not self.current_randomness:
            self.logger.error("No randomness available for leader selection.")
            return

        validators = self.omc.get_active_validators()
        if not validators:
            self.logger.error("No active validators available for leader selection.")
            return

        scores = {}
        for v in validators:
            data = (self.current_randomness + v).encode('utf-8')
            # Sort by hash for fairness
            scores[v] = int(hashlib.sha256(data).hexdigest(), 16)

        sorted_validators = sorted(scores.items(), key=lambda x: x[1], reverse=True)
        self.leader_pool = [v[0] for v in sorted_validators[:self.num_leaders]]
        self.logger.info(f"Selected leaders: {self.leader_pool}")

    def _handle_proof_of_effort(self, leader: str):
        """
        Leader attempts the PoE puzzle: find a nonce so that hash(vrf_hex-nonce) starts with
        '0' * self.poef_task_difficulty.
        """
        self.logger.info(f"Leader {leader} performing Proof of Effort.")
        vrf_out = self.vrf_outputs.get(leader)
        if not vrf_out:
            self.logger.error(f"No VRF output for leader {leader}.")
            return

        # second part of tuple is the reveal
        proof = vrf_out[1]
        poe_hash = self._perform_proof_of_effort(proof.hex())
        if not self._verify_proof_of_effort(poe_hash):
            self.logger.warning(f"Leader {leader} PoE invalid; potential penalty.")
            return
        self.logger.info(f"Leader {leader} PoE succeeded (nonce found). Proposing block.")
        self._propose_block(leader, poe_hash)

    def _propose_block(self, leader: str, proof: str):
        """
        Leader constructs a new block from mempool transactions, obtains ledger.lock,
        validates & adds block, finalizes, removes TX from mempool, broadcasts, etc.
        """
        if not self.ledger:
            self.logger.error("Ledger not set; cannot propose block.")
            return

        # 1) Gather transactions for this block
        txs = self.ledger.mempool.get_transactions_for_block()
        if not txs:
            self.logger.info("No transactions to propose in block.")
            return

        # 2) Build block
        prev_block = self.ledger.get_latest_block()
        prev_hash = prev_block.hash if prev_block else "0" * 64
        index = (prev_block.index + 1) if prev_block else 1

        new_block = Block(
            index=index,
            previous_hash=prev_hash,
            transactions=txs,
            signatures=[],  # cBFT signatures, if any
            timestamp=datetime.now(timezone.utc).isoformat(),
            leader=leader,
            proof_of_effort=proof
        )

        # 3) Acquire ledger lock to validate + add block
        with self.ledger.lock:
            if self.ledger.validate_block(new_block):
                if self.ledger.add_block(new_block):
                    # ledger.add_block calls self.mempool.remove_transactions(...) by hash
                    self.logger.info(f"Block {index} proposed by {leader} added to ledger.")
                    # finalize => apply TX to accounts, mint reward
                    self.ledger.finalize_block(new_block)

                    # Optionally broadcast
                    if self.network_manager:
                        self.network_manager.broadcast_block(new_block.to_dict())

                    # Basic reward for the leader
                    self.omc.reward_validator(leader, index)

                    # Possibly adjust PoE difficulty every N blocks
                    if index % self.poef_adjustment_interval == 0:
                        self._adjust_poef_difficulty()
                else:
                    self.logger.warning(f"Block {index} rejected by ledger.")
            else:
                self.logger.warning(f"Block {index} fails validation.")

    def _perform_proof_of_effort(self, vrf_hex: str) -> str:
        """
        Tries up to poef_task_iterations attempts to find a nonce s.t. 
        sha256(f"{vrf_hex}-{nonce}") starts with '0'*poef_task_difficulty.
        Returns the resulting hash if found, else ''.
        """
        nonce = 0
        target = '0' * self.poef_task_difficulty
        while nonce < self.poef_task_iterations:
            data = f"{vrf_hex}-{nonce}".encode('utf-8')
            h = hashlib.sha256(data).hexdigest()
            if h.startswith(target):
                self.logger.debug(f"PoE success: nonce={nonce}, hash={h}")
                return h
            nonce += 1
        return ''

    def _verify_proof_of_effort(self, proof: str) -> bool:
        """
        Checks if the given 'proof' (leading zero hash) meets the difficulty target.
        """
        if not proof:
            return False
        target = '0' * self.poef_task_difficulty
        return proof.startswith(target)

    def _adjust_poef_difficulty(self):
        """
        Adjusts PoE difficulty based on the average block time over the last N blocks
        (poef_adjustment_interval).
        """
        try:
            avg_time = self.ledger.calculate_average_block_time(last_n_blocks=self.poef_adjustment_interval)
        except Exception:
            avg_time = 60  # fallback

        desired = 60  # target block time in seconds
        if avg_time < desired * 0.9:
            self.poef_task_difficulty += 1
            self.logger.info(f"Increasing PoE difficulty to {self.poef_task_difficulty}.")
        elif avg_time > desired * 1.1 and self.poef_task_difficulty > 1:
            self.poef_task_difficulty -= 1
            self.logger.info(f"Decreasing PoE difficulty to {self.poef_task_difficulty}.")
        else:
            self.logger.info("PoE difficulty remains unchanged.")

    def shutdown(self):
        """
        Gracefully shuts down the consensus engine. 
        Typically, you'd join the round_scheduler_thread or mark a stop flag.
        """
        self.logger.info("Shutting down ConsensusEngine.")
        # If additional cleanup is needed, do it here (e.g. set a stop event, join threads).
