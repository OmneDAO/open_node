import logging
import random
import math
import json
import hashlib
from typing import Dict, List, Optional

from utils import QuantumUtils

logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)

class Verifier:
    def __init__(self, ledger):
        """
        :param ledger: A reference to the Ledger instance.
        """
        self.nodes: List[Dict] = []
        self.staking_agreements: List[Dict] = []
        self.ledger = ledger

    def add_node(self, node):
        """Add a full Node object or dict to the verifier's list."""
        if node not in self.nodes:
            self.nodes.append(node)
            logger.info(f"Node added to verifier: {node}")

    def update_staking_agreements(self, new_staking_agreements: List[Dict]):
        """
        Merge new staking agreements (dicts) into self.staking_agreements
        by unique contract_id.
        """
        existing_contract_ids = {agr['contract_id'] for agr in self.staking_agreements}
        for agreement in new_staking_agreements:
            if agreement['contract_id'] not in existing_contract_ids:
                self.staking_agreements.append(agreement)
                existing_contract_ids.add(agreement['contract_id'])
        logger.info(f"Staking agreements updated: {len(self.staking_agreements)} agreements.")

    # ----------------------------------------------------------------
    #  New Method: verify_transactions
    # ----------------------------------------------------------------
    def verify_transactions(self, block, block_signatures) -> bool:
        """
        Verifies that the block’s transactions and signatures are valid.

        :param block: The Block instance being validated.
        :param block_signatures: Typically block.signatures (list of dict).
        :return: True if all checks pass, otherwise False.
        """
        # 1) First, let the block check its own signatures.
        #    The block might have a method like block.verify_messages(...)
        #    that uses ledger.crypto_utils and ledger.account_manager.
        if not block.verify_messages(self.ledger.crypto_utils, self.ledger.account_manager):
            logger.error("Block messages/signatures verification failed.")
            return False

        # 2) Optionally, check each transaction in the block.
        #    For production, you might do e.g., signature checks, 
        #    or reference the ledger to ensure no double spends, etc.
        for tx in block.transactions:
            # Example: check required transaction fields
            if 'sender' not in tx or 'hash' not in tx:
                logger.error(f"Transaction missing sender/hash: {tx}")
                return False
            # Additional logic: check ledger for sender balance, etc. 
            # Usually done in the ledger’s finalize or block validation step.

        # If we reached here, everything is considered valid.
        return True

    def calculate_stake_weight_for_node(self, node):
        """
        Example method that sets node['stake_weight'] 
        based on all known staking agreements in self.staking_agreements.
        """
        try:
            node_address = node.get('address') if isinstance(node, dict) else getattr(node, 'address', None)
            if not node_address:
                logger.error(f"Node address not found for node: {node}")
                return

            amount = self.get_staked_amount_for_node(node_address)
            if amount == 0:
                logger.warning(f"No staked amount found for node: {node_address}.")

            if isinstance(node, dict):
                node['stake_weight'] = amount
            else:
                node.stake_weight = amount

            logger.info(f"Calculated stake weight for node {node_address}: {amount}")
        except Exception as e:
            logger.error(f"Error calculating stake weight for node {node}. Exception: {e}")

    def get_staked_amount_for_node(self, node_address: str, staking_agreements: Optional[List[Dict]] = None) -> float:
        """
        Sum up staked amounts from each agreement matching `node_address`.
        """
        if staking_agreements is None:
            staking_agreements = self.staking_agreements

        total_staked = 0
        for agreement in staking_agreements:
            try:
                if agreement.get('node_address') == node_address:
                    amt = agreement.get('amount', 0)
                    if isinstance(amt, (int, float)):
                        total_staked += amt
                        logger.debug(f"Added {amt} stake for node: {node_address}")
                    else:
                        logger.warning(f"Invalid stake amount in agreement: {agreement}")
            except Exception as e:
                logger.error(f"Error in agreement: {agreement}, {e}")

        logger.info(f"Total staked for node {node_address}: {total_staked}")
        return total_staked

    def get_contracts_count_for_node(self, node_address: str, staking_agreements: Optional[List[Dict]] = None) -> int:
        if staking_agreements is None:
            staking_agreements = self.staking_agreements
        return sum(1 for agr in staking_agreements if agr.get('node_address') == node_address)

    def get_withdrawals_count_for_node(self, node_address: str, staking_agreements: Optional[List[Dict]] = None) -> int:
        if staking_agreements is None:
            staking_agreements = self.staking_agreements
        return sum(agr.get('withdrawals', 0) for agr in staking_agreements if agr.get('node_address') == node_address)

    def calculate_stake_weights(self):
        """
        Recompute stake weights for all known nodes.
        """
        for node in self.nodes:
            self.calculate_stake_weight_for_node(node)

    def normalize_amount(self, total_staked_amount: float) -> float:
        """
        Example function: logs(Stake) + 1
        """
        adjusted = max(1, total_staked_amount)
        return math.log(adjusted) + 1

    def normalize_contracts(self, total_contracts: int) -> float:
        adjusted = max(1, total_contracts)
        return math.log(adjusted) + 1

    def normalize_withdrawals(self, total_withdrawals: int) -> float:
        """
        Inverted weighting (the more withdrawals, the less the weight).
        """
        adj = max(1, total_withdrawals)
        return 1 / (math.log(adj) + 1)

    def validate_stake(self, block) -> bool:
        """
        Example placeholder that picks a random node if stake weighting is good.
        """
        self.calculate_stake_weights()

        total_stake_weight = sum(node.get('stake_weight', 0) for node in self.nodes)
        random_number = random.uniform(0, total_stake_weight)
        cumulative_weight = 0
        for current_node in self.nodes:
            node_stake = current_node.get('stake_weight', 0)
            cumulative_weight += node_stake
            if cumulative_weight > random_number and current_node not in self.nodes:
                logger.error(f"Node not verified? {current_node}")
                return False
        return True

    def select_validator(self, block):
        """
        Example function to choose a validator from the node list 
        based on 'stake_weight'.
        """
        self.calculate_stake_weights()
        total_stake_weight = sum(node.get('stake_weight', 0) for node in self.nodes)
        if total_stake_weight <= 0:
            logger.error("Total stake weight is non-positive. Cannot select validator.")
            return None

        scale_factor = max(1, 1000 // total_stake_weight)
        max_value = int(total_stake_weight * scale_factor)
        logger.debug(f"Selecting validator with max value: {max_value}")

        try:
            quantum_random_number = QuantumUtils.quantum_random_int(max_value) / scale_factor
        except ValueError as e:
            logger.error(f"Error generating quantum random number: {e}, fallback to pseudo-random.")
            quantum_random_number = random.uniform(0, total_stake_weight)

        cumulative = 0
        for node in self.nodes:
            node_stake = node.get('stake_weight', 0)
            cumulative += node_stake
            if cumulative > quantum_random_number:
                if all(attr in node for attr in ['address', 'steward']):
                    logger.info(f"Validator selected: {node['address']} with steward {node['steward']}")
                    return node
                else:
                    logger.error(f"Selected validator missing 'address' or 'steward': {node}")
        logger.warning("No validator selected, returning None.")
        return None

    def verify_classes(self, known_hashes: Dict) -> bool:
        """
        If you store known reference hashes for ledger classes, 
        compare them with runtime computed hashes for class integrity.
        """
        try:
            for class_name, stored_hash in known_hashes.items():
                local_obj = getattr(self.ledger, class_name, None)
                if local_obj is None:
                    logger.error(f"Ledger has no attribute {class_name}, cannot verify.")
                    return False

                local_hash = self.serialize_and_create_single_hash(local_obj)
                if local_hash != stored_hash:
                    logger.error(f"Class integrity verification failed for {class_name}.")
                    return False
            logger.info("All class hashes verified successfully.")
            return True
        except Exception as e:
            logger.error(f"Error during class integrity verification: {e}")
            return False

    def serialize_and_create_single_hash(self, cls) -> str:
        """
        Serializes an object's __dict__ and returns its SHA-256.
        You can customize how to handle nested objects.
        """
        try:
            # Very naive serialization: just take cls.__dict__ 
            class_string = json.dumps(cls.__dict__, sort_keys=True, default=str)
            return hashlib.sha256(class_string.encode()).hexdigest()
        except Exception as e:
            logger.error(f"Failed to serialize and hash class {cls}: {e}")
            return ""

    def get_all_nodes(self) -> List[Dict]:
        """
        Return a copy of the list of nodes known by the verifier.
        """
        return self.nodes.copy()
