# verifier.py

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
        self.nodes: List[Dict] = []  # This will hold nodes as dictionaries (or objects convertible to dicts)
        self.staking_agreements: List[Dict] = []
        self.ledger = ledger  # Reference to Ledger instance

    def add_node(self, node):
        """Add a full Node object or dict to the verifier's list."""
        if node not in self.nodes:
            self.nodes.append(node)
            logger.info(f"Node added to verifier: {node}")

    def update_staking_agreements(self, new_staking_agreements: List[Dict]):
        """
        Update the verifier's staking agreements list by merging new agreements.
        This method adds only new agreements that are not already present, based on unique contract IDs.
        """
        existing_contract_ids = {agreement['contract_id'] for agreement in self.staking_agreements}

        for agreement in new_staking_agreements:
            if agreement['contract_id'] not in existing_contract_ids:
                self.staking_agreements.append(agreement)
                existing_contract_ids.add(agreement['contract_id'])

        logger.info(f"Staking agreements updated: {len(self.staking_agreements)} agreements.")
    
    def calculate_stake_weight_for_node(self, node):
        try:
            # Support both dict and object representations
            node_address = node.get('address') if isinstance(node, dict) else getattr(node, 'address', None)
            if not node_address:
                logger.error(f"Node address not found for node: {node}")
                return

            logger.debug(f"Staking agreements: {self.staking_agreements}")

            amount = self.get_staked_amount_for_node(node_address)
            if amount == 0:
                logger.warning(f"No staked amount found for node: {node_address}. Verify staking setup.")

            if isinstance(node, dict):
                node['stake_weight'] = amount
            else:
                node.stake_weight = amount

            logger.info(f"Calculated stake weight for node {node_address}: {amount}")
        except Exception as e:
            logger.error(f"Error calculating stake weight for node: {node}. Exception: {e}")
            
    def get_staked_amount_for_node(self, node_address: str, staking_agreements: Optional[List[Dict]] = None) -> float:
        """
        Calculate the total staked amount for a given node address.
        """
        if staking_agreements is None:
            staking_agreements = self.staking_agreements

        total_staked = 0
        for agreement in staking_agreements:
            try:
                if not isinstance(agreement, dict):
                    logger.error(f"Invalid agreement type: {type(agreement)}. Expected a dictionary.")
                    continue

                if agreement.get('node_address') == node_address:
                    amount = agreement.get('amount', 0)
                    if isinstance(amount, (int, float)):
                        total_staked += amount
                        logger.info(f"Included stake: {amount} for node: {node_address}")
                    else:
                        logger.warning(f"Agreement amount is not a valid number: {amount}. Skipping.")
            except Exception as e:
                logger.error(f"Error processing agreement: {agreement}. Exception: {e}")

        logger.info(f"Total staked for node {node_address}: {total_staked}")
        return total_staked

    def get_contracts_count_for_node(self, node_address: str, staking_agreements: Optional[List[Dict]] = None) -> int:
        if staking_agreements is None:
            staking_agreements = self.staking_agreements

        contracts_count = 0
        for agreement in staking_agreements:
            if agreement.get('node_address') == node_address:
                contracts_count += 1
        return contracts_count

    def get_withdrawals_count_for_node(self, node_address: str, staking_agreements: Optional[List[Dict]] = None) -> int:
        if staking_agreements is None:
            staking_agreements = self.staking_agreements

        total_withdrawals = 0
        for agreement in staking_agreements:
            if agreement.get('node_address') == node_address:
                total_withdrawals += agreement.get('withdrawals', 0)
        return total_withdrawals

    def calculate_stake_weights(self):
        """Calculate stake weights for all nodes."""
        for node in self.nodes:
            self.calculate_stake_weight_for_node(node)

    def normalize_amount(self, total_staked_amount: float) -> float:
        """Normalizes the total staked amount using a logarithmic scale."""
        adjusted_amount = max(1, total_staked_amount)
        return math.log(adjusted_amount) + 1

    def normalize_contracts(self, total_contracts: int) -> float:
        """Normalizes the number of contracts using a logarithmic scale."""
        adjusted_contracts = max(1, total_contracts)
        return math.log(adjusted_contracts) + 1

    def normalize_withdrawals(self, total_withdrawals: int) -> float:
        """Normalizes the number of withdrawals using a logarithmic scale, inversely."""
        adjusted_withdrawals = max(1, total_withdrawals)
        return 1 / (math.log(adjusted_withdrawals) + 1)

    def validate_stake(self, block) -> bool:
        self.calculate_stake_weights()

        total_stake_weight = sum(
            node.get('stake_weight', 0) if isinstance(node, dict) else getattr(node, 'stake_weight', 0)
            for node in self.nodes
        )
        random_number = random.uniform(0, total_stake_weight)
        cumulative_stake_weight = 0

        for current_node in self.nodes:
            node_stake_weight = current_node.get('stake_weight', 0) if isinstance(current_node, dict) else getattr(current_node, 'stake_weight', 0)
            cumulative_stake_weight += node_stake_weight
            if cumulative_stake_weight > random_number and current_node not in self.nodes:
                logger.error(f"Node not verified: {current_node}")
                return False
        
        return True

    def select_validator(self, block) -> Optional[Dict]:
        # Ensure stake weights are updated before selection
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
            logger.error(f"Error generating quantum random number: {e}. Falling back to pseudo-random.")
            quantum_random_number = random.uniform(0, total_stake_weight)

        cumulative_stake_weight = 0
        for node in self.nodes:
            node_stake_weight = node.get('stake_weight', 0)
            cumulative_stake_weight += node_stake_weight
            if cumulative_stake_weight > quantum_random_number:
                if all(attr in node for attr in ['address', 'steward']):
                    logger.info(f"Validator selected: {node['address']} with steward {node['steward']}.")
                    return node
                else:
                    logger.error(f"Selected validator is missing required attributes: {node}. Skipping validator selection.")
        
        logger.warning("No validator was selected, returning None.")
        return None

    def verify_classes(self, known_hashes: Dict) -> bool:
        """
        Verify class hashes to ensure integrity.
        Implement actual verification logic as per your security requirements.
        """
        try:
            for class_name, class_hash in known_hashes.items():
                local_hash = self.serialize_and_create_single_hash(getattr(self.ledger, class_name))
                if local_hash != class_hash:
                    logger.error(f"Class integrity verification failed for {class_name}.")
                    return False
            logger.info("All class hashes verified successfully.")
            return True
        except Exception as e:
            logger.error(f"Error during class integrity verification: {e}")
            return False

    def serialize_and_create_single_hash(self, cls) -> str:
        try:
            class_string = json.dumps(cls.__dict__, sort_keys=True)
            return hashlib.sha256(class_string.encode()).hexdigest()
        except Exception as e:
            logger.error(f"Failed to serialize and hash class {cls}: {e}")
            return ""

    # <<-- NEW METHOD ADDED BELOW -->> 
    def get_all_nodes(self) -> List[Dict]:
        """
        Retrieves a list of all nodes currently known to the verifier.
        
        :return: A copy of the list of nodes.
        """
        return self.nodes.copy()

    def normalize_amount(self, total_staked_amount):
        """Normalizes the total staked amount using a logarithmic scale."""
        adjusted_amount = max(1, total_staked_amount)
        return math.log(adjusted_amount) + 1

    def normalize_contracts(self, total_contracts):
        """Normalizes the number of contracts using a logarithmic scale."""
        adjusted_contracts = max(1, total_contracts)
        return math.log(adjusted_contracts) + 1

    def normalize_withdrawals(self, total_withdrawals):
        """Normalizes the number of withdrawals using a logarithmic scale, inversely."""
        adjusted_withdrawals = max(1, total_withdrawals)
        return 1 / (math.log(adjusted_withdrawals) + 1)

    def validate_stake(self, block):
        self.calculate_stake_weights()

        total_stake_weight = sum(getattr(node, 'stake_weight', node.get('stake_weight', 0)) for node in self.nodes)
        random_number = random.uniform(0, total_stake_weight)
        cumulative_stake_weight = 0

        for current_node in self.nodes:
            node_stake_weight = getattr(current_node, 'stake_weight', current_node.get('stake_weight', 0))
            cumulative_stake_weight += node_stake_weight
            if cumulative_stake_weight > random_number and current_node not in self.nodes:
                logger.error(f"Node not verified: {current_node}")
                return False
        
        return True

    def select_validator(self, block):
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
            logger.error(f"Error generating quantum random number: {e}. Falling back to pseudo-random.")
            quantum_random_number = random.uniform(0, total_stake_weight)

        cumulative_stake_weight = 0
        for node in self.nodes:
            node_stake_weight = node.get('stake_weight', 0)
            cumulative_stake_weight += node_stake_weight

            if cumulative_stake_weight > quantum_random_number:
                if all(attr in node for attr in ['address', 'steward']):
                    logger.info(f"Validator selected: {node['address']} with steward {node['steward']}.")
                    return node
                else:
                    logger.error(f"Selected validator is missing required attributes: {node}. Skipping validator selection.")
        
        logger.warning("No validator was selected, returning None.")
        return None

    def verify_classes(self, known_hashes):
        try:
            for class_name, class_hash in known_hashes.items():
                local_hash = self.serialize_and_create_single_hash(getattr(self.ledger, class_name))
                if local_hash != class_hash:
                    logger.error(f"Class integrity verification failed for {class_name}.")
                    return False
            logger.info("All class hashes verified successfully.")
            return True
        except Exception as e:
            logger.error(f"Error during class integrity verification: {e}")
            return False

    def serialize_and_create_single_hash(self, cls) -> str:
        try:
            class_string = json.dumps(cls.__dict__, sort_keys=True)
            return hashlib.sha256(class_string.encode()).hexdigest()
        except Exception as e:
            logger.error(f"Failed to serialize and hash class {cls}: {e}")
            return ""
