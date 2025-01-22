# ~/app/verifier.py

import logging
import random
import math
import json

from utils import QuantumUtils

class Verifier:
    def __init__(self, ledger):
        self.nodes = []
        self.staking_agreements = []
        self.ledger = ledger  # Reference to Ledger instance

    def add_node(self, node):
        """Add a full Node object or dict to the verifier's list."""
        if node not in self.nodes:
            self.nodes.append(node)
            logging.info(f"Node added to verifier: {node}")

    def update_staking_agreements(self, new_staking_agreements):
        """
        Update the verifier's staking agreements list by merging new agreements.
        This method adds only new agreements that are not already present, based on unique contract IDs.
        """
        existing_contract_ids = {agreement['contract_id'] for agreement in self.staking_agreements}

        for agreement in new_staking_agreements:
            if agreement['contract_id'] not in existing_contract_ids:
                self.staking_agreements.append(agreement)
                existing_contract_ids.add(agreement['contract_id'])

        logging.info(f"Staking agreements updated: {len(self.staking_agreements)} agreements.")
    
    def calculate_stake_weight_for_node(self, node):
        try:
            node_address = getattr(node, 'address', node.get('address'))
            if not node_address:
                logging.error(f"Node address not found for node: {node}")
                return

            # Log the staking agreements associated with the node
            logging.debug(f"Staking agreements: {self.staking_agreements}")

            # Calculate the staked amount
            amount = self.get_staked_amount_for_node(node_address)
            if amount == 0:
                logging.warning(f"No staked amount found for node: {node_address}. Verify staking setup.")

            # Set the stake weight based on the staked amount
            if isinstance(node, dict):
                node['stake_weight'] = amount
            else:
                node.stake_weight = amount

            logging.info(f"Calculated stake weight for node {node_address}: {amount}")

        except Exception as e:
            logging.error(f"Error calculating stake weight for node: {node}. Exception: {e}")
            
    def get_staked_amount_for_node(self, node_address, staking_agreements=None):
        """
        Calculate the total staked amount for a given node address.
        """
        if staking_agreements is None:
            staking_agreements = self.staking_agreements

        total_staked = 0

        # Iterate over staking agreements to calculate total staked for the node
        for agreement in staking_agreements:
            try:
                if not isinstance(agreement, dict):
                    logging.error(f"Invalid agreement type: {type(agreement)}. Expected a dictionary.")
                    continue

                agreement_node_address = agreement.get('node_address')
                amount = agreement.get('amount', 0)
                
                if agreement_node_address == node_address and isinstance(amount, (int, float)):
                    total_staked += amount
                    logging.info(f"Included stake: {amount} for node: {agreement_node_address}")
                elif agreement_node_address != node_address:
                    logging.debug(f"Skipping agreement for node: {agreement_node_address} (seeking {node_address}).")
                else:
                    logging.warning(f"Agreement amount is not a valid number: {amount}. Skipping.")

            except Exception as e:
                logging.error(f"Error processing agreement: {agreement}. Exception: {e}")

        logging.info(f"Total staked for node {node_address}: {total_staked}")
        return total_staked

    def get_contracts_count_for_node(self, node_address, staking_agreements=None):
        if staking_agreements is None:
            staking_agreements = self.staking_agreements

        contracts_count = 0
        for agreement in staking_agreements:
            if agreement.get('node_address') == node_address:
                contracts_count += 1
        return contracts_count

    def get_withdrawals_count_for_node(self, node_address, staking_agreements=None):
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
                logging.error(f"Node not verified: {current_node}")
                return False  # Do not select unverified nodes

        return True

    def select_validator(self, block):
        # Ensure stake weights are updated before selection
        self.calculate_stake_weights()

        # Compute the total stake weight for all nodes
        total_stake_weight = sum(node.get('stake_weight', 0) for node in self.nodes)

        if total_stake_weight <= 0:
            logging.error("Total stake weight is non-positive. Cannot select validator.")
            return None

        # Scale factor to prevent precision issues with very small or large values
        scale_factor = max(1, 1000 // total_stake_weight)
        max_value = int(total_stake_weight * scale_factor)

        logging.debug(f"Selecting validator with max value: {max_value}")

        # Try to generate a quantum random number, fallback to pseudo-random if necessary
        try:
            quantum_random_number = QuantumUtils.quantum_random_int(max_value) / scale_factor
        except ValueError as e:
            logging.error(f"Error generating quantum random number: {e}. Falling back to pseudo-random.")
            quantum_random_number = random.uniform(0, total_stake_weight)

        cumulative_stake_weight = 0

        # Iterate through nodes to select a validator based on cumulative stake weight
        for node in self.nodes:
            node_stake_weight = node.get('stake_weight', 0)
            cumulative_stake_weight += node_stake_weight

            if cumulative_stake_weight > quantum_random_number:
                # Ensure the selected node has all required attributes
                if all(attr in node for attr in ['address', 'steward']):
                    logging.info(f"Validator selected: {node['address']} with steward {node['steward']}.")
                    return node
                else:
                    logging.error(f"Selected validator is missing required attributes: {node}. Skipping validator selection.")
        
        logging.warning("No validator was selected, returning None.")
        return None

    def verify_classes(self, known_hashes):
        """
        Verify class hashes to ensure integrity.
        This is a placeholder method. Implement actual verification logic as per your security requirements.
        """
        # Example verification logic
        try:
            for class_name, class_hash in known_hashes.items():
                local_hash = self.serialize_and_create_single_hash(getattr(self.ledger, class_name))
                if local_hash != class_hash:
                    logging.error(f"Class integrity verification failed for {class_name}.")
                    return False
            logging.info("All class hashes verified successfully.")
            return True
        except Exception as e:
            logging.error(f"Error during class integrity verification: {e}")
            return False

    def serialize_and_create_single_hash(self, cls) -> str:
        """
        Serialize a class and create its hash.
        """
        try:
            class_string = json.dumps(cls.__dict__, sort_keys=True)
            return hashlib.sha256(class_string.encode()).hexdigest()
        except Exception as e:
            logging.error(f"Failed to serialize and hash class {cls}: {e}")
            return ""
