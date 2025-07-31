import json
from typing import Dict

class OpcodeGovernanceTransaction:
    """
    Handles validation and application of opcode-cost governance transactions.
    """
    @staticmethod
    def validate(tx: Dict) -> bool:
        """
        Validate the structure and content of an opcode-cost governance transaction.

        Args:
            tx: The transaction to validate.

        Returns:
            bool: True if the transaction is valid, False otherwise.
        """
        required_fields = {"type", "opcode_costs", "activation_block"}
        if not required_fields.issubset(tx):
            print("Missing required fields in transaction.")
            return False

        if tx["type"] != "opcode_update":
            print("Invalid transaction type.")
            return False

        if not isinstance(tx["opcode_costs"], dict):
            print("opcode_costs must be a dictionary.")
            return False

        if not isinstance(tx["activation_block"], int):
            print("activation_block must be an integer.")
            return False

        return True

    @staticmethod
    def apply(tx: Dict, current_block: int) -> bool:
        """
        Apply the opcode-cost update if the activation block is reached.

        Args:
            tx: The transaction to apply.
            current_block: The current block height.

        Returns:
            bool: True if the update was applied, False otherwise.
        """
        if current_block < tx["activation_block"]:
            print("Activation block not reached.")
            return False

        from app.object_compiler import load_opcode_cost_table
        load_opcode_cost_table(tx["opcode_costs"])
        return True