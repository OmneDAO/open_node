import json
from typing import Dict

# Global opcode cost table
OPCOST: Dict[str, int] = {}

def load_opcode_cost_table(opcode_costs: Dict[str, int]) -> None:
    """
    Load and update the global opcode cost table.

    Args:
        opcode_costs: A dictionary mapping opcodes to their costs.
    """
    global OPCOST
    OPCOST.update(opcode_costs)
    print("Opcode cost table updated:", OPCOST)