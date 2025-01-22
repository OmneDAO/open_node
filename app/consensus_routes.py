# consensus_routes.py

from flask import Blueprint, jsonify, request
from consensus_engine import ConsensusEngine

consensus_bp = Blueprint('consensus_bp', __name__)
consensus_engine = ConsensusEngine()  # Initialize appropriately

@consensus_bp.route('/consensus/status', methods=['GET'])
def consensus_status():
    """
    Retrieve the current status of the consensus engine.
    """
    status = {
        "current_block_index": consensus_engine.current_block_index,
        "active_validators": len(consensus_engine.list_validators())
    }
    return jsonify(status), 200

@consensus_bp.route('/consensus/validator_selection', methods=['GET'])
def select_validator():
    """
    Trigger manual validator selection (for testing or specific operations).
    """
    validators = consensus_engine.list_validators()
    selected = consensus_engine.select_validator(validators)
    if selected:
        return jsonify({"selected_validator": selected}), 200
    else:
        return jsonify({"error": "No validator selected."}), 400
