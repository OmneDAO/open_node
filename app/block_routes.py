# block_routes.py

from flask import Blueprint, jsonify, request
from ledger import Ledger
from block import Block

block_bp = Blueprint('block_bp', __name__)

@block_bp.route('/blocks/<int:block_index>', methods=['GET'])
def get_block(block_index):
    """
    Retrieve a specific block by its index.
    """
    block = Ledger()._get_block_by_index(block_index)
    if block:
        return jsonify(block.to_dict()), 200
    else:
        return jsonify({"error": "Block not found"}), 404

@block_bp.route('/blocks/latest', methods=['GET'])
def get_latest_block():
    """
    Retrieve the latest block in the chain.
    """
    block = Ledger().get_latest_block()
    return jsonify(block.to_dict()), 200

@block_bp.route('/blocks', methods=['GET'])
def get_full_chain():
    """
    Retrieve the entire blockchain.
    """
    ledger = Ledger()
    chain = [block.to_dict() for block in ledger.chain]
    return jsonify({"chain": chain}), 200
