# transaction_routes.py

from flask import Blueprint, jsonify, request, current_app
from ledger import Ledger

transaction_bp = Blueprint('transaction_bp', __name__)

@transaction_bp.route('/api/transaction/receive_transaction', methods=['POST'])
def receive_transaction():
    """
    Endpoint to receive a new transaction from a peer.
    """
    # Get the ledger from the current app context
    ledger = current_app.config.get('ledger')
    if not ledger:
        return jsonify({"error": "Ledger not available"}), 500
        
    transaction = request.json
    if not transaction:
        return jsonify({"error": "No transaction data received."}), 400

    # Validate the transaction
    if not ledger.account_manager.validate_transaction(transaction):
        return jsonify({"error": "Invalid transaction."}), 400

    # Add to mempool
    if ledger.mempool.add_transaction(transaction):
        return jsonify({"message": f"Transaction {transaction.get('hash')} added to mempool."}), 200
    else:
        return jsonify({"error": f"Transaction {transaction.get('hash')} failed to add to mempool."}), 400 