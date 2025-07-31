# transfer_routes.py

from flask import Blueprint, jsonify, request, current_app
from decimal import Decimal

transfer_bp = Blueprint('transfer_bp', __name__)

@transfer_bp.route('/api/transfer_coins', methods=['POST'])
def transfer_coins():
    """
    Executes a coin transfer based on an approved transfer request.
    Expects JSON: {
        "from_address": "...",
        "to_address": "...",
        "amount": Decimal,
        "fee": Decimal,
        "hash": "request_id",
        "pub_key": "...",
        "signature": "...",
        "sub_type": "...",
        "type": "..."
    }
    """
    # Get the ledger from the current app context
    ledger = current_app.config.get('ledger')
    if not ledger:
        return jsonify({"error": "Ledger not available"}), 500
        
    try:
        data = request.get_json()

        # Extract the relevant data from the request
        from_address = data.get('from_address')
        to_address = data.get('to_address')
        amount = data.get('amount')
        fee = data.get('fee')
        hash_id = data.get('hash')
        pub_key = data.get('pub_key')
        signature = data.get('signature')
        sub_type = data.get('sub_type')
        type = data.get('type')

        # Validate required data
        if not all([from_address, to_address, amount]):
            return jsonify({"error": "Missing required fields: 'from_address', 'to_address', 'amount'"}), 400

        # Convert amount to Decimal
        try:
            amount_decimal = Decimal(amount)
        except:
            return jsonify({"error": "Invalid amount format."}), 400

        # Check if sender has enough balance
        sender_balance = ledger.omc.get_balance(from_address)
        if sender_balance is None:
            return jsonify({"error": f"Sender address {from_address} does not exist."}), 404
        if sender_balance < amount_decimal:
            return jsonify({"error": f"Insufficient balance in {from_address} to transfer {amount} OMC"}), 400

        # Execute the transfer
        success = ledger.omc.transfer(from_address, to_address, amount_decimal)

        if success:
            return jsonify({"message": "Transfer executed successfully."}), 200
        else:
            return jsonify({"error": "Failed to execute transfer."}), 400

    except Exception as e:
        return jsonify({'error': 'Internal Server Error: Unable to process transfer.'}), 500 