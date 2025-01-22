# fee_calculator_routes.py

from flask import Blueprint, jsonify, request
from dynamic_fee_calculator import DynamicFeeCalculator

fee_calculator_bp = Blueprint('fee_calculator_bp', __name__)
fee_calculator = DynamicFeeCalculator()

@fee_calculator_bp.route('/fees/calculate', methods=['POST'])
def calculate_fee():
    """
    Calculate dynamic fees based on transaction parameters.
    Expects JSON: {"transaction_size": 250}  # Example parameter
    """
    data = request.json
    transaction_size = data.get("transaction_size")
    if transaction_size is None:
        return jsonify({"error": "No transaction_size provided."}), 400

    fee = fee_calculator.calculate_fee(transaction_size)
    return jsonify({"transaction_size": transaction_size, "fee": str(fee)}), 200
