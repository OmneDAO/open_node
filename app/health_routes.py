# health_routes.py

from flask import Blueprint, jsonify

health_bp = Blueprint('health_bp', __name__)

@health_bp.route('/api/health', methods=['GET'])
def health_check():
    """
    Health check endpoint to verify node availability.
    """
    return jsonify({"status": "ok"}), 200 