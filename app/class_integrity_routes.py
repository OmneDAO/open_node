# class_integrity_routes.py

from flask import Blueprint, jsonify, request
from class_integrity import ClassIntegrity

class_integrity_bp = Blueprint('class_integrity_bp', __name__)
class_integrity = ClassIntegrity()

@class_integrity_bp.route('/integrity/check', methods=['POST'])
def check_class_integrity():
    """
    Perform a class integrity check on a given script or module.
    Expects JSON: {"script_name": "block.py"}
    """
    data = request.json
    script_name = data.get("script_name")
    if not script_name:
        return jsonify({"error": "No script_name provided."}), 400

    result = class_integrity.check_integrity(script_name)
    return jsonify({"script_name": script_name, "integrity_passed": result}), 200
