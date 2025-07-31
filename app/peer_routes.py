# peer_routes.py

from flask import Blueprint, jsonify, request, current_app
from ledger import Ledger

peer_bp = Blueprint('peer_bp', __name__)

@peer_bp.route('/api/peer/add_peer', methods=['POST'])
def add_peer_endpoint():
    """
    Endpoint to add a new peer.
    Expects JSON: {"peer_url": "http://peer-address:port"}
    """
    # Get the network manager from the current app context
    network_manager = current_app.config.get('network_manager')
    if not network_manager:
        return jsonify({"error": "Network manager not available"}), 500
        
    data = request.json
    peer_url = data.get("peer_url")
    if not peer_url:
        return jsonify({"error": "No peer_url provided."}), 400

    network_manager.add_peer(peer_url)
    return jsonify({"message": f"Peer {peer_url} added."}), 200

@peer_bp.route('/api/peer/peers', methods=['GET'])
def list_peers():
    """
    Endpoint to retrieve the list of known peers.
    """
    # Get the network manager from the current app context
    network_manager = current_app.config.get('network_manager')
    if not network_manager:
        return jsonify({"error": "Network manager not available"}), 500
        
    with network_manager.lock:
        peers = list(network_manager.peers)
    return jsonify({"peers": peers}), 200 