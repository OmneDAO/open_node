"""
Node API Routes for OMNE Open Source Valid        # Essential cryptographic classes that must be identical across implementations
        essential_classes = {
            'CryptoUtils': 'app.crypto_utils.CryptoUtils',
            'MerkleTree': 'app.merkle.MerkleTree', 
            'VRFUtils': 'app.vrf_utils.VRFUtils',
            'DecimalEncoder': 'app.crypto_utils.DecimalEncoder',
            'TransferRequest': 'app.omc.TransferRequest',
            'OMC': 'app.omc.OMC',
            'Mempool': 'app.mempool.Mempool',
            'ConsensusEngine': 'app.consensus_engine.ConsensusEngine'
        }
This module provides essential API endpoints required for nexum validation and network participation.
These endpoints allow external validation services to verify node integrity, capabilities, and status.

Required for Nexum Compliance:
- /api/node/class_hashes - Class hash integrity verification
- /api/node/info - Node version and identity information  
- /api/node/capabilities - Node operational capabilities

Security Note: These endpoints provide verification data for external validation.
Reference hashes are retrieved from trusted sources (genesis block, verified nodes, external services)
to prevent malicious nodes from spoofing verification data.
"""

from flask import Blueprint, jsonify, current_app
from datetime import datetime, timezone
import logging
import os
import importlib
import socket
from typing import Dict, Any

from class_integrity_verifier import ClassIntegrityVerifier

# Create blueprint for node API routes
node_api = Blueprint('node_api', __name__)
logger = logging.getLogger(__name__)

@node_api.route('/api/node/class_hashes', methods=['GET'])
def get_node_class_hashes():
    """
    Return the class hashes of this node's implementation for integrity verification.
    Used by the Nexum relay and other nodes to verify this node's legitimacy.

    This endpoint provides SHA-256 hashes of critical blockchain classes to enable
    external verification against trusted reference implementations.

    Returns:
        JSON: Dictionary mapping class names to their SHA-256 hashes
    """
    try:
        # Define the essential cryptographic classes that need verification
        # These are core mathematical/cryptographic functions that must be identical
        # across all nodes for network security, without genesis-specific functionality
        # Essential cryptographic classes for nexum validation
        essential_classes = {
            'CryptoUtils': 'app.crypto_utils.CryptoUtils',
            'MerkleTree': 'app.merkle.MerkleTree', 
            'VRFUtils': 'app.vrf_utils.VRFUtils',
            'DecimalEncoder': 'app.crypto_utils.DecimalEncoder',
            'TransferRequest': 'app.omc.TransferRequest',
            'OMC': 'app.omc.OMC',
            'Mempool': 'app.mempool.Mempool'
        }
        
        # Import and get actual class objects
        actual_classes = {}
        for class_name, module_path in essential_classes.items():
            try:
                # Dynamic import for each class
                module_name = '.'.join(module_path.split('.')[:-1])  # Remove class name
                class_obj_name = module_path.split('.')[-1]  # Get class name
                
                # Import the module
                module = importlib.import_module(module_name)
                class_obj = getattr(module, class_obj_name)
                actual_classes[class_name] = class_obj
                    
            except (ImportError, AttributeError) as e:
                logger.warning(f"Could not import class {class_name} from {module_path}: {e}")
                continue
        
        # Compute hashes for the classes
        class_hashes = ClassIntegrityVerifier.get_local_class_hashes(actual_classes)
        
        # Add metadata
        response_data = {
            'class_hashes': class_hashes,
            'total_classes': len(class_hashes),
            'node_version': '1.0.0',
            'node_type': 'open_source_validator',
            'integrity_verification_supported': True,
            'timestamp': datetime.now(timezone.utc).isoformat()
        }
        
        logger.info(f"Served class hashes for {len(class_hashes)} classes")
        return jsonify(response_data), 200
        
    except Exception as e:
        logger.error(f"Error serving class hashes: {e}")
        return jsonify({"error": "Internal server error"}), 500


@node_api.route('/api/node/info', methods=['GET'])
def get_node_info():
    """
    Return essential node information for nexum validation.
    
    This endpoint provides core node identity and version information
    required for network compatibility verification.

    Returns:
        JSON: Node version, ID, type, and operational status
    """
    try:
        # Get node information
        node_info = {
            'node_id': _get_node_id(),
            'version': '1.0.0',
            'node_type': 'open_source_validator',
            'network': 'omne_mainnet',
            'capabilities_supported': True,
            'integrity_verification': True,
            'uptime_seconds': _get_uptime_seconds(),
            'local_ip': _get_local_ip(),
            'timestamp': datetime.now(timezone.utc).isoformat(),
            'status': 'active'
        }
        
        logger.debug(f"Served node info for node {node_info['node_id']}")
        return jsonify(node_info), 200
        
    except Exception as e:
        logger.error(f"Error serving node info: {e}")
        return jsonify({"error": "Internal server error"}), 500


@node_api.route('/api/node/capabilities', methods=['GET'])
def get_node_capabilities():
    """
    Return node operational capabilities for nexum validation.
    
    This endpoint provides information about what blockchain operations
    this node can perform, required for network participation approval.

    Returns:
        JSON: Boolean flags for supported capabilities
    """
    try:
        # Define capabilities for open source validator node
        capabilities = {
            'consensus': True,           # Can participate in consensus
            'validation': True,          # Can validate transactions and blocks
            'smart_contracts': True,     # Can execute smart contracts
            'staking': True,             # Can handle staking operations
            'block_production': False,   # Cannot produce new blocks (treasury only)
            'genesis_operations': False, # Cannot perform genesis operations
            'treasury_operations': False, # Cannot access treasury functions
            'mempool_management': True,   # Can manage transaction mempool
            'peer_discovery': True,       # Can discover and connect to peers
            'api_endpoints': True,        # Provides required API endpoints
            'integrity_verification': True, # Supports integrity verification
            'network_relay': True,        # Can relay network messages
            'fee_calculation': True,      # Can calculate transaction fees
            'account_management': True    # Can manage user accounts
        }
        
        # Add metadata
        response_data = {
            'capabilities': capabilities,
            'supported_count': sum(1 for v in capabilities.values() if v),
            'total_capabilities': len(capabilities),
            'node_version': '1.0.0',
            'timestamp': datetime.now(timezone.utc).isoformat()
        }
        
        logger.debug(f"Served capabilities: {sum(1 for v in capabilities.values() if v)}/{len(capabilities)} supported")
        return jsonify(response_data), 200
        
    except Exception as e:
        logger.error(f"Error serving capabilities: {e}")
        return jsonify({"error": "Internal server error"}), 500


def _get_node_id() -> str:
    """Generate a consistent node ID based on environment or hostname"""
    try:
        # Try to get from environment first
        node_id = os.getenv('NODE_ID')
        if node_id:
            return node_id
            
        # Fall back to hostname-based ID
        hostname = socket.gethostname()
        return f"open_node_{hostname}"
        
    except Exception:
        return "open_node_unknown"


def _get_local_ip() -> str:
    """Get the local IP address of this node"""
    try:
        # Connect to a remote address to determine local IP
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.connect(("8.8.8.8", 80))
            return s.getsockname()[0]
    except Exception:
        return "127.0.0.1"


def _get_uptime_seconds() -> int:
    """Get node uptime in seconds (simplified implementation)"""
    try:
        # This is a simplified implementation
        # In production, you'd track actual startup time
        return int(datetime.now().timestamp()) % 86400  # Mod 24 hours for demo
    except Exception:
        return 0
