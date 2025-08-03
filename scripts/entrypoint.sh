#!/bin/bash

# File: scripts/entrypoint.sh
# Purpose: Entrypoint script to initialize and start the Omne node after Docker container starts.

# Exit immediately if a command exits with a non-zero status
set -e

# Function to display error messages
function error_exit {
    echo "[Error] $1" >&2
    exit 1
}

echo "🚀 Starting Open Source Omne Validator Node..."

# Validate required environment variables
if [ -z "$STEWARD_ADDRESS" ]; then
    error_exit "STEWARD_ADDRESS environment variable is required but not set."
fi

if [ -z "$NODE_ID" ]; then
    error_exit "NODE_ID environment variable is required but not set."
fi

echo "📋 Node Configuration:"
echo "   • Steward Address: $STEWARD_ADDRESS"
echo "   • Node ID: $NODE_ID"
echo "   • Environment: ${NODE_ENV:-development}"
echo "   • Port: ${PORT_NUMBER:-3400}"

# Verify Python environment and imports
echo "🔍 Verifying Python environment..."
python3 -c "
import sys
import os
sys.path.insert(0, '/app')

try:
    from class_integrity_verifier import ClassIntegrityVerifier
    from ledger import Ledger
    from omc import OMC
    from mempool import Mempool
    from network_manager import NetworkManager
    from consensus_engine import ConsensusEngine
    from account_manager import AccountManager
    from smart_contracts import SmartContracts
    from crypto_utils import CryptoUtils
    from vrf_utils import VRFUtils
    from staked_omc import StakedOMC
    from staking import StakingMngr
    from config_manager import OpenNodeConfigManager
    print('✅ All required imports successful')
except ImportError as e:
    print(f'❌ Import error: {e}')
    sys.exit(1)
"

if [ $? -ne 0 ]; then
    error_exit "Python environment verification failed"
fi

echo "✅ Python environment verified"

# Perform class integrity verification before starting
echo "🔐 Starting class integrity verification..."

python3 - << EOF
import logging
import sys
import os

# Setup logging
logging.basicConfig(level=logging.INFO, format='[%(levelname)s] %(message)s')
logger = logging.getLogger()

# Add /app to PYTHONPATH
sys.path.insert(0, '/app')

try:
    from class_integrity_verifier import ClassIntegrityVerifier
    from ledger import Ledger
    from omc import OMC
    from mempool import Mempool
    from network_manager import NetworkManager
    from consensus_engine import ConsensusEngine
    from account_manager import AccountManager
    from smart_contracts import SmartContracts
    from crypto_utils import CryptoUtils
    from vrf_utils import VRFUtils
    from node import Node
    from verifier import Verifier

    # Set classes to verify for open source validator node
    classes_to_verify = {
        'Ledger': Ledger,
        'OMC': OMC,
        'Mempool': Mempool,
        'NetworkManager': NetworkManager,
        'ConsensusEngine': ConsensusEngine,
        'AccountManager': AccountManager,
        'SmartContracts': SmartContracts,
        'CryptoUtils': CryptoUtils,
        'VRFUtils': VRFUtils,
        'Node': Node,
        'Verifier': Verifier
    }
    
    ClassIntegrityVerifier.set_classes_to_verify(classes_to_verify)
    
    # Only verify if HASH_API_URL is available (for network joining)
    hash_api_url = os.getenv("HASH_API_URL")
    if hash_api_url:
        logger.info(f"🌐 Verifying against trusted source: {hash_api_url}")
        if ClassIntegrityVerifier.verify_class_integrity():
            logger.info("✅ Class integrity verification successful")
        else:
            logger.critical("❌ Class integrity verification failed")
            sys.exit(1)
    else:
        logger.info("⚠️  HASH_API_URL not set - skipping external verification")
        logger.info("✅ Class integrity check completed (local mode)")

except Exception as e:
    logger.critical(f"❌ Class integrity verification error: {e}")
    sys.exit(1)
EOF

if [ $? -ne 0 ]; then
    error_exit "Class integrity verification failed"
fi

echo "✅ Class integrity verification completed"

# Start the main Open Source Omne Node application
echo "🚀 Starting Open Source Omne Validator Node..."
cd /app

# Export all environment variables to ensure they're available
export STEWARD_ADDRESS
export NODE_ID
export NODE_ENV
export PORT_NUMBER
export NETWORK_SUFFIX
export HASH_API_URL

# Use the production-ready main.py which handles all initialization
python3 main.py

echo "✅ Open Source Omne Node started successfully"
