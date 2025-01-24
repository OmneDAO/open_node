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

echo "Starting class integrity verification..."

python3 - << EOF
import logging
import sys
import os
from decimal import Decimal

# Setup logging
logging.basicConfig(level=logging.INFO)

# Add /app to PYTHONPATH if not already present
sys.path.insert(0, '/app')

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

# Initialize necessary classes to verify
ClassIntegrityVerifier.set_classes_to_verify({
    'Ledger': Ledger,
    'OMC': OMC,
    'Mempool': Mempool,
    'NetworkManager': NetworkManager,
    'ConsensusEngine': ConsensusEngine,
    'AccountManager': AccountManager,
    'SmartContracts': SmartContracts,
    'CryptoUtils': CryptoUtils,
    'VRFUtils': VRFUtils
})

# Perform verification
if ClassIntegrityVerifier.verify_class_integrity():
    logging.info("Class integrity verification successful. Proceeding with node initialization.")
else:
    logging.critical("Class integrity verification failed. Exiting.")
    sys.exit(1)
EOF

# Check if the previous Python script exited successfully
if [ $? -ne 0 ]; then
    echo "Class integrity verification failed. Shutting down the node."
    exit 1
fi

echo "Class integrity verification passed."

echo "Initializing node components..."

python3 - << EOF
import logging
import sys
import os
from decimal import Decimal

# Setup logging
logging.basicConfig(level=logging.INFO)

from ledger import Ledger
from mempool import Mempool
from network_manager import NetworkManager
from consensus_engine import ConsensusEngine
from account_manager import AccountManager
from omc import OMC
from smart_contracts import SmartContracts
from crypto_utils import CryptoUtils
from vrf_utils import VRFUtils
from dynamic_fee_calculator import DynamicFeeCalculator

# Initialize CryptoUtils
crypto_utils = CryptoUtils()

# Initialize AccountManager
account_manager = AccountManager()

# Initialize DynamicFeeCalculator
fee_calculator = DynamicFeeCalculator(
    base_fee=Decimal('0.1'),
    fee_multiplier=Decimal('0.05'),
    size_multiplier=Decimal('0.001'),
    type_fee_adjustments={
        'deploy_contract': Decimal('1.0'),
        'execute_contract': Decimal('0.5'),
        'standard_transfer': Decimal('0.0')
    },
    moving_average_window=100,
    max_fee=Decimal('10'),
    min_fee=Decimal('0.01')
)

# Initialize OMC
treasury_address = os.getenv("STEWARD_ADDRESS")
if not treasury_address:
    logging.error("STEWARD_ADDRESS environment variable not set.")
    sys.exit(1)
coin = OMC(treasury_address=treasury_address)

# Initialize StakedOMC
staked_omc = StakedOMC()

# Initialize StakingMngr
staking_manager = StakingMngr(
    coin=coin, 
    account_manager=account_manager, 
    staked_omc=staked_omc
)

# Set StakingMngr in OMC
coin.set_staking_manager(staking_manager)

# Initialize ConsensusEngine
consensus_engine = ConsensusEngine(
    account_manager=account_manager,
    slash_penalty=Decimal("0.1"),
    random_source="PRNG"  # Or "VRF" if using VRF
)

# Initialize Mempool
mempool = Mempool(
    crypto_utils=crypto_utils,
    fee_calculator=fee_calculator,
    max_mempool_size=10000,
    ledger=ledger,
    omc=coin,
    account_manager=account_manager,
    vrf_utils=vrf_utils,
    blockchain=ledger.blockchain,  # Assuming ledger has a blockchain attribute
    staking_manager=staking_manager,  # Pass the staking_manager instance
)

# Initialize Ledger
ledger = Ledger(
    consensus_engine=consensus_engine,
    account_manager=account_manager,
    omc=coin,
    mempool=mempool
)

# Initialize NetworkManager
port_number = int(os.getenv("PORT_NUMBER", "3400"))
network_manager = NetworkManager(
    ledger=ledger,
    mempool=mempool,
    class_integrity_verifier=ClassIntegrityVerifier(),
    fee_calculator=fee_calculator,
    port=port_number,
    omc=coin
)

# Initialize SmartContracts
smart_contracts = SmartContracts(
    ledger=ledger,
    crypto_utils=crypto_utils,
    transaction_service=mempool
)

# Start NetworkManager server in a separate thread or process
import threading

def start_network():
    network_manager.start_server()

network_thread = threading.Thread(target=start_network)
network_thread.start()

# Initialize and run Ledger
ledger.initialize_node()
EOF

echo "Node components initialized successfully."

# Register API endpoints (assuming register_endpoints.py exists and handles it)
if [ -f "/app/register_endpoints.py" ]; then
    echo "Registering API endpoints..."
    python3 /app/register_endpoints.py
    echo "API endpoints registered."
else
    echo "Warning: /app/register_endpoints.py not found. Skipping API registration."
fi

# Start the main application
echo "Starting the Omne node..."
python3 /app/main.py &

# Start the Nginx update script in the background
echo "Starting Nginx update script..."
python3 /scripts/update_nginx.py &

# Wait indefinitely to keep the container running
wait
