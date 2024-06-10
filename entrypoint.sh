#!/bin/bash

# Set the PYTHONPATH to ensure the script can find your modules
export PYTHONPATH="/app"
echo "PYTHONPATH is set to $PYTHONPATH"
echo "Current directory is $(pwd)"
ls -l /app

# Run the Python script to verify class hashes
python3 - << EOF
import logging
import sys
sys.path.insert(0, '/app')
from open_node import Ledger  # Adjust the import to match your actual module

try:
    if Ledger.verify_class_hashes():
        logging.info("Class verification successful. Proceeding with node initialization.")
    else:
        logging.error("Class verification failed. Exiting.")
        sys.exit(1)
except ValueError as e:
    logging.error(f'Class verification failed: {e}')
    sys.exit(1)
EOF

# Check if the Python script exited with an error
if [ $? -ne 0 ]; then
  echo "Class verification failed. Exiting."
  exit 1
fi

# Initialize the necessary objects for the ledger and consensus
python3 - << EOF
import logging
from open_node import Ledger, SWRVS, Verifier, Oracle, OMC, Node, Wallet, Transactions, Treasury

# Initialize the necessary objects
oracle = Oracle(api_key="your_api_key")
coin = OMC(oracle)
node = Node(current_node_url="http://current-node-url:3400", address="your_address", stake_weight=100)
wallet = Wallet()
transactions = Transactions()
treasury = Treasury()
verifier = Verifier()
ledger = Ledger(node, wallet, transactions, coin, verifier)
swrvs = SWRVS(node, verifier)

# Initialize the node
ledger.initialize_node()
EOF

# Start the main application
exec "$@"
