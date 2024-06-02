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
from open_node import Blockchain, Verifier, CUtils, DynamicFeeCalculator

try:
    if Blockchain.verify_class_hashes():
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

# Initialize the Blockchain instance
python3 - << EOF
from open_node import Blockchain, Node, Wallet, Transactions, Treasury, Verifier, Formulary

# Initialize the necessary objects
node = Node()
wallet = Wallet()
transactions = Transactions()
treasury = MDVLTreasury()
formulary = Formulary()
verifier = Verifier()

# Create the Blockchain instance
blockchain = Blockchain(node, wallet, transactions, treasury, formulary, verifier)

# Initialize the node
blockchain.initialize_node()
EOF

# Start the main application
exec "$@"
