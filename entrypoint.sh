#!/bin/bash

# Check if docker-compose.yml exists before running sed commands
if [ -f "/docker-compose.yml" ]; then
  # Generate a unique node ID
  NODE_ID=$(date +%s%N | sha256sum | base64 | head -c 8)
  echo "Generated NODE_ID: ${NODE_ID}"

  # Calculate the port number based on the current timestamp and a random component
  BASE_PORT=3400
  RANDOM_COMPONENT=$((RANDOM % 1000))
  PORT_NUMBER=$((BASE_PORT + RANDOM_COMPONENT + 1))
  echo "Calculated PORT_NUMBER: ${PORT_NUMBER}"

  # Update docker-compose.yml
  sed -i.bak "s|services:\s*node[0-9]*.omne|services:\n  node${PORT_NUMBER}.omne|g" /docker-compose.yml
  sed -i.bak "s/container_name: node[0-9]*.omne/container_name: node${PORT_NUMBER}.omne/g" /docker-compose.yml
  sed -i.bak "s/[0-9]*:3400/${PORT_NUMBER}:3400/g" /docker-compose.yml

  # Update the Oracle class initialization in open_node.py
  if [ -f "/app/open_node.py" ]; then
    sed -i.bak "s|current_node_url=\"http://current-node-url:3400\"|current_node_url=\"http://node${PORT_NUMBER}.omne:3400\"|g" /app/open_node.py
    sed -i.bak "s|url=\"http://node.omne:3400\"|url=\"http://node${PORT_NUMBER}.omne:3400\"|g" /app/open_node.py
    sed -i.bak "s|self.node.steward = self.treasury.treasury_account|self.node.steward = \"${STEWARD_ADDRESS}\"|g" /app/open_node.py
  else
    echo "Warning: /app/open_node.py not found."
  fi

  # Update the environment variable in docker-compose.yml
  if grep -q '# - STEWARD_ADDRESS=' /docker-compose.yml; then
    sed -i.bak "s|# - STEWARD_ADDRESS=\${STEWARD_ADDRESS}|- STEWARD_ADDRESS=${STEWARD_ADDRESS}|g" /docker-compose.yml
  elif grep -q 'STEWARD_ADDRESS=' /docker-compose.yml; then
    sed -i.bak "s|STEWARD_ADDRESS=.*|STEWARD_ADDRESS=${STEWARD_ADDRESS}|g" /docker-compose.yml
  else
    echo "Environment variable placeholder not found. Please check your docker-compose.yml file."
  fi
else
  echo "Warning: /docker-compose.yml not found."
fi

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
from open_node import Ledger, Verifier, OMC, pOMC, Wallet, Transactions, OMCTreasury, QuantumUtils, PermissionMngr, DynamicFeeCalculator

# Initialize the necessary objects
quantum_utils = QuantumUtils()
coin = OMC()
precious_coin = pOMC(coin)
permision_manager = PermissionMngr()
fee_calculator = DynamicFeeCalculator()
wallet = Wallet()
transactions = Transactions()
treasury = OMCTreasury()
verifier = Verifier()
ledger = Ledger(wallet, transactions, coin, verifier)

# Initialize the node
ledger.initialize_node()
EOF

# Register endpoints
python3 /app/register_endpoints.py

# Start the main application and ensure it keeps running
python3 /app/open_node.py

# Keep the container running
tail -f /dev/null
