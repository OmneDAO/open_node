#!/bin/bash

# Generate a unique node ID
NODE_ID=$(date +%s%N | sha256sum | base64 | head -c 8)
echo "Generated NODE_ID: ${NODE_ID}"

# Calculate the port number based on the current timestamp and a random component
BASE_PORT=3400
RANDOM_COMPONENT=$((RANDOM % 1000))
PORT_NUMBER=$((BASE_PORT + RANDOM_COMPONENT + 1))
echo "Calculated PORT_NUMBER: ${PORT_NUMBER}"

# Update docker-compose.yml
sed -i '' "s/container_name: node1.omne/container_name: node${PORT_NUMBER}.omne/g" docker-compose.yml
sed -i '' "s/3401:3400/${PORT_NUMBER}:3400/g" docker-compose.yml

# Update the Oracle class initialization in open_node.py
sed -i '' "s|current_node_url=\"http://current-node-url:3400\"|current_node_url=\"http://node${PORT_NUMBER}.omne:3400\"|g" app/open_node.py

# Update the Node class initialization in open_node.py
sed -i '' "s|self.current_node_url = \"http://current-node-url:3400\"|self.current_node_url = \"http://node${PORT_NUMBER}.omne:3400\"|g" app/open_node.py

# Ask the user for their steward address
read -p "Enter your steward address: " STEWARD_ADDRESS

# Update the steward address in the open_node.py
sed -i '' "s|self.node.steward = self.treasury.treasury_account|self.node.steward = \"${STEWARD_ADDRESS}\"|g" app/open_node.py

# Update the environment variable in docker-compose.yml
sed -i '' "s|# - STEWARD_ADDRESS=\${STEWARD_ADDRESS}|- STEWARD_ADDRESS=${STEWARD_ADDRESS}|g" docker-compose.yml

echo "Setup complete. You can now run 'docker-compose up -d' to start your node."
