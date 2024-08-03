#!/bin/bash

# Generate a unique node ID
NODE_ID=$(date +%s%N | sha256sum | base64 | head -c 8)
echo "Generated NODE_ID: ${NODE_ID}"

# Calculate the port number based on the current timestamp and a random component
BASE_PORT=3400
RANDOM_COMPONENT=$((RANDOM % 1000))
PORT_NUMBER=$((BASE_PORT + RANDOM_COMPONENT + 1))
echo "Calculated PORT_NUMBER: ${PORT_NUMBER}"

# Ask the user for their steward address
read -p "Enter your wallet address, which will be set as the steward address for this node: " STEWARD_ADDRESS

# Update docker-compose.yml
sed -i.bak "s/node[0-9]*\.omne/node${PORT_NUMBER}\.omne/g" docker-compose.yml
sed -i.bak "s/[0-9]*:3400/${PORT_NUMBER}:3400/g" docker-compose.yml

# Update the Oracle class initialization in open_node.py
if [ -f "app/open_node.py" ]; then
  sed -i.bak "s|current_node_url=\"http://current-node-url:3400\"|current_node_url=\"http://node${PORT_NUMBER}.omne:3400\"|g" app/open_node.py
  sed -i.bak "s|url=\"http://node.omne:3400\"|url=\"http://node${PORT_NUMBER}.omne:3400\"|g" app/open_node.py
  sed -i.bak "s|self.node.steward = self.treasury.treasury_account|self.node.steward = \"${STEWARD_ADDRESS}\"|g" app/open_node.py
else
  echo "Warning: app/open_node.py not found."
fi

# Update the environment variable in docker-compose.yml
if grep -q '# - STEWARD_ADDRESS=' docker-compose.yml; then
  sed -i.bak "s|# - STEWARD_ADDRESS=\${STEWARD_ADDRESS}|- STEWARD_ADDRESS=${STEWARD_ADDRESS}|g" docker-compose.yml
elif grep -q 'STEWARD_ADDRESS=' docker-compose.yml; then
  sed -i.bak "s|STEWARD_ADDRESS=.*|STEWARD_ADDRESS=${STEWARD_ADDRESS}|g" docker-compose.yml
else
  echo "Environment variable placeholder not found. Please check your docker-compose.yml file."
fi

echo "Setup complete. You can now run 'docker-compose up -d' to start your node."
