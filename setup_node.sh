#!/bin/bash

# Prompt the user for their steward address
read -p "Enter the steward address for your node: " STEWARD_ADDRESS

if [ -z "$STEWARD_ADDRESS" ]; then
  echo "Steward address cannot be empty. Please run the script again and provide a valid address."
  exit 1
fi

# Generate a unique node ID
NODE_ID=$(date +%s%N | sha256sum | base64 | head -c 8)
echo "Generated NODE_ID: $NODE_ID"

# Calculate the port number
BASE_PORT=3400
PORT_NUMBER=$((BASE_PORT + RANDOM % 1000 + 1))
echo "Calculated PORT_NUMBER: $PORT_NUMBER"

# Update docker-compose.yml
sed -i "s/container_name: node_placeholder.omne/container_name: node${NODE_ID}.omne/g" docker-compose.yml
sed -i "s/3401:3400/${PORT_NUMBER}:3400/g" docker-compose.yml

# Update the Oracle class initialization in open_node.py
sed -i "s/current_node_url=\"http:\/\/current-node-url:3400\"/current_node_url=\"http:\/\/node${NODE_ID}.omne:3400\"/g" app/open_node.py

# Update the Node class initialization in open_node.py
sed -i "s/self.current_node_url = \"http:\/\/current-node-url:3400\"/self.current_node_url = \"http:\/\/node${NODE_ID}.omne:3400\"/g" app/open_node.py

# Update the steward address in open_node.py
sed -i "s/self.node.steward = self.treasury.treasury_account/self.node.steward = \"$STEWARD_ADDRESS\"/g" app/open_node.py

echo "Setup complete. You can now run 'docker-compose up -d' to start your node."
