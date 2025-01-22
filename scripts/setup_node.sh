#!/bin/bash

# File: scripts/setup_node.sh
# Purpose: Configure the Omne node with a steward address, environment, and unique settings.

# Exit immediately if a command exits with a non-zero status
set -e

# Function to display error messages
function error_exit {
    echo "[Error] $1" >&2
    exit 1
}

# Generate a unique NODE_ID using current timestamp and a random component
NODE_ID=$(date +%s%N | sha256sum | base64 | head -c 8)
echo "Generated NODE_ID: ${NODE_ID}"

# Calculate the port number based on the current timestamp and a random component
BASE_PORT=3400
RANDOM_COMPONENT=$((RANDOM % 1000))
PORT_NUMBER=$((BASE_PORT + RANDOM_COMPONENT + 1))
echo "Calculated PORT_NUMBER: ${PORT_NUMBER}"

# Prompt the user for their steward (wallet) address
read -p "Enter your wallet address, which will be set as the steward address for this node: " STEWARD_ADDRESS

# Validate the steward address format (basic validation, adjust as needed)
if [[ ! "$STEWARD_ADDRESS" =~ ^0x[0-9a-fA-F]{40}$ ]]; then
    error_exit "Invalid steward address format. It should start with '0x' followed by 40 hexadecimal characters."
fi

# Prompt the user to select the deployment environment
echo "Select the deployment environment:"
echo "1) Development"
echo "2) Staging"
echo "3) Production"
read -p "Enter the number corresponding to your choice: " ENV_CHOICE

case "$ENV_CHOICE" in
    1)
        NODE_ENV="development"
        NETWORK_SUFFIX="development"
        CXP_SUFFIX="eaies"
        ;;
    2)
        NODE_ENV="staging"
        NETWORK_SUFFIX="staging"
        CXP_SUFFIX="atio"
        ;;
    3)
        NODE_ENV="production"
        NETWORK_SUFFIX="production"
        CXP_SUFFIX="dicio"
        ;;
    *)
        error_exit "Invalid choice. Please run the script again and select a valid environment."
        ;;
esac

echo "Selected Environment: ${NODE_ENV}"

# Set HOST_PORT equal to PORT_NUMBER for simplicity; adjust if needed
HOST_PORT=${PORT_NUMBER}

# Export environment variables for use in this script
export NODE_ENV
export NETWORK_SUFFIX
export HOST_PORT

# Update docker-compose.yml with the new node name and port
DOCKER_COMPOSE_FILE="docker-compose.yml"

if [ ! -f "$DOCKER_COMPOSE_FILE" ]; then
    error_exit "docker-compose.yml not found in the current directory."
fi

# Backup the original docker-compose.yml
cp "$DOCKER_COMPOSE_FILE" "${DOCKER_COMPOSE_FILE}.bak"

# Update service name and network names based on the environment
sed -i.bak "s/node\.omne/node.omne/g" "$DOCKER_COMPOSE_FILE" || true
sed -i.bak "s/container_name: node\.omne/container_name: node.omne/g" "$DOCKER_COMPOSE_FILE" || true
sed -i.bak "s/[0-9]*:3400/${HOST_PORT}:3400/g" "$DOCKER_COMPOSE_FILE" || true

# Update the environment variables in docker-compose.yml
if grep -q 'STEWARD_ADDRESS=' "$DOCKER_COMPOSE_FILE"; then
    sed -i.bak "s|STEWARD_ADDRESS=.*|STEWARD_ADDRESS=${STEWARD_ADDRESS}|g" "$DOCKER_COMPOSE_FILE"
else
    # If STEWARD_ADDRESS is not present, add it under environment
    sed -i.bak "/environment:/a \ \ \ \ - STEWARD_ADDRESS=${STEWARD_ADDRESS}" "$DOCKER_COMPOSE_FILE"
fi

# Update NODE_ENV and NETWORK_SUFFIX in docker-compose.yml
if grep -q 'NODE_ENV=' "$DOCKER_COMPOSE_FILE"; then
    sed -i.bak "s|NODE_ENV=.*|NODE_ENV=${NODE_ENV}|g" "$DOCKER_COMPOSE_FILE"
else
    sed -i.bak "/environment:/a \ \ \ \ - NODE_ENV=${NODE_ENV}" "$DOCKER_COMPOSE_FILE"
fi

if grep -q 'NETWORK_SUFFIX=' "$DOCKER_COMPOSE_FILE"; then
    sed -i.bak "s|NETWORK_SUFFIX=.*|NETWORK_SUFFIX=${NETWORK_SUFFIX}|g" "$DOCKER_COMPOSE_FILE"
else
    sed -i.bak "/environment:/a \ \ \ \ - NETWORK_SUFFIX=${NETWORK_SUFFIX}" "$DOCKER_COMPOSE_FILE"
fi

echo "Updated docker-compose.yml with NODE_ENV, NETWORK_SUFFIX, STEWARD_ADDRESS, and PORT_NUMBER."

# Update the Oracle class initialization in app/main.py
MAIN_PY_FILE="app/main.py"

if [ ! -f "$MAIN_PY_FILE" ]; then
    echo "Warning: app/main.py not found. Skipping update of main.py."
else
    # Backup main.py
    cp "$MAIN_PY_FILE" "${MAIN_PY_FILE}.bak"

    # Update steward address
    # Assuming there's a line like: self.node.steward = "current_steward_address"
    sed -i.bak "s/self\.node\.steward = \".*\"/self.node.steward = \"${STEWARD_ADDRESS}\"/g" "$MAIN_PY_FILE" || true

    # Update node URL based on environment
    # Assuming there's a function or variable that sets the node URL
    # Modify accordingly based on your actual main.py structure

    # Example: Setting a variable `current_node_url`
    sed -i.bak "s|current_node_url = .*|current_node_url = \"http://node${PORT_NUMBER}.omne:3400\"|g" "$MAIN_PY_FILE" || true

    echo "Updated app/main.py with steward address and node URL."
fi

# Inform the user to proceed with Docker setup
echo "Setup complete. You can now run 'docker-compose up -d' to start your node."

# Optionally, offer to start Docker Compose automatically
read -p "Do you want to start the node now? (y/n): " START_NOW
if [[ "$START_NOW" == "y" || "$START_NOW" == "Y" ]]; then
    docker-compose up -d
    echo "Docker Compose is starting your node..."
fi
