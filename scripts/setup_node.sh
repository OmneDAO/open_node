#!/bin/bash
# File: scripts/setup_node.sh
# Purpose: Configure the Omne node with a steward address, environment, and unique settings.

# Exit immediately if any command fails
set -e

# Function to display error messages and exit
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

# Validate the steward address format (for our blockchain it starts with "0z")
if [[ ! "$STEWARD_ADDRESS" =~ ^0z[0-9a-fA-F]{40}$ ]]; then
    error_exit "Invalid steward address format. It should start with '0z' followed by 40 hexadecimal characters."
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

# Set HOST_PORT equal to PORT_NUMBER for simplicity (adjust if needed)
HOST_PORT=${PORT_NUMBER}

# Export environment variables for this script
export NODE_ENV
export NETWORK_SUFFIX
export HOST_PORT
export NODE_ID  # Export NODE_ID

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

# Update the port mapping.
# The regex below matches lines with an optional leading quote around "3400:3400" and replaces them with our calculated HOST_PORT.
sed -i.bak -E "s/^([[:space:]]*-[[:space:]]*)\"?3400:3400\"?/\1\"${HOST_PORT}:3400\"/" "$DOCKER_COMPOSE_FILE" || true

# Update environment variables in docker-compose.yml using newline-escaped syntax
if grep -q 'STEWARD_ADDRESS=' "$DOCKER_COMPOSE_FILE"; then
    sed -i.bak "s|STEWARD_ADDRESS=.*|STEWARD_ADDRESS=${STEWARD_ADDRESS}|g" "$DOCKER_COMPOSE_FILE"
else
    sed -i.bak '/environment:/a\
    - STEWARD_ADDRESS='"${STEWARD_ADDRESS}" "$DOCKER_COMPOSE_FILE"
fi

if grep -q 'NODE_ENV=' "$DOCKER_COMPOSE_FILE"; then
    sed -i.bak "s|NODE_ENV=.*|NODE_ENV=${NODE_ENV}|g" "$DOCKER_COMPOSE_FILE"
else
    sed -i.bak '/environment:/a\
    - NODE_ENV='"${NODE_ENV}" "$DOCKER_COMPOSE_FILE"
fi

if grep -q 'NETWORK_SUFFIX=' "$DOCKER_COMPOSE_FILE"; then
    sed -i.bak "s|NETWORK_SUFFIX=.*|NETWORK_SUFFIX=${NETWORK_SUFFIX}|g" "$DOCKER_COMPOSE_FILE"
else
    sed -i.bak '/environment:/a\
    - NETWORK_SUFFIX='"${NETWORK_SUFFIX}" "$DOCKER_COMPOSE_FILE"
fi

if grep -q 'NODE_ID=' "$DOCKER_COMPOSE_FILE"; then
    sed -i.bak "s|NODE_ID=.*|NODE_ID=${NODE_ID}|g" "$DOCKER_COMPOSE_FILE"
else
    sed -i.bak '/environment:/a\
    - NODE_ID='"${NODE_ID}" "$DOCKER_COMPOSE_FILE"
fi

echo "Updated docker-compose.yml with NODE_ENV, NETWORK_SUFFIX, STEWARD_ADDRESS, PORT_NUMBER, and NODE_ID."

# Update the Oracle class initialization in app/main.py
MAIN_PY_FILE="app/main.py"

if [ ! -f "$MAIN_PY_FILE" ]; then
    echo "Warning: app/main.py not found. Skipping update of main.py."
else
    # Backup main.py
    cp "$MAIN_PY_FILE" "${MAIN_PY_FILE}.bak"

    # Update steward address
    sed -i.bak "s/self\.node\.steward = \".*\"/self.node.steward = \"${STEWARD_ADDRESS}\"/g" "$MAIN_PY_FILE" || true

    # Update node URL based on environment
    sed -i.bak "s|current_node_url = .*|current_node_url = \"http://${NODE_ID}.omne:${PORT_NUMBER}\"|g" "$MAIN_PY_FILE" || true

    echo "Updated app/main.py with steward address and node URL."
fi

echo "Setup complete. You can now run 'docker-compose up -d' to start your node."

read -p "Do you want to start the node now? (y/n): " START_NOW
if [[ "$START_NOW" == "y" || "$START_NOW" == "Y" ]]; then
    docker-compose up -d
    echo "Docker Compose is starting your node..."
fi
