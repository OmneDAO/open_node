#!/bin/bash
# File: scripts/setup_node.sh
# Purpose: Configure the Open Source Omne Validator Node with steward address, environment, and unique settings.

# Exit immediately if any command fails
set -e

# Function to display error messages and exit
function error_exit {
    echo "[Error] $1" >&2
    exit 1
}

echo "🌟 Open Source Omne Validator Node Setup"
echo "=========================================="

# Generate a unique NODE_ID using current timestamp and a random component
NODE_ID=$(date +%s%N | sha256sum | base64 | head -c 12)
echo "📋 Generated NODE_ID: ${NODE_ID}"

# Calculate the port number based on the current timestamp and a random component
BASE_PORT=3400
RANDOM_COMPONENT=$((RANDOM % 1000))
PORT_NUMBER=$((BASE_PORT + RANDOM_COMPONENT + 1))
echo "🌐 Calculated PORT_NUMBER: ${PORT_NUMBER}"

# Prompt the user for their steward (wallet) address
echo ""
echo "💼 Steward Address Configuration"
echo "Your steward address is your wallet address that will control this validator node."
read -p "Enter your wallet address (steward address): " STEWARD_ADDRESS

# Validate the steward address format (for OMNE blockchain it starts with "0z")
if [[ ! "$STEWARD_ADDRESS" =~ ^0z[0-9a-fA-F]{40}$ ]]; then
    error_exit "Invalid steward address format. It should start with '0z' followed by 40 hexadecimal characters."
fi

# Prompt the user to select the deployment environment
echo ""
echo "🌍 Environment Selection"
echo "1) Development  - Local testing network"
echo "2) Staging      - Pre-production testing"
echo "3) Production   - Live OMNE network"
read -p "Enter the number corresponding to your choice: " ENV_CHOICE

case "$ENV_CHOICE" in
    1)
        NODE_ENV="development"
        NETWORK_SUFFIX="development"
        BOOTSTRAP_NODES="http://dev-bootstrap.omne.io:3400"
        HASH_API_URL="http://dev-trusted.omne.io/class-hashes.json"
        ;;
    2)
        NODE_ENV="staging"
        NETWORK_SUFFIX="staging"
        BOOTSTRAP_NODES="http://staging-bootstrap.omne.io:3400"
        HASH_API_URL="http://staging-trusted.omne.io/class-hashes.json"
        ;;
    3)
        NODE_ENV="production"
        NETWORK_SUFFIX="production"
        BOOTSTRAP_NODES="http://bootstrap.omne.io:3400,http://bootstrap2.omne.io:3400"
        HASH_API_URL="https://trusted-source.omne.io/class-hashes.json"
        ;;
    *)
        error_exit "Invalid choice. Please run the script again and select a valid environment."
        ;;
esac

echo "✅ Selected Environment: ${NODE_ENV}"

# Set HOST_PORT equal to PORT_NUMBER for Docker port mapping
HOST_PORT=${PORT_NUMBER}

# Export environment variables for this script
export NODE_ENV
export NETWORK_SUFFIX
export HOST_PORT
export NODE_ID
export STEWARD_ADDRESS
export BOOTSTRAP_NODES
export HASH_API_URL

echo ""
echo "🔧 Updating Docker Configuration"

# Update docker-compose.yml with the new node configuration
DOCKER_COMPOSE_FILE="docker-compose.yml"

if [ ! -f "$DOCKER_COMPOSE_FILE" ]; then
    error_exit "docker-compose.yml not found in the current directory."
fi

# Backup the original docker-compose.yml
cp "$DOCKER_COMPOSE_FILE" "${DOCKER_COMPOSE_FILE}.backup.$(date +%s)"
echo "📁 Backed up original docker-compose.yml"

# Update container name to include NODE_ID for uniqueness
sed -i.bak "s/container_name: .*/container_name: omne-validator-${NODE_ID}/g" "$DOCKER_COMPOSE_FILE" || true

# Update the port mapping
sed -i.bak -E "s/^([[:space:]]*-[[:space:]]*)\"?[0-9]+:3400\"?/\1\"${HOST_PORT}:3400\"/" "$DOCKER_COMPOSE_FILE" || true

# Update or add environment variables
update_env_var() {
    local var_name=$1
    local var_value=$2
    
    if grep -q "${var_name}=" "$DOCKER_COMPOSE_FILE"; then
        sed -i.bak "s|${var_name}=.*|${var_name}=${var_value}|g" "$DOCKER_COMPOSE_FILE"
    else
        sed -i.bak "/environment:/a\\
      - ${var_name}=${var_value}" "$DOCKER_COMPOSE_FILE"
    fi
}

update_env_var "STEWARD_ADDRESS" "$STEWARD_ADDRESS"
update_env_var "NODE_ENV" "$NODE_ENV"
update_env_var "NODE_ID" "$NODE_ID"
update_env_var "PORT_NUMBER" "$PORT_NUMBER"
update_env_var "NETWORK_SUFFIX" "$NETWORK_SUFFIX"
update_env_var "OMNE_BOOTSTRAP_NODES" "$BOOTSTRAP_NODES"
update_env_var "HASH_API_URL" "$HASH_API_URL"

echo "✅ Updated docker-compose.yml with node configuration"

# Create or update .env file for easier management
ENV_FILE=".env"
cat > "$ENV_FILE" << EOF
# Open Source Omne Validator Node Configuration
# Generated on $(date)

NODE_ID=${NODE_ID}
STEWARD_ADDRESS=${STEWARD_ADDRESS}
NODE_ENV=${NODE_ENV}
PORT_NUMBER=${PORT_NUMBER}
HOST_PORT=${HOST_PORT}
NETWORK_SUFFIX=${NETWORK_SUFFIX}
OMNE_BOOTSTRAP_NODES=${BOOTSTRAP_NODES}
HASH_API_URL=${HASH_API_URL}

# Network configuration
NETWORK_HOST=0.0.0.0
NETWORK_PORT=3400

# Storage configuration
STORAGE_BACKEND=file
DATA_DIRECTORY=./data

# Consensus configuration
RANDAO_COMMIT_DURATION=30
RANDAO_REVEAL_DURATION=30
POEF_TASK_DIFFICULTY=4

# Fee configuration
BASE_FEE=0.000001
FEE_MULTIPLIER=1.5
EOF

echo "📄 Created .env file with node configuration"

echo ""
echo "📊 Configuration Summary"
echo "========================"
echo "Node ID: ${NODE_ID}"
echo "Steward Address: ${STEWARD_ADDRESS}"
echo "Environment: ${NODE_ENV}"
echo "Container Name: omne-validator-${NODE_ID}"
echo "Port Mapping: ${HOST_PORT}:3400"
echo "Bootstrap Nodes: ${BOOTSTRAP_NODES}"
echo "Hash Verification: ${HASH_API_URL}"

echo ""
echo "✅ Setup complete!"
echo ""
echo "🚀 Next Steps:"
echo "1. Review the generated .env file for any additional configuration"
echo "2. Run 'docker-compose up -d' to start your validator node"
echo "3. Monitor logs with 'docker-compose logs -f'"
echo "4. Check node status at http://localhost:${HOST_PORT}/api/health"

read -p "Do you want to start the validator node now? (y/n): " START_NOW
if [[ "$START_NOW" == "y" || "$START_NOW" == "Y" ]]; then
    echo ""
    echo "🚀 Starting Open Source Omne Validator Node..."
    docker-compose up -d
    
    echo ""
    echo "⏳ Waiting for node to initialize..."
    sleep 5
    
    echo ""
    echo "📊 Node Status:"
    if curl -s "http://localhost:${HOST_PORT}/api/health" > /dev/null 2>&1; then
        echo "✅ Node is responding to health checks"
        echo "🌐 Health endpoint: http://localhost:${HOST_PORT}/api/health"
        echo "📈 Monitor with: docker-compose logs -f"
    else
        echo "⚠️  Node is still starting up..."
        echo "📈 Check startup progress with: docker-compose logs -f"
    fi
else
    echo ""
    echo "💡 To start your node later, run: docker-compose up -d"
    echo "📈 To monitor logs: docker-compose logs -f"
fi

echo ""
echo "🎉 Open Source Omne Validator Node setup completed!"
echo "💼 Your node will join the ${NODE_ENV} network as a validator"
echo "🔒 Node secured with steward address: ${STEWARD_ADDRESS}"
