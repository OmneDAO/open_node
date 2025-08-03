# Open Source Omne Validator Node Scripts

This directory contains setup and management scripts for the Open Source Omne Validator Node.

## Scripts Overview

### 🚀 setup_node.sh
**Purpose**: Initial setup and configuration of your validator node

**Usage**:
```bash
./scripts/setup_node.sh
```

**What it does**:
- Generates a unique NODE_ID for your validator
- Assigns a random port to avoid conflicts
- Prompts for your steward (wallet) address
- Allows selection of network environment (development/staging/production)
- Updates docker-compose.yml with your configuration
- Creates a .env file with all settings
- Optionally starts the node immediately

**Requirements**:
- Valid OMNE wallet address (starting with "0z")
- Docker and Docker Compose installed

### 🔍 validate_setup.sh
**Purpose**: Validates that your node is properly configured

**Usage**:
```bash
./scripts/validate_setup.sh
```

**What it checks**:
- All required files are present
- Python syntax is valid
- Docker configuration is correct
- Environment variables are set
- Script permissions are correct

### 🏁 entrypoint.sh
**Purpose**: Docker container entrypoint that starts the validator node

**Usage**: Automatically called by Docker container

**What it does**:
- Validates environment variables
- Performs class integrity verification
- Starts the Open Source Omne Validator Node
- Connects to the specified network

## Setup Process

1. **Initial Setup**:
   ```bash
   # Clone the repository
   git clone <open_node_repository>
   cd open_node
   
   # Run the setup script
   ./scripts/setup_node.sh
   ```

2. **Validation** (optional):
   ```bash
   ./scripts/validate_setup.sh
   ```

3. **Start Node** (if not started during setup):
   ```bash
   docker-compose up -d
   ```

4. **Monitor Node**:
   ```bash
   # View logs
   docker-compose logs -f
   
   # Check health
   curl http://localhost:<YOUR_PORT>/api/health
   ```

## Configuration Files

### .env
Contains all environment variables for your node:
- `NODE_ID`: Unique identifier for your validator
- `STEWARD_ADDRESS`: Your wallet address (controls the validator)
- `NODE_ENV`: Network environment (development/staging/production)
- `PORT_NUMBER`: Port your node listens on
- `OMNE_BOOTSTRAP_NODES`: Network entry points
- `HASH_API_URL`: Class verification endpoint

### docker-compose.yml
Docker configuration updated with:
- Unique container name
- Port mapping
- Environment variables
- Network settings

## Network Environments

### Development
- **Purpose**: Local testing and development
- **Bootstrap**: `http://dev-bootstrap.omne.io:3400`
- **Verification**: `http://dev-trusted.omne.io/class-hashes.json`

### Staging
- **Purpose**: Pre-production testing
- **Bootstrap**: `http://staging-bootstrap.omne.io:3400`
- **Verification**: `http://staging-trusted.omne.io/class-hashes.json`

### Production
- **Purpose**: Live OMNE network
- **Bootstrap**: `http://bootstrap.omne.io:3400,http://bootstrap2.omne.io:3400`
- **Verification**: `https://trusted-source.omne.io/class-hashes.json`

## Validator Node Features

### 🔐 Security
- Class integrity verification via nexum relay
- Steward address validation
- Secure key generation and management

### 🌐 Network Participation
- Automatic network discovery and joining
- Validator registration system
- Consensus participation
- Block validation and creation

### 📊 Monitoring
- Health check endpoints
- Performance monitoring
- Real-time logging
- API endpoints for status

## Troubleshooting

### Common Issues

1. **Port conflicts**:
   ```bash
   # Change port in .env file and restart
   PORT_NUMBER=3401
   docker-compose down && docker-compose up -d
   ```

2. **Network connection issues**:
   ```bash
   # Check bootstrap nodes connectivity
   curl http://bootstrap.omne.io:3400/api/health
   ```

3. **Class verification failures**:
   ```bash
   # Check hash API availability
   curl https://trusted-source.omne.io/class-hashes.json
   ```

### Log Analysis
```bash
# View recent logs
docker-compose logs --tail=100

# Follow logs in real-time
docker-compose logs -f

# Filter for specific components
docker-compose logs | grep "NetworkManager\|ConsensusEngine\|Validator"
```

## Support

For support and documentation:
- Repository Issues: Create an issue in the repository
- Network Status: Check network status pages
- Community: Join the OMNE community channels

## License

This software is open source and distributed under the terms specified in the LICENSE file.
