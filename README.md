# OMNE Open Source Node - Production Ready Validator Node

OMNE Open Source Node allows individuals to run their own production-grade validator node within the existing OMNE network. This node connects to the existing OMNE blockchain network and participates as a validator through a proper registration and verification process.

**Key Features:**
- ✅ **Joins existing networks** - Connects to established OMNE networks via bootstrap nodes
- ✅ **Validator registration** - Requests validator status through staking mechanism
- ✅ **Network verification** - Goes through proper verification process
- ✅ **Consensus participation** - Participates in block validation and consensus
- ❌ **Does NOT create genesis blocks** - This is a regular validator, not a network launcher
- ❌ **Does NOT launch new networks** - Joins existing networks only

## 🚀 Quick Start

**For immediate setup with minimal configuration:**

```bash
# 1. Clone the repository
git clone https://github.com/OmneDAO/open_node
cd open_node

# 2. Install dependencies
pip install -r requirements_open.txt

# 3. Configure environment (copy and edit the example)
cp .env.example .env
# Edit .env with your steward address and bootstrap nodes

# 4. Start the node
python app/main.py
```

The node will automatically:
1. Connect to the network via bootstrap nodes
2. Request validator status by staking OMC
3. Wait for network verification
4. Start participating in consensus as a validator

## 📖 Table of Contents

- [Prerequisites](#prerequisites)
- [Quick Installation](#quick-installation)
- [Production Deployment](#production-deployment)
- [Configuration](#configuration)
- [Monitoring & Health](#monitoring--health)
- [Development](#development)
- [Troubleshooting](#troubleshooting)
- [Contributing](#contributing)
- [License](#license)

## Prerequisites

Before setting up your OMNE Open Source Node, ensure you have the following prerequisites:

1. **Omne Wallet Address with Sufficient Balance**
   - Obtain an Omne wallet address with at least 1000 OMC tokens for staking
   - This will be used to set the steward of your node, which receives validator rewards
   - You can create a wallet address using the [Omne Wallet Interface](https://wallet.omne.io) once it's available

2. **Network Access to Bootstrap Nodes**
   - Ensure your server can connect to OMNE bootstrap nodes
   - Bootstrap nodes provide initial network discovery and connection
   - Default bootstrap nodes are configured for mainnet (update for testnet/custom networks)

3. **System Requirements**
   - **Python 3.8+** installed on your system
   - **Minimum 2 GB RAM** for validator operations
   - **Stable internet connection** with 99.9% uptime
   - **Open port 3400** (or configured port) for peer connections

4. **Optional: Docker Support**
   - Install Docker for containerized deployment
   - [Download Docker](https://www.docker.com/get-started)

## 🔗 Validator Registration Process

The open node follows this automatic process to become a validator:

### Step 1: Network Discovery
- Connects to bootstrap nodes specified in `OMNE_BOOTSTRAP_NODES`
- Discovers other peers in the network
- Announces itself to the network

### Step 2: Validator Registration
- Stakes the minimum required OMC (default: 1000 OMC)
- Submits validator registration request to the network
- Provides node information and cryptographic proofs

### Step 3: Network Verification
- Network validates the staking transaction
- Verifies node connectivity and software version
- Checks node compliance with network requirements
- Awaits consensus from existing validators

### Step 4: Active Participation
- Once verified, begins participating in consensus
- Validates transactions and blocks
- Earns rewards for honest validator behavior

### Verification Timeline
- **Immediate**: Network discovery and connection
- **1-2 minutes**: Staking transaction and registration
- **5-10 minutes**: Network verification process
- **Active**: Consensus participation begins

4. **Docker (Optional)**
   - Install Docker on your system for containerized deployment.
   - [Download Docker](https://www.docker.com/get-started)

5. **Docker Compose (Optional)**
   - Install Docker Compose to manage multi-container Docker applications.
   - [Install Docker Compose](https://docs.docker.com/compose/install/)

## 🔧 Quick Installation

### Method 1: Python Setup (Recommended)

```bash
# 1. Clone the repository
git clone <repository-url>
cd open_node

# 2. Create virtual environment (recommended)
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# 3. Install dependencies
pip install -r requirements_open.txt

# 4. Quick setup with your steward address
python setup.py --steward-address "your-omne-wallet-address"

# 5. Start the node
python app/main.py
```

### Method 2: Docker Setup

```bash
# 1. Clone the repository
git clone <repository-url>
cd open_node

# 2. Set your steward address in environment
echo "STEWARD_ADDRESS=your-omne-wallet-address" > app/.env

# 3. Build and run
docker-compose up --build
```

## 🏭 Production Deployment

This node is production-ready with enterprise-grade features:

### 🛡️ Security Features
- Advanced key management with rotation
- Security monitoring and threat detection
- Encrypted communications and data storage
- Comprehensive audit logging

### 📊 Monitoring & Observability
- Real-time performance metrics
- Health checks and system diagnostics
- Automated error handling and recovery
- Structured logging with multiple levels

### 🔧 Configuration Management
- Centralized configuration system
- Environment-based settings
- Runtime configuration validation
- Production readiness checks

### 🗃️ Storage Options
- Pluggable storage backend (memory, file, database)
- Data persistence and backup
- Transaction history management
- Configurable retention policies

For detailed production deployment instructions, see [docs/PRODUCTION_DEPLOYMENT.md](docs/PRODUCTION_DEPLOYMENT.md).

## ⚙️ Configuration

The node requires minimal configuration - mainly your steward address:

### Essential Configuration
```bash
# Set your steward address (required)
export STEWARD_ADDRESS="your-omne-wallet-address"

# Optional: Set custom port
export PORT=5000

# Optional: Set storage type
export STORAGE_TYPE="file"  # Options: memory, file, database
```

### Advanced Configuration
See [docs/OPERATIONAL_RUNBOOK.md](docs/OPERATIONAL_RUNBOOK.md) for comprehensive configuration options.

## 🔍 Monitoring & Health

### Health Endpoints
```bash
# Basic health check
curl http://localhost:5000/api/health

# Detailed system status
curl http://localhost:5000/api/health/detailed

# Performance metrics
curl http://localhost:5000/api/metrics

# Comprehensive status
curl http://localhost:5000/api/status
```

### Performance Monitoring
The node includes built-in performance monitoring:
- CPU and memory usage tracking
- Network performance metrics
- Blockchain synchronization status
- Transaction processing rates

## 🧪 Testing

Run the comprehensive test suite:

```bash
# Run all tests
python -m pytest tests/ -v

# Run specific test categories
python -m pytest tests/test_infrastructure.py -v

# Run with coverage
python -m pytest tests/ --cov=app --cov-report=html
```

## 🛠️ Development

### Setting Up the Development Environment

```bash
# 1. Clone and setup
git clone <repository-url>
cd open_node
python -m venv venv
source venv/bin/activate

# 2. Install development dependencies
pip install -r requirements_open.txt
pip install pytest pytest-cov mypy

# 3. Setup development environment
python setup.py --steward-address "test-address" --environment development --check-only

# 4. Run tests
python -m pytest tests/ -v
```

## 📚 Documentation

Comprehensive documentation is available:

- **[Operational Runbook](docs/OPERATIONAL_RUNBOOK.md)** - Day-to-day operations, monitoring, and maintenance
- **[Troubleshooting Guide](docs/TROUBLESHOOTING_GUIDE.md)** - Common issues and solutions
- **[Production Deployment](docs/PRODUCTION_DEPLOYMENT.md)** - Enterprise deployment guide

## 🆘 Troubleshooting

### Common Issues

**Node won't start:**
```bash
# Check configuration
python setup.py --steward-address "your-address" --check-only

# Validate environment
python app/main.py --validate-config
```

**Performance issues:**
```bash
# Check system metrics
curl http://localhost:5000/api/metrics

# View performance logs
tail -f logs/performance.log
```

For detailed troubleshooting, see [docs/TROUBLESHOOTING_GUIDE.md](docs/TROUBLESHOOTING_GUIDE.md).

## 📋 Requirements

**System Requirements:**
- Python 3.8+
- 2GB RAM minimum (4GB recommended)
- 10GB storage minimum (50GB recommended)
- Stable internet connection

**Dependencies:**
All dependencies are automatically installed via `requirements_open.txt`.

### 🐧 Linux/macOS Users:
   - Use Git Bash, which includes `sha256sum`, or install GNU Core Utilities for Windows:
     1. **Using Git Bash:**
        - [Download Git for Windows](https://gitforwindows.org/) and use the `sha256sum` command within Git Bash.
     2. **Using GNU Core Utilities:**
        - Download and install from [GnuWin32](http://gnuwin32.sourceforge.net/packages/coreutils.htm).
        - Add the installation directory to your system's PATH environment variable.

   **Linux Users:**
   - `sha256sum` is typically pre-installed. Verify by running:
     ```sh
     sha256sum --version
     ```

## Installation

Follow these steps to set up and run your OMNE Open Source Node.

### 1. Clone the Repository

Begin by cloning the OMNE Open Node repository to your local machine.

```sh
git clone https://github.com/OmneDAO/open_node.git
cd open_node
```

### 2. Make the Setup Script Executable

Ensure that the `setup_node.sh` script has the necessary execution permissions.

```sh
chmod +x scripts/setup_node.sh
```

### 3. Configure the Node

Run the setup script to configure your node. This script will:

- Generate a unique `NODE_ID`.
- Calculate a port number for the node.
- Update configuration files with your steward address and environment settings.

```sh
./scripts/setup_node.sh
```

**During the setup, you will be prompted to:**

1. **Enter Your Steward Wallet Address:**

- This address will receive any potential validator rewards

- Ensure your wallet address starts with `0z` followed by 40 hexadecimal characters (e.g., `0z1234567890abcdef1234567890abcdef12345678`).

2. **Select the Deployment Environment:**

- Choose from Development, Staging, or Production to set appropriate network configurations. (only `Development` is available at this time)

### 4. Launch the Node with Docker Compose

After successful configuration, start your node using Docker Compose.

```sh
docker-compose up -d
```

**This command will:**

- Build the Docker image for the OMNE node.

- Start the node container in detached mode.

- Set up necessary networking configurations based on your selected environment.

**To Check the Status of Your Node:**

```sh
docker-compose ps
```

**To View Logs:**

```sh
docker-compose logs -f
```

## Development

If you're interested in contributing to the OMNE Open Source Node or customizing it, follow the steps below to set up a development environment.

### Setting Up the Development Environment

1. Create a Virtual Environment:

```sh
python3 -m venv venv
source venv/bin/activate
```

2. Install Dependencies:

```sh
pip install -r requirements.txt
```

3. Run the Node Locally:

```sh
python main.py
```

**Note:** Running the node locally is useful for development and testing purposes. For production deployments, it's recommended to use Docker Compose as described in the Installation section.


## Usage

Once your node is up and running, it will:

- Participate in the Omne network consensus mechanism.

- Potentially be selected as a validator, earning rewards based on your node's performance and stake.

Accessing Node APIs:

Your node exposes various APIs for interaction. By default, the node runs on the port specified during setup (e.g., http://localhost:3400). Refer to the API Documentation for detailed endpoints and usage.

## Configuration

Configuration files and environment variables allow you to customize your node's behavior.

### `.env` File

The `.env` file located in the root directory contains essential environment variables:

- `STEWARD_ADDRESS:` Your Omne wallet address acting as the steward.

- `NODE_ID:` Unique identifier for your node, generated during setup.

- `PORT_NUMBER:` Port on which your node operates.

- `NODE_ENV:` Deployment environment (development, staging, production).

- `NETWORK_SUFFIX:` Network suffix based on the environment.

- `VALIDATOR_PRIVATE_KEY:` Private key for validator operations (auto-generated).

- `VALIDATOR_PUBLIC_KEY:` Public key derived from the private key.

- `VALIDATOR_VRF_PRIVATE_KEY:` Private key for VRF operations (auto-generated).
VALIDATOR_VRF_PUBLIC_KEY: Public key derived from the VRF private key.

**Note:** Sensitive information such as private keys should be securely managed and never exposed publicly.

## Updating Configuration

To manually update environment variables, edit the `.env` file:

```sh
nano .env
```

After making changes, restart your node to apply the new configurations:

```sh
docker-compose down
docker-compose up -d
```

## Contributing

Contributions are welcome! Whether you're fixing bugs, improving documentation, or adding new features, your efforts help make the OMNE network stronger.

### How to Contribute

1. **Fork the Repository:**

    Click the "Fork" button at the top-right corner of the repository page to create a personal copy.

2. **Clone Your Fork:**

```sh
git clone https://github.com/your-username/open_node.git
cd open_node
```

3. **Create a New Branch:**

```sh
git checkout -b feature/your-feature-name
```

4. **Make Your Changes:**

    Implement your feature or fix.

5. **Commit Your Changes:**

```sh
git commit -m "Add feature: your feature description"
```

6. **Push to Your Fork:**

```sh
git push origin feature/your-feature-name
```

7. **Open a Pull Request:**

    Navigate to the original repository and open a pull request from your fork.

## Code of Conduct

Please adhere to the [Code of Conduct](./Code_of_conduct.md) when contributing to this project.

## License

This project is licensed under the [MIT License](./LICENSE). See the [LICENSE](./LICENSE) file for details.

## Additional Information

- **Secure Handling of Secrets:** Ensure that your .env file and any other secret files are not exposed publicly or committed to version control systems.

- **Monitoring and Logs:** Regularly monitor your node's logs to ensure it operates correctly. Use tools like docker-compose logs -f for real-time log streaming.

- **Updates:** Keep your node software up-to-date by pulling the latest changes from the repository and rebuilding your Docker containers as needed.

For any issues or feature requests, please open an [issue](https://github.com/OmneDAO/open_node/issues) on the repository.

Happy validating!
