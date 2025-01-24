# OMNE Open Source Node

OMNE Open Source Node allows individuals to run their own node within the Omne network. By operating a node, you contribute to the network's decentralization and security, and you stand a chance to be selected as a validator, earning potential rewards.

## Table of Contents

- [Prerequisites](#prerequisites)
- [Installation](#installation)
  - [1. Clone the Repository](#1-clone-the-repository)
  - [2. Make the Setup Script Executable](#2-make-the-setup-script-executable)
  - [3. Configure the Node](#3-configure-the-node)
  - [4. Launch the Node with Docker Compose](#4-launch-the-node-with-docker-compose)
- [Development](#development)
  - [Setting Up the Development Environment](#setting-up-the-development-environment)
- [Usage](#usage)
- [Configuration](#configuration)
- [Contributing](#contributing)
- [License](#license)

## Prerequisites

Before setting up your OMNE Open Source Node, ensure you have the following prerequisites:

1. **Omne Wallet Address**
   - Obtain an Omne wallet address. This will be used to set the steward of your node, which receives any potential validator rewards during consensus.
   - You can create a wallet address using the [Omne Wallet Interface](https://wallet.omne.io) once it's available, which utilizes the Omne SDK.

2. **Docker**
   - Install Docker on your system. Docker is essential for containerizing the node application.
   - [Download Docker](https://www.docker.com/get-started)

3. **Docker Compose**
   - Install Docker Compose to manage multi-container Docker applications.
   - [Install Docker Compose](https://docs.docker.com/compose/install/)

4. **`sha256sum` Command**
   - Ensure the `sha256sum` utility is available on your system for checksum operations.

   **macOS Users:**
   - Install `coreutils` using Homebrew:
     ```sh
     brew install coreutils
     ```
   - Add `coreutils` to your PATH:
     ```sh
     echo 'export PATH="/usr/local/opt/coreutils/libexec/gnubin:$PATH"' >> ~/.zshrc
     source ~/.zshrc
     ```

   **Windows Users:**
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
chmod +x setup_node.sh
```

### 3. Configure the Node

Run the setup script to configure your node. This script will:

- Generate a unique `NODE_ID`.
- Calculate a port number for the node.
- Update configuration files with your steward address and environment settings.

```sh
./setup_node.sh
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