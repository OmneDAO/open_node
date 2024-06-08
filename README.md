# OMNE Open Node Project

OMNE open source node

## Setup Instructions

### Prerequisites

- Docker
- Docker Compose
- Omne wallet address (use the https://phaylos.xyz mobile wallet to create a wallet address if you do not have one already)

- `sha256sum` command

### Installing `sha256sum` on macOS

**Windows**

To install `sha256sum` on Windows, you can use Git Bash or install the GNU Core Utilities for Windows:

1. Using Git Bash:

   - If you have Git for Windows installed, you can use the sha256sum command from Git Bash.

2. Using GNU Core Utilities:

   - Download the GNU Core Utilities from GnuWin32.
   - Install the package and add the installation path to your system's PATH environment variable.

**macOS**

If you're on macOS, you might need to install `coreutils` to get `sha256sum`:

```sh
brew install coreutils
```

After installation, you might need to add the coreutils binaries to your PATH:

```sh
echo 'export PATH="/usr/local/opt/coreutils/libexec/gnubin:$PATH"' >> ~/.zshrc
```
```sh
source ~/.zshrc
```
**Linux**

Most Linux distributions have `sha256sum` pre-installed. You can verify its installation by running:

```sh
sha256sum --version
```

### Getting Started

1. **Clone the repository**:
```sh
   git clone https://github.com/OmneDAO/open_node.git
```
```sh
   cd open_node
```

2. **Make the setup script executable**:
```sh
chmod +x setup_node.sh
```

3. **Set up the node**:
Run the setup script to configure your node:

```sh
./setup_node.sh
```

4. **Run Docker Compose**:
After the setup script completes, you can run the Docker Compose setup:

```sh
docker-compose up -d
```

***Development***

If you are a developer and want to work on the project without Docker, you can run the node locally. Follow the steps below to set up the development environment:

1. ***Create a virtual environment:***
```sh
python3 -m venv venv
source venv/bin/activate
```

2. ***Install dependencies:***
```sh
pip install -r requirements.txt
```

3. ***Run the node:***
```sh
python app/open_node.py
```

These steps allow you to develop and test the node without needing Docker. However, for deployment and production use, Docker Compose is required.


***Notes***

- The setup script automatically updates the node's configuration, including the container name and port number.


### Contributing

Contributions are welcome! Please open issues and pull requests as needed.


### License

This project is licensed under the MIT License. See the LICENSE file for more details.


### Explanation

1. **`setup_node.sh` script**: This script performs the necessary setup steps locally. It generates a unique node ID, calculates a port number, and updates the relevant configuration files.



2. **`entrypoint.sh` script**: This script is used in the Docker container to ensure all necessary steps are completed before running the node. It verifies class hashes to ensure the integrity of the codebase and initializes the node.

By running the `setup_node.sh` script, users will be able to configure and run their node without needing administrative rights on the repository.
