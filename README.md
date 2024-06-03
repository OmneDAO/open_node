# OMNE Open Node Project
OMNE open source node

## Setup Instructions

### Prerequisites

- Docker
- Docker Compose

### Getting Started

1. **Clone the repository**:
```sh
   git clone https://github.com/yourusername/omne-open-node.git
   cd omne-open-node
```

2. ### Setup Environment Variables

Before running the project, ensure you have set the following environment variables:

```sh
export STEWARD_ADDRESS=<your_omne_address>
```

3. ### Trigger the GitHub Actions workflow to configure your node

After cloning the repository, you need to trigger the GitHub Actions workflow to set up your node's configuration. You can do this manually via the GitHub API or GitHub CLI.

***Using GitHub CLI***
```sh
gh workflow run open-node-iterator.yml --repo yourusername/omne-open-node --ref main --field event_type=setup-node
```
***Using cURL***
```sh
curl -X POST -H "Accept: application/vnd.github.v3+json" \
-H "Authorization: token YOUR_GITHUB_TOKEN" \
https://api.github.com/repos/yourusername/omne-open-node/dispatches \
-d '{"event_type":"setup-node"}'
```

4. ### Run Docker Compose

After the GitHub Actions workflow completes, you can run the Docker Compose setup:

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

- The GitHub Actions workflow automatically updates the node's configuration, including the container name and port number.


### Contributing

Contributions are welcome! Please open issues and pull requests as needed.


### License

This project is licensed under the MIT License. See the LICENSE file for more details.


### Explanation

1. **GitHub Actions Workflow**: The workflow only triggers on `repository_dispatch` with the event type `setup-node`.

2. **README.md**: Updated to include instructions for triggering the GitHub Actions workflow manually after cloning the repository using either GitHub CLI or cURL.

This ensures that the workflow only runs when explicitly triggered by the user, avoiding unnecessary runs on every push.