# network_manager.py

from flask import Flask, jsonify, request, Blueprint
from flask_cors import CORS, cross_origin
from datetime import datetime, timezone, date
from ledger import Ledger
from mempool import Mempool
from class_integrity_verifier import ClassIntegrityVerifier
from dynamic_fee_calculator import DynamicFeeCalculator
from omc import OMC, TransferRequest, DoubleSpendingError
from account_manager import AccountManager
from staking import StakingMngr
from staked_omc import StakedOMC
from permissions import PermissionManager
from consensus_engine import ConsensusEngine
from crypto_utils import DecimalEncoder, CryptoUtils
from smart_contracts import SmartContracts
from verifier import Verifier
from vrf_utils import VRFUtils
from validator_api import validator_api, initialize_validator_api
from verification.transaction_verifier import TransactionVerifier
from pymongo import MongoClient
from pymongo.server_api import ServerApi
import logging
import os
import sys
import hashlib
from block import Block
import threading
import time
from functools import wraps
import requests
from decimal import Decimal, InvalidOperation
from typing import List, Dict, Optional, Tuple
import socket
import json

logger = logging.getLogger('NetworkManager')

# ----------------------------------------------------------------
#  Flask App and Logging Configuration
# ----------------------------------------------------------------

app = Flask(__name__)
CORS(app)

def setup_logging():
    logging.basicConfig(
        level=logging.INFO,
        format='[%(asctime)s] [%(levelname)s] [%(name)s] %(message)s',
        handlers=[
            logging.StreamHandler()
        ]
    )

setup_logging()

# ----------------------------------------------------------------
#  NetworkManager Class Definition
# ----------------------------------------------------------------

class NetworkManager:
    """
    Manages peer discovery, incoming/outgoing HTTP requests,
    and block/transaction broadcasting. Integrates with:
      - Ledger        (for adding blocks)
      - Mempool       (for receiving new transactions)
      - ConsensusEngine (for coordination)
      - OMC           (for staking and rewards)
    """

    def __init__(self, 
                 ledger: Ledger, 
                 mempool: Mempool, 
                 class_integrity_verifier: ClassIntegrityVerifier = None,
                 fee_calculator: DynamicFeeCalculator = None,
                 port: int = 3400,
                 omc: Optional[OMC] = None,
                 account_manager: Optional[AccountManager] = None,
                 staking_manager: Optional[StakingMngr] = None,
                 verifier: Optional[Verifier] = None):
        """
        :param ledger: A reference to the Ledger instance
        :param mempool: Reference to the Mempool instance
        :param class_integrity_verifier: Reference to ClassIntegrityVerifier for integrity checks
        :param fee_calculator: Reference to DynamicFeeCalculator for fee calculations
        :param port: The port on which this node listens for incoming requests
        :param omc: Reference to the OMC instance for staking and reward management
        :param account_manager: Reference to the AccountManager instance
        :param staking_manager: Reference to the StakingMngr instance
        :param verifier: Reference to the Verifier instance
        """
        self.ledger = ledger
        app.config["LEDGER"] = ledger
        self.mempool = mempool
        self.class_integrity_verifier = class_integrity_verifier
        self.fee_calculator = fee_calculator
        self.omc = omc
        self.account_manager = account_manager
        self.staking_manager = staking_manager
        self.verifier = verifier
        
        # Fix the ledger's OMC reference if it's None but we have an OMC instance
        logging.info(f"NetworkManager OMC debugging: ledger.omc={self.ledger.omc}, self.omc={self.omc}")
        if self.ledger.omc is None and self.omc is not None:
            self.ledger.omc = self.omc
            logging.info("Fixed ledger.omc reference using NetworkManager's OMC instance")
        else:
            logging.info("No OMC reference fix needed")

        self.port = port
        self.peers = set()  # Track known peer URLs
        self.lock = threading.Lock()

        # Consensus-related attributes
        self.consensus_engine: Optional[ConsensusEngine] = None

        # Initialize Flask Blueprints
        self._initialize_blueprints()

        # Start background threads for peer discovery and health checks
        self.discovery_thread = threading.Thread(target=self._peer_discovery_routine, daemon=True)
        self.discovery_thread.start()

        self.health_check_thread = threading.Thread(target=self._peer_health_check_routine, daemon=True)
        self.health_check_thread.start()

        logger.info(f"NetworkManager initialized on port {self.port}.")

    def set_consensus_engine(self, consensus_engine: ConsensusEngine):
        """
        Sets the reference to the ConsensusEngine.
        """
        self.consensus_engine = consensus_engine
        logger.info("ConsensusEngine reference set in NetworkManager.")

    # ----------------------------------------------------------------
    #  PEER DISCOVERY METHODS
    # ----------------------------------------------------------------

    def get_local_ip(self) -> str:
        """
        Returns the local machine's IP address.
        """
        try:
            # Connect to an external host to force selection of an interface.
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            ip = s.getsockname()[0]
            s.close()
            return ip
        except Exception as e:
            logging.error(f"Error obtaining local IP: {e}")
            return "127.0.0.1"

    def discover_services(self, prefix: str = "omne", max_range: int = 10) -> List[str]:
        """
        Discovers Omne node services within the Docker network based on a naming convention.
        Returns a list of discovered service names.
        """
        discovered_services = []
        local_ip = self.get_local_ip()

        for i in range(1, max_range + 1):
            service_name = f"{prefix}{i}"
            try:
                service_ip = socket.gethostbyname(service_name)
                # Only add services whose IP is different from our local IP.
                if service_ip != local_ip:
                    discovered_services.append(service_name)
                    logging.debug(f"Discovered service: {service_name} at {service_ip}")
                else:
                    logging.debug(f"Skipping self service: {service_name} with IP {service_ip}")
            except socket.gaierror:
                logging.debug(f"Service {service_name} not found.")
                continue

        if not discovered_services:
            logging.warning("No external services were discovered during this discovery cycle.")
        else:
            logging.info(f"Discovered services: {discovered_services}")
        return discovered_services

    def ping_services(self, services: List[str], endpoint: str = "api/peer/peers") -> None:
        """
        Pings discovered services to verify their availability and retrieve their node information.
        """
        local_ip = self.get_local_ip()
        for service in services:
            try:
                service_ip = socket.gethostbyname(service)
            except socket.gaierror:
                logging.debug(f"Cannot resolve IP for service {service}. Skipping.")
                continue

            # Skip if the discovered IP is the same as local IP
            if service_ip == local_ip:
                logging.debug(f"Skipping ping for local service {service} at {service_ip}")
                continue

            service_base_url = f"http://{service}:{self.port}"
            service_url = f"{service_base_url}/{endpoint}"
            logging.debug(f"Attempting to ping {service_url}")
            try:
                response = requests.get(service_url, timeout=5)
                if response.status_code == 200:
                    logging.debug(f"Successfully pinged {service_url}")
                    received_peers = response.json().get('peers', [])
                    for received_peer in received_peers:
                        node_address = received_peer.get('address')
                        if node_address and node_address not in [peer['address'] for peer in self.verifier.nodes]:
                            self.verifier.nodes.append(received_peer)
                            logging.debug(f"Added new node: {node_address}")
                else:
                    logging.debug(f"Failed to ping {service_url}, status code: {response.status_code}")
            except requests.exceptions.RequestException as e:
                logging.warning(f"Error pinging {service_url}: {e}")

    def _peer_discovery_routine(self, interval_seconds: int = 60, prefix: str = "omne", max_range: int = 10):
        """
        Periodically attempts to discover new peers.

        :param interval_seconds: Time interval between discovery attempts
        :param prefix: The prefix used for naming services
        :param max_range: The maximum number of services to attempt discovery for
        """
        while True:
            logging.info("Starting peer discovery cycle...")
            discovered_services = self.discover_services(prefix=prefix, max_range=max_range)
            self.ping_services(discovered_services)
            logging.info("Peer discovery cycle complete.")
            time.sleep(interval_seconds)

    # ----------------------------------------------------------------
    #  PEER HEALTH CHECK METHODS
    # ----------------------------------------------------------------

    def _peer_health_check_routine(self, interval_seconds: int = 300):
        """
        Periodically checks the health of known peers and removes unresponsive ones.

        :param interval_seconds: Time interval between health checks
        """
        while True:
            logging.info("Starting peer health check cycle...")
            time.sleep(interval_seconds)
            with self.lock:
                peers_to_remove = []
                for peer in self.peers:
                    try:
                        response = requests.get(f"{peer}/api/health", timeout=5)
                        if response.status_code != 200:
                            logging.warning(f"Peer {peer} failed health check with status {response.status_code}.")
                            peers_to_remove.append(peer)
                    except requests.exceptions.RequestException as e:
                        logging.error(f"Peer {peer} failed health check: {e}")
                        peers_to_remove.append(peer)

                for peer in peers_to_remove:
                    self.peers.discard(peer)
                    logging.info(f"Removed unresponsive peer: {peer}")
            logging.info("Peer health check cycle complete.")

    # ----------------------------------------------------------------
    #  PEER ADDITION AND VERIFICATION
    # ----------------------------------------------------------------

    def add_peer(self, peer_url: str):
        """
        Adds a peer to the local set after verifying with the gateway.

        :param peer_url: The URL of the peer to add
        """
        if self.verify_peer_with_gateway(peer_url):
            with self.lock:
                if peer_url not in self.peers and peer_url != self.get_own_url():
                    self.peers.add(peer_url)
                    logging.info(f"Peer added: {peer_url}")

            # Broadcast the new peer to existing peers
            self.broadcast_peer(peer_url)
        else:
            logging.warning(f"Peer {peer_url} failed gateway verification and was not added.")

    def verify_peer_with_gateway(self, peer_url: str) -> bool:
        """
        Verifies the peer's validity and security through the gateway.

        :param peer_url: The URL of the peer to verify
        :return: True if verification succeeds, False otherwise
        """
        gateway_verification_url = os.getenv("GATEWAY_VERIFICATION_URL", "http://gateway.omne:4000/api/verify_peer")
        payload = {"peer_url": peer_url}
        try:
            response = requests.post(gateway_verification_url, json=payload, timeout=5)
            if response.status_code == 200:
                verification_result = response.json().get('verified', False)
                if verification_result:
                    logger.info(f"Peer {peer_url} verified successfully by gateway.")
                    return True
                else:
                    logger.warning(f"Peer {peer_url} failed verification by gateway.")
                    return False
            else:
                logger.error(f"Gateway verification failed for {peer_url} with status code: {response.status_code}")
                return False
        except requests.exceptions.RequestException as e:
            logger.error(f"Error verifying peer {peer_url} with gateway: {e}")
            return False

    # ----------------------------------------------------------------
    #  BROADCASTING METHODS
    # ----------------------------------------------------------------

    def broadcast_block(self, block: dict, exclude_peer_url: Optional[str] = None):
        """
        Broadcasts a newly mined block to all known peers.
        Each peer will call the 'receive_block' endpoint to decide acceptance.

        :param block: The block data to broadcast
        :param exclude_peer_url: The peer URL to exclude from broadcasting (e.g., sender)
        """
        with self.lock:
            current_peers = list(self.peers)

        headers = {
            'X-Peer-URL': self.get_own_url()
        }

        for peer in current_peers:
            if exclude_peer_url and peer == exclude_peer_url:
                continue
            url = f"{peer}/api/block/receive_block"
            try:
                response = requests.post(url, json=block, headers=headers, timeout=5)
                logger.debug(f"Broadcasted block to {url}, response={response.status_code}")
            except requests.exceptions.RequestException as e:
                logger.error(f"Failed to broadcast block to {url}: {e}")

    def broadcast_transaction(self, transaction: dict, exclude_peer_url: Optional[str] = None):
        """
        Broadcasts a new transaction to all known peers so they can include it in their mempool.

        :param transaction: The transaction data to broadcast
        :param exclude_peer_url: The peer URL to exclude from broadcasting (e.g., sender)
        """
        with self.lock:
            current_peers = list(self.peers)

        headers = {
            'X-Peer-URL': self.get_own_url()
        }

        for peer in current_peers:
            if exclude_peer_url and peer == exclude_peer_url:
                continue
            url = f"{peer}/api/transaction/receive_transaction"
            try:
                response = requests.post(url, json=transaction, headers=headers, timeout=5)
                logger.debug(f"Broadcasted transaction to {url}, response={response.status_code}")
            except requests.exceptions.RequestException as e:
                logger.error(f"Failed to broadcast transaction to {url}: {e}")

    def broadcast_peer(self, peer_url: str):
        """
        Informs all known peers of a new peer. Peers can then connect to it.

        :param peer_url: The URL of the new peer to broadcast
        """
        with self.lock:
            current_peers = list(self.peers)

        data = {"peer_url": peer_url}
        headers = {
            'X-Peer-URL': self.get_own_url()
        }

        for peer in current_peers:
            if peer == peer_url:
                continue  # Avoid broadcasting to the new peer itself
            url = f"{peer}/api/peer/add_peer"
            try:
                response = requests.post(url, json=data, headers=headers, timeout=5)
                logger.debug(f"Broadcasted new peer to {url}, response={response.status_code}")
            except requests.exceptions.RequestException as e:
                logger.error(f"Failed to broadcast peer to {url}: {e}")

    def broadcast_vrf_output(self, validator_id: str, proof: bytes):
        """
        Broadcasts the VRF output to all known peers.

        :param validator_id: The identifier of the validator.
        :param proof: The VRF proof bytes.
        """
        payload = {
            "validator_id": validator_id,
            "vrf_output": proof.hex()  # Convert bytes to hex string for transmission
        }
        headers = {"Content-Type": "application/json"}

        with self.lock:
            current_peers = list(self.peers)

        for peer in current_peers:
            url = f"{peer}/api/consensus/submit_vrf"
            try:
                response = requests.post(url, json=payload, headers=headers, timeout=5)
                response.raise_for_status()
                logger.info(f"Successfully broadcasted VRF output to peer: {peer}")
            except requests.exceptions.RequestException as e:
                logger.error(f"Failed to broadcast VRF output to peer {peer}: {e}")
                
    def broadcast_vrf_output(self, validator_id: str, proof: bytes):
        """
        Broadcasts the VRF output to all known peers.

        :param validator_id: The identifier of the validator.
        :param proof: The VRF proof bytes.
        """
        payload = {
            "validator_id": validator_id,
            "vrf_output": proof.hex()  # Convert bytes to hex string for transmission
        }
        headers = {"Content-Type": "application/json"}

        with self.lock:
            current_peers = list(self.peers)

        for peer in current_peers:
            url = f"{peer}/api/consensus/submit_vrf"
            try:
                response = requests.post(url, json=payload, headers=headers, timeout=5)
                response.raise_for_status()
                logger.info(f"Successfully broadcasted VRF output to peer: {peer}")
            except requests.exceptions.RequestException as e:
                logger.error(f"Failed to broadcast VRF output to peer {peer}: {e}")
                
    def broadcast_new_account(
        self,
        sender: str, 
        balance: str,
        exclude_peer_url: Optional[str],
        fee: str, 
        public_key: str,
        nonce: str, 
        signature: str,
        timestamp: str,
        tx_hash: str,
        type: str,
        data: dict
    ) -> Optional[str]:
        """
        Creates and broadcasts a new account creation transaction.
        The transaction is added to the local mempool for inclusion on the blockchain,
        and then propagated to all known peers.
        Returns the local mempool hash if added successfully, otherwise None.
        """
        if data is None:
            data = {}

        transaction = {
            'sender': sender,
            'balance': balance,
            'fee': fee if fee else "0",
            'nonce': nonce if nonce else "0",
            'public_key': public_key,
            'timestamp': timestamp,
            'type': type,
            'data': data,
            'signature': signature,
            'hash': tx_hash  # user-provided, but not used for verification
        }

        success, local_hash = self.mempool.add_transaction(transaction)
        if success:
            logging.info(f"Account creation transaction for {sender} added to mempool. local_hash={local_hash}")
        else:
            logging.warning(f"Failed to add account creation transaction for {sender} to mempool.")
            return None

        # Prepare propagation payload
        propagation_payload = transaction

        with self.lock:
            current_peers = list(self.peers)

        for peer in current_peers:
            if exclude_peer_url and peer == exclude_peer_url:
                continue
            url = f"{peer}/api/propagate_account"
            try:
                response = requests.post(url, json=propagation_payload, timeout=5)
                if response.status_code in [200, 201]:
                    logger.info(f"Successfully propagated account to {peer}.")
                else:
                    logger.warning(f"Failed to propagate account to {peer}. Status Code: {response.status_code}")
            except requests.exceptions.RequestException as e:
                logger.error(f"Error propagating account to {peer}: {e}")

        return local_hash
                
    # ----------------------------------------------------------------
    #  CHAIN SYNC METHODS
    # ----------------------------------------------------------------

    def request_chain_sync(self, peer_url: str):
        """
        Requests a full chain from a peer and adopts it if it's longer and valid.
        
        This function makes a GET request to the peer's /api/block/full_chain endpoint.
        It then reserializes the response using json.dumps with DecimalEncoder to ensure
        that all Decimal values (like fees) are formatted in fixed‑point notation rather than
        scientific notation. Finally, it validates and, if appropriate, adopts the new chain.
        
        :param peer_url: The URL of the peer to request the chain from.
        """
        try:
            url = f"{peer_url}/api/block/full_chain"
            response = requests.get(url, timeout=10)
            if response.status_code == 200:
                # Get the JSON response from the peer
                original_data = response.json()
                # Re-serialize using our custom DecimalEncoder to enforce fixed‑point formatting
                chain_str = json.dumps(original_data, cls=DecimalEncoder)
                # Then parse the string back to a dictionary
                chain_data = json.loads(chain_str).get('chain', [])
                if len(chain_data) > len(self.ledger.chain):
                    # Validate the fetched chain using the ledger's full-chain validator
                    if self.ledger.validate_full_chain(chain_data):
                        # Adopt the new chain if it's valid and longer
                        if self.ledger.adopt_new_chain(chain_data):
                            logger.info(f"Adopted new chain from {peer_url}, length={len(chain_data)}.")
                            return
            else:
                logger.warning(f"Failed to retrieve chain from {peer_url}, status code: {response.status_code}")
        except requests.exceptions.RequestException as e:
            logger.error(f"Error requesting chain sync from {peer_url}: {e}")

    # ----------------------------------------------------------------
    #  UTILITY METHODS
    # ----------------------------------------------------------------

    def get_own_url(self) -> str:
        """
        Retrieves the node's own URL based on its hostname and port.

        Returns:
            str: The node's own URL (e.g., "http://omne1:3400")
        """
        hostname = socket.gethostname()
        try:
            ip_address = socket.gethostbyname(hostname)
            return f"http://{hostname}:{self.port}"
        except socket.gaierror:
            # Fallback to localhost if hostname resolution fails
            return f"http://localhost:{self.port}"
    
    # ----------------------------------------------------------------
    #  REQUEST VRF OUTPUTS METHOD
    # ----------------------------------------------------------------

    def request_vrf_outputs(self, round_number: int) -> List[Dict]:
        """
        Requests VRF outputs from all known peers for a specific consensus round.

        :param round_number: The current consensus round number
        :return: A list of VRF output dictionaries from peers
        """
        vrf_outputs = []
        logger.info(f"Requesting VRF outputs from peers for Round {round_number}.")

        with self.lock:
            current_peers = list(self.peers)

        for peer in current_peers:
            vrf_endpoint = f"{peer}/api/consensus/get_vrf_outputs"
            try:
                response = requests.get(vrf_endpoint, params={"round": round_number}, timeout=5)
                if response.status_code == 200:
                    peer_vrf_output = response.json().get('vrf_output')
                    if peer_vrf_output:
                        vrf_outputs.append({
                            'peer': peer,
                            'vrf_output': bytes.fromhex(peer_vrf_output)
                        })
                        logger.debug(f"Received VRF output from {peer}.")
                    else:
                        logger.warning(f"No VRF output found in response from {peer}.")
                else:
                    logger.warning(f"Failed to get VRF output from {peer}. Status Code: {response.status_code}")
            except requests.exceptions.RequestException as e:
                logger.error(f"Error requesting VRF output from {peer}: {e}")

        logger.info(f"Received {len(vrf_outputs)} VRF outputs from peers for Round {round_number}.")
        return vrf_outputs

    # ----------------------------------------------------------------
    #  SHUTDOWN METHOD
    # ----------------------------------------------------------------

    def shutdown(self):
        """
        Gracefully shuts down the network manager.
        """
        logger.info("Shutting down NetworkManager.")
        # Implement any necessary cleanup here, such as stopping threads or closing connections

    # ----------------------------------------------------------------
    #  Flask Blueprints for Modular Endpoints
    # ----------------------------------------------------------------

    def _initialize_blueprints(self):
        """
        Initializes and registers Flask blueprints.
        """
        # 1. Block Management Endpoints
        block_bp = Blueprint('block_bp', __name__)

        @block_bp.route('/api/block/receive_block', methods=['POST'])
        def receive_block():
            """
            Endpoint to receive a new block from a peer.
            """
            block_data = request.json
            if not block_data:
                return jsonify({"error": "No block data received."}), 400

            try:
                block = Block.from_dict(block_data)
            except Exception as e:
                logger.error(f"Failed to parse block data: {e}")
                return jsonify({"error": "Invalid block data format."}), 400

            success = self.ledger.add_block(block)
            if success:
                self.ledger.finalize_block_transactions(block)
                logger.info(f"Block {block.index} accepted and finalized.")
                # Broadcast the block to other peers except the one who sent it
                peer_url = request.headers.get('X-Peer-URL')  # Use a custom header to get the peer's URL
                if peer_url:
                    self.broadcast_block(block.to_dict(), exclude_peer_url=peer_url)
                else:
                    self.broadcast_block(block.to_dict())
                return jsonify({"message": "Block accepted and broadcasted"}), 200
            else:
                logger.warning(f"Block {block.hash} rejected.")
                # Optionally, trigger chain sync or further fork handling
                peer_url = request.headers.get('X-Peer-URL')
                if peer_url:
                    self.request_chain_sync(peer_url=peer_url)
                return jsonify({"message": "Block rejected"}), 400

        # 2. Transaction Management Endpoints
        transaction_bp = Blueprint('transaction_bp', __name__)

        @transaction_bp.route('/api/transaction/receive_transaction', methods=['POST'])
        def receive_transaction():
            """
            Endpoint to receive a new transaction from a peer.
            """
            transaction = request.json
            if not transaction:
                return jsonify({"error": "No transaction data received."}), 400

            # Validate the transaction using TransactionVerifier instead of account_manager
            if not TransactionVerifier.verify(transaction):
                return jsonify({"error": "Invalid transaction."}), 400

            # Add to mempool
            if self.mempool.add_transaction(transaction):
                logger.info(f"Transaction {transaction.get('hash')} added to mempool.")
            else:
                logger.warning(f"Transaction {transaction.get('hash')} failed to add to mempool.")

            # Broadcast to other peers except the one who sent it
            peer_url = request.headers.get('X-Peer-URL')
            if peer_url:
                self.broadcast_transaction(transaction, exclude_peer_url=peer_url)
            else:
                self.broadcast_transaction(transaction)

            return jsonify({"message": "Transaction received and broadcasted"}), 200

        # 3. Peer Management Endpoints
        peer_bp = Blueprint('peer_bp', __name__)

        @peer_bp.route('/api/peer/add_peer', methods=['POST'])
        def add_peer_endpoint():
            """
            Endpoint to add a new peer.
            Expects JSON: {"peer_url": "http://peer-address:port"}
            """
            data = request.json
            peer_url = data.get("peer_url")
            if not peer_url:
                return jsonify({"error": "No peer_url provided."}), 400

            self.add_peer(peer_url)
            return jsonify({"message": f"Peer {peer_url} added."}), 200

        @peer_bp.route('/api/peer/peers', methods=['GET'])
        def list_peers():
            """
            Endpoint to retrieve the list of known peers.
            """
            with self.lock:
                peers = list(self.peers)
            return jsonify({"peers": peers}), 200

        # 4. Consensus Management Endpoints
        consensus_bp = Blueprint('consensus_bp', __name__)

        @consensus_bp.route('/api/consensus/submit_vrf', methods=['POST'])
        def submit_vrf():
            """
            Endpoint for validators to submit their VRF outputs during the commit phase.
            Expects JSON: {"validator_id": "Validator1", "vrf_output": "randomstring"}
            """
            data = request.json
            validator_id = data.get("validator_id")
            vrf_output = data.get("vrf_output")

            if not validator_id or not vrf_output:
                return jsonify({"error": "validator_id and vrf_output are required."}), 400

            # Convert vrf_output from hex string to bytes
            try:
                vrf_output_bytes = bytes.fromhex(vrf_output)
            except ValueError:
                return jsonify({"error": "Invalid vrf_output format."}), 400

            if self.consensus_engine and self.consensus_engine.receive_vrf_output(validator_id, vrf_output_bytes):
                return jsonify({"message": "VRF output received."}), 200
            else:
                return jsonify({"error": "Failed to receive VRF output."}), 400

        # 5. Health Check Endpoint
        health_bp = Blueprint('health_bp', __name__)

        @health_bp.route('/api/health', methods=['GET'])
        def health_check():
            """
            Health check endpoint to verify node availability.
            """
            return jsonify({"status": "ok"}), 200

        @health_bp.route('/api/health/detailed', methods=['GET'])
        def detailed_health_check():
            """
            Detailed health check with system metrics and status.
            """
            try:
                # Import performance monitor if available
                try:
                    from performance_monitor import PerformanceMonitor
                    monitor = PerformanceMonitor()
                    metrics = monitor.get_current_metrics()
                except ImportError:
                    metrics = {"error": "Performance monitoring not available"}
                
                # Basic system status
                status = {
                    "status": "ok",
                    "timestamp": datetime.now(timezone.utc).isoformat(),
                    "node_id": getattr(self, 'node_id', 'unknown'),
                    "blockchain_height": len(self.ledger.chain) if self.ledger else 0,
                    "mempool_size": len(self.mempool.transactions) if self.mempool else 0,
                    "is_mining": getattr(self.consensus_engine, 'is_mining', False) if self.consensus_engine else False,
                    "peer_count": len(getattr(self, 'peers', [])),
                    "performance_metrics": metrics
                }
                
                return jsonify(status), 200
            except Exception as e:
                logger.error(f"Health check failed: {e}")
                return jsonify({
                    "status": "error", 
                    "error": str(e),
                    "timestamp": datetime.now(timezone.utc).isoformat()
                }), 500

        @health_bp.route('/api/metrics', methods=['GET'])
        def get_metrics():
            """
            Get performance and system metrics for monitoring.
            """
            try:
                # Import performance monitor if available
                try:
                    from performance_monitor import PerformanceMonitor
                    monitor = PerformanceMonitor()
                    return jsonify(monitor.get_detailed_metrics()), 200
                except ImportError:
                    return jsonify({"error": "Performance monitoring not available"}), 503
            except Exception as e:
                logger.error(f"Metrics endpoint failed: {e}")
                return jsonify({"error": str(e)}), 500

        @health_bp.route('/api/status', methods=['GET'])
        def get_status():
            """
            Get comprehensive node status for diagnostics.
            """
            try:
                status = {
                    "node_info": {
                        "node_id": getattr(self, 'node_id', 'unknown'),
                        "version": "1.0.0",  # Should come from config
                        "uptime": time.time() - getattr(self, 'start_time', time.time()),
                        "timestamp": datetime.now(timezone.utc).isoformat()
                    },
                    "blockchain": {
                        "height": len(self.ledger.chain) if self.ledger else 0,
                        "last_block_time": self.ledger.chain[-1].timestamp if self.ledger and self.ledger.chain else None,
                        "difficulty": getattr(self.consensus_engine, 'difficulty', 'unknown') if self.consensus_engine else 'unknown'
                    },
                    "network": {
                        "peer_count": len(getattr(self, 'peers', [])),
                        "connected_peers": getattr(self, 'peers', []),
                        "is_syncing": getattr(self, 'is_syncing', False)
                    },
                    "mempool": {
                        "transaction_count": len(self.mempool.transactions) if self.mempool else 0,
                        "pending_size": len(getattr(self.mempool, 'transactions', {}))
                    },
                    "consensus": {
                        "is_mining": getattr(self.consensus_engine, 'is_mining', False) if self.consensus_engine else False,
                        "validator_status": "active" if self.consensus_engine else "inactive"
                    }
                }
                
                return jsonify(status), 200
            except Exception as e:
                logger.error(f"Status endpoint failed: {e}")
                return jsonify({"error": str(e)}), 500

        # 6. Full Chain Retrieval Endpoint
        @block_bp.route('/api/block/full_chain', methods=['GET'])
        def full_chain():
            logger.info("full_chain endpoint called - about to acquire ledger.lock.")
            with self.ledger.lock:
                logger.info("full_chain endpoint: lock acquired, building chain_data.")
                chain_data = [block.to_dict() for block in self.ledger.chain]
            logger.info("full_chain endpoint: lock released, returning data.")
            return jsonify({"chain": chain_data}), 200
        
        # 7. Accounts Management Endpoints
        accounts_bp = Blueprint('accounts_bp', __name__)
        
        @accounts_bp.route('/api/get_transactions_for_address', methods=['GET'])
        def get_transactions_for_address():
            """
            Retrieves all transactions related to a given wallet address.
            This includes mined (on‑chain) transactions as well as pending transactions.
            """
            wallet_address = request.args.get('address')
            if not wallet_address:
                return jsonify({"error": "Wallet address is required"}), 400

            address_transactions = {
                'mined_transactions': [],
                'pending_transactions': [],
                'cleaned_transactions': [],
                'verified_transactions': [],
                'confirmed_transactions': []
            }

            # --- Mined Transactions ---
            # Iterate over all blocks in the ledger’s chain.
            # (Assumes that each block is either a dictionary or a Block instance with a to_dict() method.)
            ledger = app.config.get("LEDGER")  # Assuming you have stored the ledger reference in Flask's config
            if ledger is None:
                logging.error("Ledger not configured in Flask app context.")
                return jsonify({"error": "Server misconfiguration"}), 500

            for block in ledger.chain:
                if hasattr(block, "to_dict"):
                    block_data = block.to_dict()
                else:
                    block_data = block
                for tx in block_data.get('transactions', []):
                    # Check if the wallet address is the sender or (if present) the recipient.
                    if tx.get('sender') == wallet_address or tx.get('recipient') == wallet_address:
                        address_transactions['mined_transactions'].append(tx)

            # --- Pending Transactions ---
            # Assume pending transactions are stored in the mempool.
            mempool = ledger.mempool  # We assume the ledger has a reference to the mempool.
            pending = getattr(mempool, "transactions", [])
            address_transactions['pending_transactions'] = [
                tx for tx in pending
                if tx.get('sender') == wallet_address or tx.get('recipient') == wallet_address
            ]

            # --- Verified/Confirmed/Cleaned Transactions ---
            # For now, if these lists are not implemented, return empty arrays.
            address_transactions['verified_transactions'] = []
            address_transactions['confirmed_transactions'] = []
            address_transactions['cleaned_transactions'] = []

            return jsonify(address_transactions), 200
        
        @accounts_bp.route('/api/omc_info', methods=['GET'])
        def omc_info():
            """
            Returns basic information about the Omne coin (OMC).
            """
            ledger = app.config.get("LEDGER")
            if ledger is None or not hasattr(ledger, "omc"):
                logging.error("OMC not configured in ledger.")
                return jsonify({"error": "Server misconfiguration"}), 500

            coin_info = {
                'name': ledger.omc.name,
                'symbol': ledger.omc.symbol,
                'decimals': ledger.omc.decimals,
                'image': ledger.omc.image
            }
            return jsonify(coin_info), 200
        
        @accounts_bp.route('/api/propagate_account', methods=['POST'])
        def propagate_account():
            """
            Propagates a new account to the network.
            Expects JSON with keys:
            "sender", "balance", "public_key", "signature", "timestamp", 
            "hash", "type", "nonce", "fee", "data"
            
            Returns:
            {
                "message": "Account propagated and added successfully.",
                "local_hash": "<mempool-local-hash>"
            }
            on success, or an error JSON on failure.
            """
            data = request.json
            sender = data.get('sender')
            balance = data.get('balance')
            public_key = data.get('public_key')
            signature = data.get('signature')
            fee = data.get('fee')
            tx_type = data.get('type')
            nonce = data.get('nonce')
            timestamp = data.get('timestamp')
            tx_hash = data.get('hash')

            data_field = data.get('data') or {}

            if not sender or balance is None:
                return jsonify({'error': "Missing 'sender' or 'balance' in request."}), 400

            # Convert balance to Decimal
            try:
                balance_decimal = Decimal(balance)
            except InvalidOperation:
                return jsonify({'error': "Invalid balance format."}), 400

            # Check if account already exists
            if self.account_manager.get_account_balance(sender) is not None:
                return jsonify({'message': 'Account already exists.'}), 200

            # Try adding account to ledger with the given balance
            success = self.account_manager.add_account(sender, balance_decimal)
            if not success:
                return jsonify({'error': 'Failed to add account to ledger.'}), 500

            # Broadcast to local mempool + peers
            local_hash = self.broadcast_new_account(
                sender=sender,
                balance=str(balance_decimal),
                exclude_peer_url=None,
                public_key=public_key,
                signature=signature,
                timestamp=timestamp,
                tx_hash=tx_hash,  # user-provided hash, not used for verification
                type=tx_type,
                nonce=nonce,
                fee=fee,
                data=data_field
            )

            if local_hash:
                return jsonify({
                    'message': 'Account propagated and added successfully.',
                    'local_hash': local_hash
                }), 201
            else:
                return jsonify({'error': 'Failed to propagate account.'}), 500
            
        @accounts_bp.route('/api/retrieve_accounts', methods=['GET'])
        def retrieve_accounts():
            """
            Endpoint to retrieve all accounts, staking contracts, and node information.
            Now includes each address' sOMC balance as 'sOMC'.
            """
            try:
                # 1) Handle pagination parameters
                page = int(request.args.get('page', 1))
                per_page = int(request.args.get('per_page', 100))

                # 2) Retrieve account balances from the ledger
                all_accounts = self.ledger.account_manager.get_all_accounts()  # => dict: address -> account dict
                account_items = list(all_accounts.items())  # => [ (address, account_dict), ... ]

                start = (page - 1) * per_page
                end = start + per_page
                paginated_list = account_items[start:end]

                # convert back to a dict
                paginated_accounts = dict(paginated_list)

                # 3) For each address in our paginated accounts, fetch sOMC from staked_omc
                for address, account_data in paginated_accounts.items():
                    s_balance = self.ledger.staking_manager.staked_omc.get_balance(address)
                    # If s_balance is None, it might not exist in staked_omc
                    # We'll assume that means zero
                    s_balance_str = str(s_balance) if s_balance is not None else "0"
                    account_data["sOMC"] = s_balance_str

                # 4) Retrieve staking contracts with pagination
                all_staking = self.ledger.staking_manager.get_active_staking_agreements()
                staking_paginated = all_staking[start:end]

                # 5) Retrieve node info
                nodes = self.ledger.verifier.get_all_nodes()

                response_data = {
                    'data': paginated_accounts,  # now each account has "sOMC": <string> included
                    'staking_accounts': staking_paginated,
                    'nodes': nodes,
                    'pagination': {
                        'page': page,
                        'per_page': per_page,
                        'total_accounts': len(all_accounts),
                        'total_staking': len(all_staking)
                    }
                }

                return jsonify(response_data), 200

            except Exception as e:
                logger.exception("Exception occurred while retrieving accounts.")
                return jsonify({"message": "Error retrieving accounts", "error": str(e)}), 500
        
        @accounts_bp.route('/api/omc_balance', methods=['POST'])
        def get_omc_balance():
            """
            Endpoint to check the balance of a wallet's OMC.
            Expects JSON: { "address": "0zUserAddress123" }
            """
            try:
                data = request.get_json()
                address = data.get('address')
                if not address:
                    return jsonify({"error": "Address not provided"}), 400

                logger.debug(f"Fetching OMC balance for address: {address}")
                balance = self.ledger.account_manager.get_account_balance(address)

                if balance is not None:
                    response = {
                        'message': 'Account balance retrieved successfully',
                        'balance': balance,
                        'balance_float': float(balance) / (10 ** self.ledger.omc.decimals)
                    }
                    logger.debug(f"OMC balance for {address}: {balance}")
                    return jsonify(response), 200
                else:
                    logger.debug(f"Address {address} not found in OMC balances.")
                    return jsonify({"error": "Account not found"}), 404

            except Exception as e:
                logger.exception("Error in get_omc_balance endpoint.")
                return jsonify({"error": "Internal server error", "details": str(e)}), 500

        @accounts_bp.route('/api/somc_balance', methods=['POST'])
        def get_somc_balance():
            """
            Endpoint to check the sOMC balance of a given wallet address.
            Expects JSON: { "address": "0zUserAddress123" }
            """
            try:
                data = request.get_json()
                if not data or "address" not in data:
                    return jsonify({"error": "No 'address' provided"}), 400

                address = data["address"]
                logger.debug(f"Fetching sOMC balance for address: {address}")

                # Use staked_omc's get_balance
                s_balance = self.ledger.staking_manager.staked_omc.get_balance(address)
                if s_balance is None:
                    # If an address isn't found in staked_omc, we consider it zero
                    s_balance = 0

                # Return the integer-based sOMC plus a float version
                s_balance_str = str(s_balance)
                # If your staked_omc stores the raw integer scaled by decimals,
                # you might want to convert it like so:
                s_balance_float = float(s_balance) / (10 ** self.ledger.omc.decimals)

                response = {
                    'message': 'sOMC balance retrieved successfully',
                    'address': address,
                    'balance': s_balance_str,
                    'balance_float': s_balance_float
                }
                return jsonify(response), 200

            except Exception as e:
                logger.exception("Error in get_somc_balance endpoint.")
                return jsonify({"error": "Internal server error", "details": str(e)}), 500

        @accounts_bp.route('/api/check_activity', methods=['POST'])
        def check_activity():
            """
            Endpoint to check the activity of a wallet.
            Expects JSON: { "address": "0zUserAddress123" }
            """
            try:
                data = request.get_json()
                address = data.get('address')
                if not address:
                    return jsonify({"error": "Address not provided"}), 400

                logger.debug(f"Checking activity for address: {address}")

                # Initialize result dictionaries for each history type
                transfer_result = Decimal('0')
                minting_result = Decimal('0')
                burning_result = Decimal('0')

                # Check for the address in each history list and calculate the totals
                # Assuming OMC and StakedOMC maintain transfer_history, minting_history, burning_history

                # Transfer History
                for transfer in self.ledger.omc.transfer_history:
                    from_address, to_address, amount = transfer
                    if from_address == address:
                        transfer_result -= Decimal(amount)
                    if to_address == address:
                        transfer_result += Decimal(amount)

                for transfer in self.ledger.staking_manager.staked_omc.transfer_history:
                    from_address, to_address, amount = transfer
                    if from_address == address:
                        transfer_result -= Decimal(amount)
                    if to_address == address:
                        transfer_result += Decimal(amount)

                # Minting History
                for mint in self.ledger.omc.minting_history:
                    to_address, amount = mint
                    if to_address == address:
                        minting_result += Decimal(amount)

                for mint in self.ledger.staking_manager.staked_omc.minting_history:
                    to_address, amount = mint
                    if to_address == address:
                        minting_result += Decimal(amount)

                # Burning History
                for burn in self.ledger.omc.burning_history:
                    amount = burn
                    burning_result -= Decimal(amount)

                for burn in self.ledger.staking_manager.staked_omc.burning_history:
                    amount = burn
                    burning_result -= Decimal(amount)

                # Prepare the response
                response_data = {
                    "address": address,
                    "transfer_history": str(transfer_result),
                    "minting_history": str(minting_result),
                    "burning_history": str(burning_result)
                }

                logger.debug(f"Activity for {address}: {response_data}")

                return jsonify(response_data), 200

            except Exception as e:
                logger.exception("Error in check_activity endpoint.")
                return jsonify({"error": "Internal server error", "details": str(e)}), 500

        @accounts_bp.route('/api/get_coin_economy', methods=['GET'])
        def get_coin_economy():
            """
            Endpoint to retrieve coin economy data.
            """
            try:
                logger.debug("Fetching coin economy data.")

                # Economy data structure for open nodes (no treasury access)
                economy_data = {
                    "total_coin_supply": str(self.ledger.omc.coin_max),
                    "total_staked": str(self.ledger.staking_manager.get_total_staked()),
                    "staked_omc_distributed": str(self.ledger.staking_manager.get_staked_omc_distributed())
                    # Note: Treasury balance not accessible to open nodes
                }

                logger.debug(f"Coin economy data: {economy_data}")

                return jsonify({
                    "message": "Coin economy data retrieved successfully",
                    "data": economy_data
                }), 200

            except Exception as e:
                logger.exception("Error in get_coin_economy endpoint.")
                return jsonify({"error": "Internal server error", "details": str(e)}), 500
        
        @accounts_bp.route('/api/get_last_nonce', methods=['GET'])
        def get_last_nonce():
            """
            Retrieves the last confirmed nonce for the given wallet address.
            Expects a query parameter 'address'.
            Returns JSON: { "nonce": <number> }
            """
            address = request.args.get('address')
            if not address:
                return jsonify({"error": "Address not provided"}), 400

            # Retrieve the nonce from the account manager.
            nonce = 0
            try:
                nonce = self.ledger.account_manager.get_last_nonce(address)
            except Exception as e:
                logger.error(f"Error fetching nonce for {address}: {e}")
                return jsonify({"error": "Internal server error"}), 500

            return jsonify({"nonce": nonce}), 200
        
        # 8. Transfer Management Endpoints
        transfer_bp = Blueprint('transfer_bp', __name__)
        
        # 8.1. /create_transfer_request [POST]
        @transfer_bp.route('/api/create_transfer_request', methods=['POST'])
        def create_transfer_request():
            """
            Creates a new transfer request.
            Expects JSON: { "from_address": "...", "to_address": "...", "amount": Decimal, "permission": { "permission": "pending" } }
            """
            try:
                data = request.get_json()
                from_address = data.get('from_address')
                to_address = data.get('to_address')
                amount = data.get('amount')
                permission = data.get('permission', {'permission': 'pending'})

                # Validate required fields
                if not all([from_address, to_address, amount]):
                    return jsonify({"error": "Missing required fields: 'from_address', 'to_address', 'amount'"}), 400

                # Convert amount to Decimal
                try:
                    amount_decimal = Decimal(str(amount))
                except InvalidOperation:
                    return jsonify({"error": "Invalid amount format."}), 400

                # Create transfer request via OMC
                transfer_request = self.ledger.omc.create_transfer_request(from_address, to_address, amount_decimal, permission)

                return jsonify({
                    "message": "Transfer request created successfully",
                    "request_id": transfer_request.permission['id']
                }), 200

            except DoubleSpendingError as e:
                self.logger.error(f"Double spending attempt: {e}")
                return jsonify({"error": str(e)}), 400
            except Exception as e:
                self.logger.exception("Error creating transfer request.")
                return jsonify({"error": "Internal server error", "details": str(e)}), 500

        # 8.2. /approve_transfer_request/<request_id> [POST]
        @transfer_bp.route('/api/approve_transfer_request/<request_id>', methods=['POST'])
        def approve_transfer_request(request_id):
            """
            Approves a specific transfer request.
            Expects JSON: { "sender_pub": "...", "permission_sig": "..." }
            """
            try:
                data = request.get_json()
                sender_pub = data.get('sender_pub')
                permission_sig = data.get('permission_sig')

                if not all([sender_pub, permission_sig]):
                    return jsonify({"error": "Missing required fields: 'sender_pub', 'permission_sig'"}), 400

                # Approve transfer request via OMC
                success = self.ledger.omc.approve_transfer_request(request_id, sender_pub, permission_sig)

                if success:
                    return jsonify({"message": "Transfer request approved successfully"}), 200
                else:
                    return jsonify({"error": "Transfer request not found or already processed"}), 404

            except Exception as e:
                self.logger.exception("Error approving transfer request.")
                return jsonify({"error": "Internal server error", "details": str(e)}), 500

        # 8.3. /decline_transfer_request/<request_id> [POST]
        @transfer_bp.route('/api/decline_transfer_request/<request_id>', methods=['POST'])
        def decline_transfer_request(request_id):
            """
            Declines a specific transfer request.
            """
            try:
                success = self.ledger.omc.decline_transfer_request(request_id)

                if success:
                    return jsonify({"message": "Transfer request declined successfully"}), 200
                else:
                    return jsonify({"error": "Transfer request not found or already processed"}), 404

            except Exception as e:
                self.logger.exception("Error declining transfer request.")
                return jsonify({"error": "Internal server error", "details": str(e)}), 500

        # 8.4. /process_transfer_request/<request_id> [POST]
        @transfer_bp.route('/api/process_transfer_request/<request_id>', methods=['POST'])
        def process_transfer_request(request_id):
            """
            Processes an approved transfer request.
            """
            try:
                success = self.ledger.omc.process_transfer_request(request_id)

                if success:
                    return jsonify({"message": "Transfer request processed successfully"}), 200
                else:
                    return jsonify({"error": "Failed to process transfer request"}), 400

            except Exception as e:
                self.logger.exception("Error processing transfer request.")
                return jsonify({"error": "Internal server error", "details": str(e)}), 500

        # 8.5. /get_request/<request_id> [GET]
        @transfer_bp.route('/api/get_request/<request_id>', methods=['GET'])
        def get_request(request_id):
            """
            Retrieves details of a specific transfer request.
            """
            try:
                transfer_request = self.ledger.omc.get_request_by_id(request_id)

                if transfer_request:
                    return jsonify({
                        'from_address': transfer_request.from_address,
                        'to_address': transfer_request.to_address,
                        'amount': str(transfer_request.amount),
                        'permission': transfer_request.permission,
                        'sender_pub': transfer_request.sender_pub,
                        'permission_sig': transfer_request.permission_sig,
                        'timestamp': transfer_request.timestamp.isoformat(),
                        'status': transfer_request.status
                    }), 200
                else:
                    return jsonify({'error': 'Transfer request not found'}), 404

            except Exception as e:
                self.logger.exception("Error retrieving transfer request.")
                return jsonify({"error": "Internal server error", "details": str(e)}), 500

        # 8.6. /get_pending_requests/<address> [GET]
        @transfer_bp.route('/api/get_pending_requests/<address>', methods=['GET'])
        def get_pending_requests(address):
            """
            Retrieves all pending transfer requests for a specific address.
            """
            try:
                pending_requests = self.ledger.omc.get_pending_requests_for_user(address)

                return jsonify(pending_requests), 200

            except Exception as e:
                self.logger.exception("Error retrieving pending transfer requests.")
                return jsonify({"error": "Internal server error", "details": str(e)}), 500

        # 8.7. /update_request_permissions/<request_id> [POST]
        @transfer_bp.route('/api/update_request_permissions/<request_id>', methods=['POST'])
        def update_request_permissions(request_id):
            """
            Updates permissions for a specific transfer request.
            Expects JSON: { "sender_pub": "...", "permission_sig": "...", "permission_approval": "approved" or "declined" }
            """
            try:
                data = request.get_json()
                sender_pub = data.get('sender_pub')
                permission_sig = data.get('permission_sig')
                permission_approval = data.get('permission_approval')

                if not all([sender_pub, permission_sig, permission_approval]):
                    return jsonify({"error": "Missing required fields: 'sender_pub', 'permission_sig', 'permission_approval'"}), 400

                if permission_approval.lower() not in ['approved', 'declined']:
                    return jsonify({"error": "Invalid permission_approval value. Must be 'approved' or 'declined'."}), 400

                # Update permissions via OMC
                success = self.ledger.omc.update_request_permissions(request_id, sender_pub, permission_sig, permission_approval)

                if success:
                    return jsonify({"message": "Transfer request permissions updated successfully"}), 200
                else:
                    return jsonify({"error": "Transfer request not found"}), 404

            except ValueError as e:
                self.logger.error(f"ValueError: {e}")
                return jsonify({'error': str(e)}), 400
            except Exception as e:
                self.logger.exception("Error updating transfer request permissions.")
                return jsonify({"error": "Internal server error", "details": str(e)}), 500

        # 8.8. /transfer_coins [POST]
        @transfer_bp.route('/api/transfer_coins', methods=['POST'])
        def transfer_coins():
            """
            Executes a coin transfer based on an approved transfer request.
            Expects JSON: {
                "from_address": "...",
                "to_address": "...",
                "amount": Decimal,
                "fee": Decimal,
                "hash": "request_id",
                "pub_key": "...",
                "signature": "...",
                "sub_type": "...",
                "type": "..."
            }
            """
            try:
                data = request.get_json()

                # Extract the relevant data from the request
                from_address = data.get('from_address')
                to_address = data.get('to_address')
                amount = data.get('amount')
                fee = data.get('fee')
                hash_id = data.get('hash')
                pub_key = data.get('pub_key')
                signature = data.get('signature')
                sub_type = data.get('sub_type')
                type = data.get('type')

                # Validate required data
                if not all([from_address, to_address, amount]):
                    return jsonify({"error": "Missing required fields: 'from_address', 'to_address', 'amount'"}), 400

                # Convert amount to Decimal
                try:
                    amount_decimal = Decimal(amount)
                except InvalidOperation:
                    return jsonify({"error": "Invalid amount format."}), 400

                # Check if sender has enough balance
                sender_balance = self.ledger.omc.get_balance(from_address)
                if sender_balance is None:
                    return jsonify({"error": f"Sender address {from_address} does not exist."}), 404
                if sender_balance < amount_decimal:
                    return jsonify({"error": f"Insufficient balance in {from_address} to transfer {amount} OMC"}), 400

                # Check if the transfer request exists and is approved
                transfer_request = self.ledger.omc.get_request_by_id(hash_id)
                if not transfer_request:
                    return jsonify({"error": "Transfer request not found."}), 404
                if transfer_request.status != "approved":
                    return jsonify({"error": f"Transfer request {hash_id} is not approved."}), 403

                # Optionally, verify signature and pub_key here

                # Execute the transfer
                success = self.ledger.omc.transfer(from_address, to_address, amount_decimal)

                if success:
                    # Log the transfer
                    self.logger.info(f"Transfer of {amount_decimal} OMC from {from_address} to {to_address} executed successfully.")
                    return jsonify({"message": "Transfer executed successfully."}), 200
                else:
                    return jsonify({"error": "Failed to execute transfer."}), 400

            except Exception as e:
                self.logger.exception("Error executing coin transfer.")
                return jsonify({'error': 'Internal Server Error: Unable to process transfer.'}), 500
            
        # 9. STAKING MANAGEMENT ENDPOINTS
        staking_bp = Blueprint('staking_bp', __name__)
        
        # 9.1 /stake_coins [POST]
        @staking_bp.route('/api/stake_coins', methods=['POST'])
        def stake_coins():
            """
            Endpoint to stake coins.
            Expects JSON:
            {
            "node_address": "node-address",
            "address": "user-address",
            "amount": <number>,
            "min_term": <number>,
            "pub_key": "public-key"
            }
            """
            try:
                data = request.get_json()
                node_address = data.get('node_address')
                address = data.get('address')
                amount = data.get('amount')
                min_term = data.get('min_term')
                pub_key = data.get('pub_key')
                if not all([node_address, address, amount, min_term, pub_key]):
                    return jsonify({"error": "Missing required fields"}), 400

                # Convert amount to float (the staking method expects a float for amount)
                amount_float = float(amount)
                staking_contract = self.ledger.staking_manager.stake_coins(node_address, address, amount_float, int(min_term), pub_key)
                return jsonify({"message": "Staking contract created successfully", "staking_contract": staking_contract}), 200
            except Exception as e:
                logger.exception("Error creating staking contract.")
                return jsonify({"error": "Internal server error", "details": str(e)}), 500
        
        # 9.2 /unstake_coins [POST]
        @staking_bp.route('/api/unstake_coins', methods=['POST'])
        def unstake_coins():
            """
            Endpoint to unstake coins.
            Expects JSON:
            {
            "address": "user-address",
            "contract_id": "staking-contract-id",
            "current_block_height": <number> (optional, default 0),
            "force": <boolean> (optional, default False)
            }
            """
            try:
                data = request.get_json()
                address = data.get('address')
                contract_id = data.get('contract_id')
                current_block_height = data.get('current_block_height', 0)
                force = data.get('force', False)
                if not all([address, contract_id]):
                    return jsonify({"error": "Missing required fields: address and contract_id"}), 400

                success = self.ledger.staking_manager.unstake_coins(address, contract_id, int(current_block_height), bool(force))
                if success:
                    return jsonify({"message": "Unstake operation successful"}), 200
                else:
                    return jsonify({"error": "Unstake operation failed"}), 400
            except Exception as e:
                logger.exception("Error processing unstake request.")
                return jsonify({"error": "Internal server error", "details": str(e)}), 500

        # Register Blueprints
        app.register_blueprint(block_bp)
        app.register_blueprint(transaction_bp)
        app.register_blueprint(peer_bp)
        app.register_blueprint(consensus_bp)
        app.register_blueprint(health_bp)
        app.register_blueprint(accounts_bp)
        app.register_blueprint(transfer_bp)
        
        # Initialize and register validator API for network joining
        initialize_validator_api(self.ledger, self.omc, self.staking_manager, self.verifier, self.consensus_engine)
        app.register_blueprint(validator_api)

    # ----------------------------------------------------------------
    #  START SERVER METHOD
    # ----------------------------------------------------------------

    def start_server(self):
        """
        Starts the Flask server. Intended to run in a separate thread.
        """
        logger.info(f"Starting Flask server on port {self.port}...")
        # Disable Flask's default logger to prevent duplicate logs
        log = logging.getLogger('werkzeug')
        log.setLevel(logging.ERROR)
        app.run(host='0.0.0.0', port=self.port, threaded=True)

    # ----------------------------------------------------------------
    #  NODE INITIALIZATION METHOD
    # ----------------------------------------------------------------

    def initialize_node(self):
        """
        Initializes the node for service discovery using Docker's service discovery.
        """
        logger.info("Initializing node for service discovery using Docker DNS...")

        # Define the prefix based on your Docker service naming convention
        prefix = "omne"
        max_range = int(os.getenv("NODE_COUNT", "10"))  # Set NODE_COUNT appropriately

        # Discover services
        discovered_services = self.discover_services(prefix=prefix, max_range=max_range)

        # Ping discovered services to validate and retrieve their node information
        self.ping_services(discovered_services)

        logger.info("Peer discovery and validation complete.")

# ----------------------------------------------------------------
#  MAIN APPLICATION ENTRY POINT
# ----------------------------------------------------------------

def main():
    """
    Main function to initialize and start the NetworkManager.
    """
    setup_logging()
    logger = logging.getLogger('Main')
    logger.info("Starting Omne Node NetworkManager...")

    # Read secrets
    TREASURY_ADDRESS = read_secret("TREASURY_ADDRESS")
    TREASURY_PUBLIC_KEY = read_secret("TREASURY_PUBLIC_KEY")
    TREASURY_PRIVATE_KEY = read_secret("TREASURY_PRIVATE_KEY")
    MONGODB_URI = read_secret("MONGODB_URI")

    # Initialize MongoDB client
    try:
        mongo_client = MongoClient(MONGODB_URI, server_api=ServerApi('1'))  # Ensure server_api is set if needed
        # Optionally, test the connection
        mongo_client.admin.command('ping')
        logging.info("Successfully connected to MongoDB.")
    except Exception as e:
        logging.critical(f"Failed to connect to MongoDB: {e}")
        sys.exit(1)  # Exit since MongoDB is critical

    # Initialize CryptoUtils
    crypto_utils = CryptoUtils()

    # Initialize DynamicFeeCalculator
    fee_calculator = DynamicFeeCalculator(
        base_fee=Decimal('0.1'),
        fee_multiplier=Decimal('0.05'),
        size_multiplier=Decimal('0.001'),
        type_fee_adjustments={
            'deploy_contract': Decimal('1.0'),
            'execute_contract': Decimal('0.5'),
            'standard_transfer': Decimal('0.0')
        },
        moving_average_window=100,
        max_fee=Decimal('10'),
        min_fee=Decimal('0.01')
    )

    # Initialize AccountManager **before** Ledger
    account_manager = AccountManager()

    # Initialize OMC (Omne Coin) with the treasury address
    omc = OMC(
        account_manager=account_manager,
        treasury_address=TREASURY_ADDRESS,
        coin_max=Decimal('22000000'),
        minting_rules={
            'initial_mint': '2200000',  # Ensure consistency with your previous setup
            'block_reward_multiplier': '1.1'
        }
    )

    # Initialize Mempool
    mempool = Mempool(
        crypto_utils=crypto_utils,
        fee_calculator=fee_calculator,
        max_size=10000,  # Corrected from max_mempool_size
        min_size=500,    # Optionally set other parameters if needed
        adjustment_interval=60,
        high_activity_threshold=100,
        low_activity_threshold=10,
        stale_time=3600
    )

    # Initialize Ledger **after** AccountManager
    ledger = Ledger(
        account_manager=account_manager,
        omc=omc,
        fee_calculator=fee_calculator,
        consensus_engine=None,  # To be set after ConsensusEngine is initialized
        mempool=mempool,
        mongo_client=mongo_client,
        auto_mine_interval=1
    )

    # Initialize Verifier
    verifier = Verifier(ledger=ledger)
    ledger.verifier = verifier  # Assign verifier to ledger

    # Initialize ConsensusEngine with references to AccountManager, OMC, and VRFUtils
    vrf_utils = VRFUtils(private_key_pem=TREASURY_PRIVATE_KEY)  # Ensure VRFUtils is correctly initialized
    consensus_engine = ConsensusEngine(
        ledger=ledger,
        omc=omc,
        account_manager=account_manager,
        vrf_utils=vrf_utils,
        blockchain=ledger,  # Pass ledger as the blockchain reference
        randao_commit_duration=60,    # seconds
        randao_reveal_duration=60,    # seconds
        poef_task_difficulty=4,        # leading zeros
        poef_task_iterations=100000,   # maximum nonce attempts
        poef_adjustment_interval=100,  # blocks
        num_leaders=3                   # number of leaders per round
    )

    # Assign ConsensusEngine to Mempool
    mempool.set_consensus_engine(consensus_engine)

    # Assign Ledger to Mempool
    mempool.set_ledger(ledger)

    # Initialize PermissionManager (ensure it's correctly imported and used)
    permission_manager = PermissionManager()

    # Initialize NetworkManager for Validator Node
    network_manager = NetworkManager(
        ledger=ledger,
        mempool=mempool,
        class_integrity_verifier=ClassIntegrityVerifier(),
        fee_calculator=fee_calculator,
        port=int(os.getenv("PORT_NUMBER", "3400")),
        omc=omc
    )

    # Assign ConsensusEngine to NetworkManager
    network_manager.set_consensus_engine(consensus_engine)

    # Assign NetworkManager to ConsensusEngine
    consensus_engine.set_network_manager(network_manager)

    # Initialize SmartContracts with Ledger, ConsensusEngine, CryptoUtils, and Mempool as the transaction service
    smart_contracts = SmartContracts(
        ledger=ledger,
        consensus_engine=consensus_engine,  # If needed
        crypto_utils=crypto_utils,
        transaction_service=mempool
    )
    ledger.smart_contracts = smart_contracts  # Assign smart contracts to ledger

    # Determine node role
    node_role = os.getenv("NODE_ROLE", "validator_initial")  # Set to 'validator_initial' for the first validator

    if node_role == "validator_initial":
        # Initial validator node should skip class integrity verification
        logger.info("Initial validator node skipping class integrity verification.")
    elif node_role == "validator":
        # Subsequent validator nodes perform class integrity verification
        logger.info("Validator node performing class integrity verification.")
        try:
            # Example: Fetch and verify class hashes from trusted source
            known_hashes_url = os.getenv("HASH_API_URL", "http://trusted-source.omne.io/class-hashes.json")  # Adjust as needed
            response = requests.get(known_hashes_url, timeout=10)
            response.raise_for_status()
            known_hashes = response.json()

            # Perform verification
            if not ClassIntegrityVerifier.verify_class_integrity():
                logger.critical("Class integrity verification failed. Exiting.")
                sys.exit(1)
            else:
                logger.info("Class integrity verification succeeded.")
        except requests.exceptions.RequestException as e:
            logger.error(f"Error fetching known hashes: {e}")
            logger.critical("No known hashes available for verification. Exiting.")
            sys.exit(1)
    else:
        logger.warning(f"Unknown NODE_ROLE: {node_role}. Proceeding without specific configurations.")

    # Start the NetworkManager's Flask server in a separate thread
    server_thread = threading.Thread(target=network_manager.start_server, daemon=True)
    server_thread.start()
    logger.info(f"NetworkManager Flask server started on port {network_manager.port}.")

    # Invoke NetworkManager's initialize_node method for service discovery
    network_manager.initialize_node()

    # Start the ConsensusEngine's consensus routine in a separate thread
    consensus_thread = threading.Thread(target=consensus_engine.start_consensus_routine, daemon=True)
    consensus_thread.start()
    logger.info("ConsensusEngine consensus routine started.")

    # Define signal handlers for graceful shutdown
    def signal_handler(sig, frame):
        logger.info("Received termination signal. Shutting down gracefully...")
        ledger.shutdown()
        network_manager.shutdown()
        consensus_engine.shutdown()
        sys.exit(0)

    import signal
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)

    # Keep the main thread alive to allow background threads to run
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        logger.info("Shutting down Omne Node NetworkManager.")
        ledger.shutdown()
        network_manager.shutdown()

# ----------------------------------------------------------------
#  HELPER FUNCTION TO READ SECRETS
# ----------------------------------------------------------------

def read_secret(secret_name: str) -> str:
    """
    Reads a secret from the /run/secrets directory.

    :param secret_name: The name of the secret file
    :return: The secret content as a string
    """
    secret_path = f'/run/secrets/{secret_name}'
    try:
        with open(secret_path, 'r') as secret_file:
            secret = secret_file.read().strip()
            logging.info(f"Successfully read secret: {secret_name}")
            return secret
    except FileNotFoundError:
        logging.error(f"Secret {secret_name} not found at {secret_path}. Ensure it is correctly mounted.")
        sys.exit(1)
    except Exception as e:
        logging.error(f"Error reading secret {secret_name}: {e}")
        sys.exit(1)

# ----------------------------------------------------------------
#  RUN MAIN APPLICATION
# ----------------------------------------------------------------

if __name__ == "__main__":
    main()
