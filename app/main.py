#!/usr/bin/env python3
"""
main.py – Entry point for an open‑source Omne node.
This node does not create the treasury or genesis block; those are determined by the initial node.
The node’s own identity is defined by its steward address provided via an environment variable.
"""

import logging
import os
import threading
import time
import signal
import sys
from decimal import Decimal

# Omne modules
from block import Block
from class_integrity_verifier import ClassIntegrityVerifier
from ledger import Ledger
from mempool import Mempool
from account_manager import AccountManager
from omc import OMC
from consensus_engine import ConsensusEngine
from network_manager import NetworkManager
from smart_contracts import SmartContracts
from dynamic_fee_calculator import DynamicFeeCalculator
from crypto_utils import CryptoUtils
from node import Node
from verifier import Verifier

import requests
from vrf_utils import VRFUtils

from dotenv import load_dotenv, set_key
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization

from generate_pem_key import generate_pem_private_key

# ----------------------------------------------------------------
# HELPER FUNCTIONS
# ----------------------------------------------------------------

def read_secret(secret_name: str) -> str:
    """Reads a secret from the /run/secrets directory."""
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

def setup_logging():
    logging.basicConfig(
        level=logging.DEBUG,  # Adjust as needed for production.
        format='[%(asctime)s] [%(levelname)s] [%(name)s] %(message)s',
        handlers=[logging.StreamHandler()]
    )

def ensure_keys_in_env(env_path: str) -> (str, str):
    """
    Ensures that VALIDATOR_PRIVATE_KEY and VALIDATOR_VRF_PRIVATE_KEY exist in the .env file.
    If not, generates new keys and saves them.
    """
    try:
        load_dotenv(dotenv_path=env_path)
        validator_private_key = os.getenv("VALIDATOR_PRIVATE_KEY")
        if not validator_private_key:
            logging.info("VALIDATOR_PRIVATE_KEY not found in .env. Generating new key.")
            validator_private_key, validator_public_key = generate_ec_key_pair()
            set_key(env_path, "VALIDATOR_PRIVATE_KEY", validator_private_key)
            set_key(env_path, "VALIDATOR_PUBLIC_KEY", validator_public_key)
            logging.info("Validator keys set in .env.")
        validator_vrf_private_key = os.getenv("VALIDATOR_VRF_PRIVATE_KEY")
        if not validator_vrf_private_key:
            logging.info("VALIDATOR_VRF_PRIVATE_KEY not found in .env. Generating new VRF key.")
            validator_vrf_private_key, validator_vrf_public_key = generate_vrf_key_pair()
            set_key(env_path, "VALIDATOR_VRF_PRIVATE_KEY", validator_vrf_private_key)
            set_key(env_path, "VALIDATOR_VRF_PUBLIC_KEY", validator_vrf_public_key)
            logging.info("Validator VRF keys set in .env.")
        return validator_private_key, validator_vrf_private_key
    except Exception as e:
        logging.critical(f"Failed to ensure keys in .env: {e}")
        sys.exit(1)

def generate_ec_key_pair() -> (str, str):
    """Generates a new EC key pair (PEM formatted) using SECP256K1."""
    try:
        private_key = ec.generate_private_key(ec.SECP256K1())
        public_key = private_key.public_key()
        private_pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        ).decode()
        public_pem = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ).decode()
        logging.info("Generated new EC key pair.")
        return private_pem, public_pem
    except Exception as e:
        logging.critical(f"Failed to generate EC key pair: {e}")
        sys.exit(1)

def generate_vrf_key_pair() -> (str, str):
    """Generates a new VRF key pair (PEM formatted) using SECP256K1."""
    try:
        vrf_private_key = ec.generate_private_key(ec.SECP256K1())
        vrf_public_key = vrf_private_key.public_key()
        vrf_private_pem = vrf_private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        ).decode()
        vrf_public_pem = vrf_public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ).decode()
        logging.info("Generated new VRF EC key pair.")
        return vrf_private_pem, vrf_public_pem
    except Exception as e:
        logging.critical(f"Failed to generate VRF EC key pair: {e}")
        sys.exit(1)

# ----------------------------------------------------------------
# MAIN FUNCTION – OPEN SOURCE NODE (No genesis/treasury setup)
# ----------------------------------------------------------------

def main():
    setup_logging()
    logger = logging.getLogger('Main')
    logger.info("Starting Open‑Source Omne Node...")

    # Load environment variables from .env file.
    env_path = os.path.join(os.path.dirname(__file__), '.env')
    if not os.path.exists(env_path):
        open(env_path, 'a').close()
        logger.info(f"Created new .env file at {env_path}.")

    # Ensure validator keys exist.
    VALIDATOR_PRIVATE_KEY, VALIDATOR_VRF_PRIVATE_KEY = ensure_keys_in_env(env_path)

    # For an open‑source node, the steward address is provided via the environment.
    STEWARD_ADDRESS = os.getenv("STEWARD_ADDRESS")
    if not STEWARD_ADDRESS:
        logger.critical("STEWARD_ADDRESS not set. Aborting node startup.")
        sys.exit(1)

    # Initialize CryptoUtils.
    crypto_utils = CryptoUtils()

    # Initialize DynamicFeeCalculator.
    fee_calculator = DynamicFeeCalculator(
        base_fee=Decimal('0.0000000000000001'),
        fee_multiplier=Decimal('0.00000000000001'),
        gas_price_adjustment=Decimal('0.000000000000001'),
        type_fee_adjustments={
            'deploy_contract': Decimal('0.00000000000001'),
            'execute_contract': Decimal('0.000000000000005'),
            'standard_transfer': Decimal('0.0')
        },
        moving_average_window=100,
        max_fee=Decimal('0.0000000000001'),
        min_fee=Decimal('0.00000000000000001')
    )

    # Initialize AccountManager.
    account_manager = AccountManager()

    # Initialize OMC without a local treasury address (treasury is determined by the network).
    omc = OMC(
        account_manager=account_manager,
        treasury_address="",  # Empty string since this node is not the initial node.
        coin_max=Decimal('22000000'),
        minting_rules={}
    )

    # Initialize Mempool.
    mempool = Mempool(
        crypto_utils=crypto_utils,
        fee_calculator=fee_calculator,
        max_size=10000,
        min_size=500,
        adjustment_interval=60,
        high_activity_threshold=100,
        low_activity_threshold=10,
        stale_time=3600
    )

    # Initialize Ledger (no MongoDB persistence needed for open‑source node).
    ledger = Ledger(
        account_manager=account_manager,
        omc=omc,
        fee_calculator=fee_calculator,
        consensus_engine=None,
        mempool=mempool,
        mongo_client=None,
        auto_mine_interval=1
    )

    # Initialize Node with the provided steward address.
    node = Node(
        address=None,
        stake_weight=1,
        url=os.getenv("NODE_URL", "http://localhost:3400"),
        version="0.0.1",
        private_key=VALIDATOR_PRIVATE_KEY,
        public_key=crypto_utils.get_public_key_pem(VALIDATOR_PRIVATE_KEY),
        signature=None,
        steward=STEWARD_ADDRESS
    )
    ledger.node = node

    # Initialize Verifier.
    verifier = Verifier(ledger=ledger)
    ledger.verifier = verifier

    # For open‑source nodes, staking and genesis transactions are not created locally.
    # Instead, the node will join the network and synchronize its blockchain.
    # However, we still need to set up the remaining components.

    # Set up the staking manager (if used) from the ledger.
    staking_manager = ledger.staking_manager
    omc.set_staking_manager(staking_manager)

    # Initialize VRFUtils with the validator's VRF private key.
    vrf_utils = VRFUtils(private_key_pem=VALIDATOR_VRF_PRIVATE_KEY)

    # Initialize ConsensusEngine.
    consensus_engine = ConsensusEngine(
        ledger=ledger,
        omc=omc,
        account_manager=account_manager,
        staking_manager=staking_manager,
        vrf_utils=vrf_utils,
        blockchain=ledger,
        randao_commit_duration=60,
        randao_reveal_duration=60,
        poef_task_difficulty=4,
        poef_task_iterations=100000,
        poef_adjustment_interval=100,
        num_leaders=3
    )

    # Wire up the components.
    mempool.set_consensus_engine(consensus_engine)
    mempool.set_ledger(ledger)
    ledger.consensus_engine = consensus_engine

    network_manager = NetworkManager(
        ledger=ledger,
        mempool=mempool,
        class_integrity_verifier=ClassIntegrityVerifier(),
        fee_calculator=fee_calculator,
        port=int(os.getenv("PORT_NUMBER", "3400")),
        omc=omc,
        account_manager=account_manager
    )
    consensus_engine.set_network_manager(network_manager)

    smart_contracts = SmartContracts(
        ledger=ledger,
        consensus_engine=consensus_engine,
        crypto_utils=crypto_utils,
        transaction_service=mempool
    )
    ledger.smart_contracts = smart_contracts

    # Determine node role.
    node_role = os.getenv("NODE_ROLE", "validator")
    if node_role == "validator":
        logger.info("Validator node performing class integrity verification.")
        try:
            known_hashes_url = os.getenv("HASH_API_URL", "http://trusted-source.omne.io/class-hashes.json")
            response = requests.get(known_hashes_url, timeout=10)
            response.raise_for_status()
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
        logger.info(f"Node role set to '{node_role}'. Proceeding without additional verification.")

    # Start the NetworkManager's Flask server in a separate thread.
    server_thread = threading.Thread(target=network_manager.start_server, daemon=True)
    server_thread.start()
    logger.info(f"NetworkManager Flask server started on port {network_manager.port}.")

    network_manager.initialize_node()

    # Start the ConsensusEngine's consensus routine in a separate thread.
    consensus_thread = threading.Thread(target=consensus_engine.start_consensus_routine, daemon=True)
    consensus_thread.start()
    logger.info("ConsensusEngine consensus routine started.")

    # Signal handlers for graceful shutdown.
    def signal_handler(sig, frame):
        logger.info("Received termination signal. Shutting down gracefully...")
        ledger.shutdown()
        consensus_engine.shutdown()
        network_manager.shutdown()
        sys.exit(0)

    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)

    # Keep the main thread alive.
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        logger.info("Shutting down Open‑Source Omne Node.")
        ledger.shutdown()
        consensus_engine.shutdown()
        network_manager.shutdown()

if __name__ == "__main__":
    main()
