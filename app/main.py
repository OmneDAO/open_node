# main.py

import logging
import os
import threading
import time
from decimal import Decimal
import signal
import sys

from block import Block
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
from vrf_utils import VRFUtils  # Import VRFUtils

from dotenv import load_dotenv, set_key  # Import dotenv functions
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization

from generate_pem_key import generate_pem_private_key

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
#  LOGGING SETUP
# ----------------------------------------------------------------

def setup_logging():
    logging.basicConfig(
        level=logging.INFO,  # Set to INFO for general logs; DEBUG can be used during development
        format='[%(asctime)s] [%(levelname)s] [%(name)s] %(message)s',
        handlers=[
            logging.StreamHandler()
        ]
    )

# ----------------------------------------------------------------
#  KEY GENERATION FUNCTIONS
# ----------------------------------------------------------------

def generate_ec_key_pair() -> (str, str):
    """
    Generates a new EC key pair and returns the private and public keys in PEM format.

    :return: Tuple containing (private_key_pem, public_key_pem)
    """
    try:
        # Generate EC private key using SECP256K1 curve
        private_key = ec.generate_private_key(ec.SECP256K1())
        public_key = private_key.public_key()

        # Serialize private key to PEM
        private_pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        ).decode()

        # Serialize public key to PEM
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
    """
    Generates a new VRF key pair and returns the private and public keys in PEM format.

    :return: Tuple containing (vrf_private_key_pem, vrf_public_key_pem)
    """
    try:
        # Generate EC private key for VRF using SECP256K1 curve
        vrf_private_key = ec.generate_private_key(ec.SECP256K1())
        vrf_public_key = vrf_private_key.public_key()

        # Serialize VRF private key to PEM
        vrf_private_pem = vrf_private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        ).decode()

        # Serialize VRF public key to PEM
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
#  ENVIRONMENT KEYS ENSURANCE
# ----------------------------------------------------------------

def ensure_keys_in_env(env_path: str) -> (str, str):
    """
    Ensures that VALIDATOR_PRIVATE_KEY and VALIDATOR_VRF_PRIVATE_KEY exist in the .env file.
    If not, generates new keys and saves them to the .env file.

    :param env_path: Path to the .env file.
    :return: Tuple containing (validator_private_key, validator_vrf_private_key)
    """
    try:
        # Load existing .env variables
        load_dotenv(dotenv_path=env_path)

        # Check for VALIDATOR_PRIVATE_KEY
        validator_private_key = os.getenv("VALIDATOR_PRIVATE_KEY")
        if not validator_private_key:
            logging.info("VALIDATOR_PRIVATE_KEY not found in .env. Generating new key.")
            validator_private_key, validator_public_key = generate_ec_key_pair()
            set_key(env_path, "VALIDATOR_PRIVATE_KEY", validator_private_key)
            set_key(env_path, "VALIDATOR_PUBLIC_KEY", validator_public_key)
            logging.info("VALIDATOR_PRIVATE_KEY and VALIDATOR_PUBLIC_KEY have been set in .env.")

        # Check for VALIDATOR_VRF_PRIVATE_KEY
        validator_vrf_private_key = os.getenv("VALIDATOR_VRF_PRIVATE_KEY")
        if not validator_vrf_private_key:
            logging.info("VALIDATOR_VRF_PRIVATE_KEY not found in .env. Generating new VRF key.")
            validator_vrf_private_key, validator_vrf_public_key = generate_vrf_key_pair()
            set_key(env_path, "VALIDATOR_VRF_PRIVATE_KEY", validator_vrf_private_key)
            set_key(env_path, "VALIDATOR_VRF_PUBLIC_KEY", validator_vrf_public_key)
            logging.info("VALIDATOR_VRF_PRIVATE_KEY and VALIDATOR_VRF_PUBLIC_KEY have been set in .env.")

        return validator_private_key, validator_vrf_private_key

    except Exception as e:
        logging.critical(f"Failed to ensure keys in .env: {e}")
        sys.exit(1)

# ----------------------------------------------------------------
#  MAIN FUNCTION
# ----------------------------------------------------------------

def main():
    # Setup logging
    setup_logging()
    logger = logging.getLogger('Main')
    logger.info("Starting Omne Validator Node...")

    # Load .env file from the current directory
    env_path = os.path.join(os.path.dirname(__file__), '.env')
    if not os.path.exists(env_path):
        # Create an empty .env file if it doesn't exist
        open(env_path, 'a').close()
        logger.info(f"Created new .env file at {env_path}.")

    # Ensure that VALIDATOR_PRIVATE_KEY and VALIDATOR_VRF_PRIVATE_KEY exist in .env
    VALIDATOR_PRIVATE_KEY, VALIDATOR_VRF_PRIVATE_KEY = ensure_keys_in_env(env_path)

    # Read STEWARD_ADDRESS from environment variables
    STEWARD_ADDRESS = os.getenv("STEWARD_ADDRESS")
    if not STEWARD_ADDRESS:
        logger.error("STEWARD_ADDRESS environment variable not set.")
        sys.exit(1)
    else:
        logger.info(f"Steward Address: {STEWARD_ADDRESS}")

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

    # Initialize AccountManager
    account_manager = AccountManager()

    # Initialize OMC (Omne Coin) with the steward address
    omc = OMC(
        account_manager=account_manager,
        steward_address=STEWARD_ADDRESS,  # Updated parameter name
        coin_max=Decimal('22000000'),
        minting_rules={
            'initial_mint': '2200000',  # Initial minting
            'block_reward_multiplier': '1.1'
        }
    )

    # Initialize StakedOMC and StakingMngr have been removed as staking is not automatic in open-source mode

    # Initialize Mempool with corrected keyword arguments
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

    # Initialize Ledger with references to AccountManager, OMC, Fee Calculator, Mempool
    ledger = Ledger(
        account_manager=account_manager,
        omc=omc,
        fee_calculator=fee_calculator,
        consensus_engine=None,  # To be set after ConsensusEngine is initialized
        mempool=mempool,
        auto_mine_interval=1
    )

    # Initialize Node
    node = Node(
        address=None,  # Will be generated if not provided
        stake_weight=1,  # Assuming initial stake weight
        url=None,  # Will be set dynamically from environment variables
        version="0.0.1",
        private_key=VALIDATOR_PRIVATE_KEY,  # Provided via .env
        public_key=crypto_utils.get_public_key_pem(VALIDATOR_PRIVATE_KEY),   # Derived from private key
        signature=None,
        steward=STEWARD_ADDRESS  # Directly use steward address from env
    )
    ledger.node = node  # Assign node to ledger

    # Initialize Verifier
    verifier = Verifier(ledger=ledger)
    ledger.verifier = verifier  # Assign verifier to ledger
    
    staking_manager = ledger.staking_manager
    
    # Initialize VRFUtils with the validator's VRF private key
    vrf_utils = VRFUtils(private_key_pem=VALIDATOR_VRF_PRIVATE_KEY)

    # Initialize ConsensusEngine with references to Ledger, OMC, AccountManager, and VRFUtils
    consensus_engine = ConsensusEngine(
        ledger=ledger,
        omc=omc,
        account_manager=account_manager,
        vrf_utils=vrf_utils,
        blockchain=ledger,  # Pass ledger as the blockchain reference
        staking_manager=None,  # No staking manager in open-source mode
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

    # Assign ConsensusEngine to Ledger
    ledger.consensus_engine = consensus_engine  # Link back to Ledger

    # Initialize NetworkManager for Validator Node
    network_manager = NetworkManager(
        ledger=ledger,
        mempool=mempool,
        fee_calculator=fee_calculator,
        port=int(os.getenv("PORT_NUMBER", "3400")),
        omc=omc
    )

    # Assign NetworkManager to ConsensusEngine using the setter method
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
    node_role = os.getenv("NODE_ROLE", "validator")  # Default to 'validator'

    if node_role == "validator_initial":
        # Initial validator node can skip class integrity verification
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
            if not Verifier.verify_class_integrity(known_hashes):
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

    # Initialize and start SmartContracts (if needed)
    # smart_contracts.initialize()  # Uncomment if SmartContracts require initialization

    # Define signal handlers for graceful shutdown
    def signal_handler(sig, frame):
        logger.info("Received termination signal. Shutting down gracefully...")
        ledger.shutdown()
        consensus_engine.shutdown()
        network_manager.shutdown()
        sys.exit(0)

    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)

    # Keep the main thread alive to allow background threads to run
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        logger.info("Shutting down Omne Validator Node.")
        ledger.shutdown()
        consensus_engine.shutdown()
        network_manager.shutdown()

if __name__ == "__main__":
    main()
