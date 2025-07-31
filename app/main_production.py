#!/usr/bin/env python3
"""
main.py – Production-Ready Open‑Source Omne Node Entry Point
Features comprehensive infrastructure including:
- Centralized configuration management
- Robust error handling and validation
- Pluggable storage abstraction
- Performance monitoring and health checks
- Advanced security with key management
- Complete operational monitoring

This node participates in consensus, block validation, and staking agreements
but does not create the genesis block or treasury.
"""

import logging
import os
import threading
import time
import signal
import sys
from decimal import Decimal

# Production infrastructure components
from config_manager import OpenNodeConfigManager
from error_handling import ErrorHandler, with_error_handling, retry_on_error, OpenNodeError
from storage_abstraction import StorageManager, BlockStorage, TransactionStorage
from performance_monitor import PerformanceMonitor
from advanced_security import SecurityManager

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
# GLOBAL INFRASTRUCTURE COMPONENTS
# ----------------------------------------------------------------

config_manager = None
error_handler = None
performance_monitor = None
security_manager = None
storage_manager = None
logger = None

# ----------------------------------------------------------------
# INFRASTRUCTURE INITIALIZATION
# ----------------------------------------------------------------

def setup_basic_logging():
    """Setup basic logging before config manager takes over"""
    logging.basicConfig(
        level=logging.INFO,
        format='[%(asctime)s] [%(levelname)s] [%(name)s] %(message)s',
        handlers=[logging.StreamHandler()]
    )

def initialize_infrastructure():
    """Initialize all production infrastructure components"""
    global config_manager, error_handler, performance_monitor, security_manager, storage_manager, logger
    
    logger = logging.getLogger('Infrastructure')
    
    try:
        logger.info("🚀 Initializing Open Omne Node Infrastructure...")
        
        # Initialize configuration management
        config_manager = OpenNodeConfigManager()
        logger.info(f"✅ Configuration initialized for steward: {config_manager.config.steward_address}")
        
        # Initialize error handling
        error_handler = ErrorHandler()
        logger.info("✅ Error handling system initialized")
        
        # Initialize storage management
        storage_manager = StorageManager(
            backend_type=config_manager.config.storage_backend,
            data_directory=config_manager.config.data_directory
        )
        storage_manager.initialize()
        logger.info(f"✅ Storage system initialized: {config_manager.config.storage_backend}")
        
        # Initialize performance monitoring
        performance_monitor = PerformanceMonitor(collection_interval=60)
        performance_monitor.start_monitoring()
        logger.info("✅ Performance monitoring started")
        
        # Initialize security management
        security_data_dir = os.path.join(config_manager.config.data_directory, "security")
        security_manager = SecurityManager(security_data_dir)
        security_manager.initialize()
        logger.info("✅ Security management initialized")
        
        # Log system readiness status
        if config_manager.is_production_ready():
            logger.info("🌟 Node is PRODUCTION READY")
        else:
            logger.warning("⚠️  Node is in DEVELOPMENT mode")
        
        # Log configuration summary
        summary = config_manager.get_summary()
        logger.info(f"📊 Node Configuration Summary:")
        logger.info(f"   • Network Port: {summary['network_port']}")
        logger.info(f"   • Storage Backend: {summary['storage_backend']}")
        logger.info(f"   • Data Directory: {summary['data_directory']}")
        logger.info(f"   • Node Role: {summary['node_role']}")
        
        return True
        
    except Exception as e:
        logger.critical(f"❌ Failed to initialize infrastructure: {e}")
        if error_handler:
            error_handler.handle_error(e, {'component': 'infrastructure_init'})
        sys.exit(1)

@with_error_handling(reraise=True)
def read_secret(secret_name: str) -> str:
    """Reads a secret from the /run/secrets directory."""
    secret_path = f'/run/secrets/{secret_name}'
    try:
        with open(secret_path, 'r') as secret_file:
            secret = secret_file.read().strip()
            logger.info(f"Successfully read secret: {secret_name}")
            return secret
    except FileNotFoundError:
        logger.error(f"Secret {secret_name} not found at {secret_path}.")
        sys.exit(1)
    except Exception as e:
        logger.error(f"Error reading secret {secret_name}: {e}")
        sys.exit(1)

@retry_on_error(max_retries=3, delay=1.0)
def ensure_keys_in_env(env_path: str) -> tuple:
    """
    Ensures that validator keys exist in the .env file.
    Uses advanced security manager for key generation if available.
    """
    try:
        load_dotenv(dotenv_path=env_path)
        validator_private_key = os.getenv("VALIDATOR_PRIVATE_KEY")
        
        if not validator_private_key:
            logger.info("Generating new validator keys...")
            if security_manager:
                # Use security manager for key generation
                private_key, public_key = security_manager.key_manager.generate_ec_key_pair('validator')
            else:
                # Fallback to basic key generation
                private_key, public_key = generate_ec_key_pair()
            
            set_key(env_path, "VALIDATOR_PRIVATE_KEY", private_key)
            set_key(env_path, "VALIDATOR_PUBLIC_KEY", public_key)
            validator_private_key = private_key
            logger.info("✅ Validator keys generated and stored")
        
        validator_vrf_private_key = os.getenv("VALIDATOR_VRF_PRIVATE_KEY")
        if not validator_vrf_private_key:
            logger.info("Generating new VRF keys...")
            if security_manager:
                # Use security manager for VRF key generation
                vrf_private_key, vrf_public_key = security_manager.key_manager.generate_ec_key_pair('validator_vrf')
            else:
                # Fallback to basic VRF key generation
                vrf_private_key, vrf_public_key = generate_vrf_key_pair()
            
            set_key(env_path, "VALIDATOR_VRF_PRIVATE_KEY", vrf_private_key)
            set_key(env_path, "VALIDATOR_VRF_PUBLIC_KEY", vrf_public_key)
            validator_vrf_private_key = vrf_private_key
            logger.info("✅ VRF keys generated and stored")
        
        return validator_private_key, validator_vrf_private_key
        
    except Exception as e:
        logger.critical(f"Failed to ensure keys in .env: {e}")
        if error_handler:
            error_handler.handle_error(e, {'component': 'key_management'})
        sys.exit(1)

@with_error_handling(reraise=True)
def generate_ec_key_pair() -> tuple:
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
        
        return private_pem, public_pem
        
    except Exception as e:
        logger.critical(f"Failed to generate EC key pair: {e}")
        sys.exit(1)

@with_error_handling(reraise=True)
def generate_vrf_key_pair() -> tuple:
    """Generates a new VRF key pair."""
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
        
        return vrf_private_pem, vrf_public_pem
        
    except Exception as e:
        logger.critical(f"Failed to generate VRF key pair: {e}")
        sys.exit(1)

# ----------------------------------------------------------------
# MAIN FUNCTION – PRODUCTION-READY OPEN SOURCE NODE
# ----------------------------------------------------------------

def main():
    """Main entry point for the production-ready Open Omne Node"""
    global logger
    
    # Setup basic logging first
    setup_basic_logging()
    logger = logging.getLogger('Main')
    
    logger.info("🌟 Starting Production-Ready Open‑Source Omne Node...")
    
    try:
        # Initialize all infrastructure components
        initialize_infrastructure()
        
        # Track node startup performance
        with performance_monitor.time_operation('node_startup'):
            
            # Load environment variables from .env file
            env_path = os.path.join(os.path.dirname(__file__), '.env')
            if not os.path.exists(env_path):
                open(env_path, 'a').close()
                logger.info(f"Created new .env file at {env_path}")
            
            # Ensure validator keys exist
            VALIDATOR_PRIVATE_KEY, VALIDATOR_VRF_PRIVATE_KEY = ensure_keys_in_env(env_path)
            
            # Get steward address from configuration
            STEWARD_ADDRESS = config_manager.config.steward_address
            logger.info(f"🏛️  Node steward address: {STEWARD_ADDRESS}")
            
            # Initialize core blockchain components
            logger.info("🔧 Initializing blockchain components...")
            
            # Initialize CryptoUtils
            crypto_utils = CryptoUtils()
            performance_monitor.record_response_time(0.001)  # Quick init
            
            # Initialize DynamicFeeCalculator with config values
            fee_calculator = DynamicFeeCalculator(
                base_fee=config_manager.config.base_fee,
                fee_multiplier=config_manager.config.fee_multiplier,
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
            
            # Initialize AccountManager
            account_manager = AccountManager()
            
            # Initialize OMC (no treasury for open nodes)
            omc = OMC(
                account_manager=account_manager,
                treasury_address="",  # Treasury determined by network
                coin_max=config_manager.config.initial_supply,
                minting_rules={}
            )
            
            # Initialize Mempool with monitoring
            mempool = Mempool(
                crypto_utils=crypto_utils,
                fee_calculator=fee_calculator,
                max_size=config_manager.config.max_transaction_pool_size,
                min_size=500,
                adjustment_interval=60,
                high_activity_threshold=100,
                low_activity_threshold=10,
                stale_time=config_manager.config.transaction_timeout
            )
            
            # Initialize Ledger with storage backend
            ledger = Ledger(
                account_manager=account_manager,
                omc=omc,
                fee_calculator=fee_calculator,
                consensus_engine=None,
                mempool=mempool,
                mongo_client=None,  # Using our storage abstraction instead
                auto_mine_interval=1
            )
            
            # Initialize Node with proper configuration
            node = Node(
                address=None,
                stake_weight=1,
                url=f"http://{config_manager.config.network_host}:{config_manager.config.network_port}",
                version="1.0.0",
                private_key=VALIDATOR_PRIVATE_KEY,
                public_key=crypto_utils.get_public_key_pem(VALIDATOR_PRIVATE_KEY),
                signature=None,
                steward=STEWARD_ADDRESS
            )
            ledger.node = node
            
            # Initialize Verifier
            verifier = Verifier(ledger=ledger)
            ledger.verifier = verifier
            
            # Set up staking manager
            staking_manager = ledger.staking_manager
            omc.set_staking_manager(staking_manager)
            
            # Initialize VRFUtils
            vrf_utils = VRFUtils(private_key_pem=VALIDATOR_VRF_PRIVATE_KEY)
            
            # Initialize ConsensusEngine with configuration
            consensus_engine = ConsensusEngine(
                ledger=ledger,
                omc=omc,
                account_manager=account_manager,
                staking_manager=staking_manager,
                vrf_utils=vrf_utils,
                blockchain=ledger,
                randao_commit_duration=config_manager.config.randao_commit_duration,
                randao_reveal_duration=config_manager.config.randao_reveal_duration,
                poef_task_difficulty=config_manager.config.poef_task_difficulty,
                poef_task_iterations=100000,
                poef_adjustment_interval=100,
                num_leaders=3
            )
            
            # Wire up the components
            mempool.set_consensus_engine(consensus_engine)
            mempool.set_ledger(ledger)
            ledger.consensus_engine = consensus_engine
            
            # Initialize NetworkManager with configuration
            network_manager = NetworkManager(
                ledger=ledger,
                mempool=mempool,
                class_integrity_verifier=ClassIntegrityVerifier(),
                fee_calculator=fee_calculator,
                port=config_manager.config.network_port,
                omc=omc,
                account_manager=account_manager
            )
            consensus_engine.set_network_manager(network_manager)
            
            # Initialize SmartContracts
            smart_contracts = SmartContracts(
                ledger=ledger,
                consensus_engine=consensus_engine,
                crypto_utils=crypto_utils,
                transaction_service=mempool
            )
            ledger.smart_contracts = smart_contracts
            
            logger.info("✅ Core blockchain components initialized")
            
            # Perform node role verification
            node_role = config_manager.config.node_role
            if node_role == "validator":
                logger.info("🔍 Performing validator node verification...")
                try:
                    known_hashes_url = os.getenv("HASH_API_URL", "http://trusted-source.omne.io/class-hashes.json")
                    response = requests.get(known_hashes_url, timeout=10)
                    response.raise_for_status()
                    
                    if not ClassIntegrityVerifier.verify_class_integrity():
                        logger.critical("❌ Class integrity verification failed")
                        sys.exit(1)
                    else:
                        logger.info("✅ Class integrity verification passed")
                        
                except requests.exceptions.RequestException as e:
                    logger.warning(f"⚠️  Could not fetch class hashes: {e}")
                    logger.info("Proceeding without external verification")
            else:
                logger.info(f"Node role: {node_role}")
            
            # Start services
            logger.info("🚀 Starting node services...")
            
            # Start NetworkManager Flask server
            server_thread = threading.Thread(target=network_manager.start_server, daemon=True)
            server_thread.start()
            logger.info(f"✅ Network server started on port {network_manager.port}")
            
            # Initialize network connections
            network_manager.initialize_node()
            
            # Start ConsensusEngine
            consensus_thread = threading.Thread(target=consensus_engine.start_consensus_routine, daemon=True)
            consensus_thread.start()
            logger.info("✅ Consensus engine started")
            
            # Record successful startup
            performance_monitor.record_consensus_round()
            
            logger.info("🌟 Open‑Source Omne Node fully operational!")
            logger.info(f"📊 Monitoring dashboard available at http://localhost:{config_manager.config.network_port}/api/health")
            
            # Setup graceful shutdown
            def signal_handler(sig, frame):
                logger.info("🛑 Received shutdown signal. Gracefully shutting down...")
                
                # Stop infrastructure components
                if performance_monitor:
                    performance_monitor.stop_monitoring()
                
                # Stop blockchain components
                if 'ledger' in locals():
                    ledger.shutdown()
                if 'consensus_engine' in locals():
                    consensus_engine.shutdown()
                if 'network_manager' in locals():
                    network_manager.shutdown()
                
                logger.info("✅ Graceful shutdown completed")
                sys.exit(0)
            
            signal.signal(signal.SIGINT, signal_handler)
            signal.signal(signal.SIGTERM, signal_handler)
            
            # Main event loop
            try:
                while True:
                    time.sleep(1)
                    
                    # Periodic health checks (every 5 minutes)
                    if int(time.time()) % 300 == 0:
                        health_report = performance_monitor.get_health_report()
                        if not health_report['health_status'].get('overall_healthy', True):
                            logger.warning("⚠️  Health check detected issues")
                        
            except KeyboardInterrupt:
                logger.info("🛑 Keyboard interrupt received. Shutting down...")
            
    except Exception as e:
        logger.critical(f"❌ Fatal error during node startup: {e}")
        if error_handler:
            error_handler.handle_error(e, {'component': 'main_startup'}, reraise=False)
        sys.exit(1)
    
    finally:
        # Cleanup
        logger.info("🧹 Performing final cleanup...")
        try:
            if performance_monitor:
                performance_monitor.stop_monitoring()
            if 'ledger' in locals():
                ledger.shutdown()
            if 'consensus_engine' in locals():
                consensus_engine.shutdown()
            if 'network_manager' in locals():
                network_manager.shutdown()
        except Exception as e:
            logger.error(f"Error during cleanup: {e}")

if __name__ == "__main__":
    main()
