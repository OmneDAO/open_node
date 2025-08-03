import logging
import json
import secrets
import hashlib
from datetime import datetime, timezone, timedelta
from cryptography.fernet import Fernet
from decimal import Decimal, InvalidOperation
from typing import Dict, Optional, List, Tuple, Any
import os
import uuid
import time
import asyncio
import threading

from merkle import MerkleTree
from utils import QuantumUtils
from verifier import Verifier
from permissions import PermissionManager
from omc import OMC
from staked_omc import StakedOMC
from mempool import Mempool
from account_manager import AccountManager
from dynamic_fee_calculator import DynamicFeeCalculator
from class_integrity_verifier import ClassIntegrityVerifier
from crypto_utils import CryptoUtils, DecimalEncoder
from ledger import Ledger
from smart_contracts import SmartContracts
from block import Block

from verification.transaction_verifier import TransactionVerifier
from services.transaction_data import TransactionDataService
from network_manager import NetworkManager
from consensus_engine import ConsensusEngine
from transaction_queue import TransactionQueue
from staking import StakingMngr
from vrf_utils import VRFUtils
from alpha_generator import AlphaGenerator
from network_verifier import NetworkVerifier
from node import Node
from secrets_utils import get_secret
from storage_backend import StorageBackend
from key_management import KeyManager
from canonicalization import canonicalize_transaction
from generate_pem_key import generate_pem_private_key

# Configuration and error handling systems
from config_manager import ConfigManager
from error_handling import (
    ErrorHandler, Validator, ConfigurationError, StorageError,
    ErrorSeverity, with_error_handling, with_retry
)
from performance_monitor import PerformanceMonitor, time_operation, timed_operation
from storage_abstraction import StorageManager

class ValidatorInitializer:
    """
    Validator Node Initializer - Initializes validator nodes that join existing networks
    Excludes genesis functionality which is reserved for the genesis node
    """
    
    def __init__(self, ledger, account_manager, node_address, node_public_key, node_private_key):
        """
        Initialize validator node components (non-genesis)
        
        Args:
            ledger: Shared ledger instance
            account_manager: Shared account manager
            node_address: This validator's wallet address
            node_public_key: This validator's public key
            node_private_key: This validator's private key
        """
        # Error handling and configuration
        self.error_handler = ErrorHandler()
        self.config_manager = ConfigManager()
        self.validator = Validator()
        self.performance_monitor = PerformanceMonitor()
        
        # Storage initialization
        try:
            self.storage_manager = StorageManager(self.config_manager)
        except Exception as e:
            raise ConfigurationError(
                f"Failed to initialize storage: {e}",
                severity=ErrorSeverity.CRITICAL
            )
        
        # Core components
        self.ledger = ledger
        self.node_address = node_address.strip().lower()
        self.node_public_key = node_public_key
        self.node_private_key = node_private_key
        self.account_manager = account_manager  # Shared instance
        
        # Security
        self.encryption_key = Fernet.generate_key()
        self.fernet = Fernet(self.encryption_key)
        
        # Business logic components
        self.fee_calculator = DynamicFeeCalculator()
        self.crypto_utils = CryptoUtils()

        # Validate node address
        if not self.validator.validate_address(self.node_address):
            raise ConfigurationError(
                f"Invalid node address format: {self.node_address}",
                severity=ErrorSeverity.HIGH
            )

        # 1) Ensure the validator account exists
        self._ensure_validator_account()

        # 2) Initialize StakedOMC for validator staking
        try:
            self.staked_omc = StakedOMC(
                account_manager=self.account_manager,
                decimals=self.config_manager.get('decimals', 18)
            )
        except Exception as e:
            raise ConfigurationError(
                f"Failed to initialize StakedOMC: {e}",
                severity=ErrorSeverity.CRITICAL
            )

        # 3) Validator Initialization (connects to existing network)
        self._initialize_validator_safely()

        # 4) Register classes for integrity verification
        self._register_classes_for_verification()

        logging.info("Validator initialization completed successfully")

    def _register_classes_for_verification(self):
        """Register core classes for network integrity verification"""
        try:
            # Define the same classes as in the genesis node
            classes_to_hash = {
                'object_registry': self.object_registry.__class__,
                'coin': OMC,
                'quantum_utils': QuantumUtils,
                'verifier': Verifier,
                'permissions_manager': PermissionManager,
                'fee_calculator': DynamicFeeCalculator,
                'ledger': self.ledger.__class__,
                'mempool': Mempool,
                'smart_contracts': SmartContracts,
                'class_integrity_verifier': ClassIntegrityVerifier,
                'crypto_utils': CryptoUtils,
                'consensus_engine': ConsensusEngine,
                'account_manager': AccountManager,
                'transaction_verifier': TransactionVerifier,
                'network_manager': NetworkManager
            }
            
            # Set classes for verification
            ClassIntegrityVerifier.set_classes_to_verify(classes_to_hash)
            
            logging.info("Classes registered for integrity verification")
            
        except Exception as e:
            logging.error(f"Failed to register classes for verification: {e}")
            # Don't raise - this shouldn't block validator startup

    @with_retry(max_attempts=3, delay=1.0)
    def _initialize_validator_safely(self):
        """Initialize validator to join existing network"""
        try:
            result = self.initialize_validator()
            if not result:
                raise ConfigurationError(
                    "Validator initialization returned None or False",
                    severity=ErrorSeverity.CRITICAL
                )
                
        except Exception as e:
            self.error_handler.handle_error(e, context={'operation': 'validator_initialization'})
            raise

    @with_error_handling(reraise=True)
    @timed_operation("validator_initialization")
    def initialize_validator(self):
        """Initialize validator node to join existing network"""
        with time_operation("validator_initialization_total"):
            try:
                logging.info(f"Initializing validator with address: {self.node_address}")

                # Ensure validator account exists and is properly configured
                self._ensure_validator_account()

                logging.info(f"Validator Address: {self.node_address}")
                logging.info(f"Validator Public Key: {self.node_public_key}")

                # Set validator address on components
                if self.ledger.node:
                    self.ledger.node.validator_address = self.node_address

                # Connect to existing network and sync
                network_config = self.config_manager.get_network_config()
                self._connect_to_network(network_config)
                
                # Initialize validator-specific components
                self._initialize_validator_components()
                
                # Sync with network state
                self._sync_with_network()

                logging.info("Validator initialization completed successfully")
                return True

            except Exception as e:
                logging.error(f"Validator initialization failed: {e}")
                self.error_handler.handle_error(
                    e, 
                    context={'operation': 'validator_initialization', 'validator_address': self.node_address}
                )
                raise

    def _ensure_validator_account(self):
        """Ensure validator account exists with proper configuration"""
        try:
            if not self.account_manager.account_exists(self.node_address):
                # Create validator account
                account_data = {
                    'address': self.node_address,
                    'public_key': self.node_public_key,
                    'balance': Decimal('0'),
                    'nonce': 0,
                    'type': 'validator',
                    'created_at': datetime.now(timezone.utc).isoformat()
                }
                
                self.account_manager.create_account(
                    self.node_address,
                    self.node_public_key,
                    account_data
                )
                
                logging.info(f"Created validator account: {self.node_address}")
            else:
                logging.info(f"Validator account already exists: {self.node_address}")
                
        except Exception as e:
            raise ConfigurationError(
                f"Failed to ensure validator account: {e}",
                severity=ErrorSeverity.HIGH
            )

    def _connect_to_network(self, network_config):
        """Connect validator to existing OMNE network"""
        try:
            # Initialize network manager for validator
            self.network_manager = NetworkManager(
                node_address=self.node_address,
                config=network_config
            )
            
            # Connect to bootstrap nodes
            bootstrap_nodes = network_config.get('bootstrap_nodes', [])
            for node in bootstrap_nodes:
                try:
                    self.network_manager.connect_to_peer(node)
                    logging.info(f"Connected to bootstrap node: {node}")
                except Exception as e:
                    logging.warning(f"Failed to connect to bootstrap node {node}: {e}")
            
            # Discover additional peers
            self.network_manager.discover_peers()
            
        except Exception as e:
            raise ConfigurationError(
                f"Failed to connect to network: {e}",
                severity=ErrorSeverity.HIGH
            )

    def _initialize_validator_components(self):
        """Initialize validator-specific components"""
        try:
            # Transaction queue for validator operations
            self.transaction_queue = TransactionQueue()
            
            # Consensus engine for validation
            self.consensus_engine = ConsensusEngine(
                validator_address=self.node_address,
                staking_manager=self.ledger.staking_manager
            )
            
            # Network verifier
            self.network_verifier = NetworkVerifier()
            
            # Transaction verifier
            self.transaction_verifier = TransactionVerifier()
            
            logging.info("Validator components initialized successfully")
            
        except Exception as e:
            raise ConfigurationError(
                f"Failed to initialize validator components: {e}",
                severity=ErrorSeverity.HIGH
            )

    def _sync_with_network(self):
        """Sync validator with current network state"""
        try:
            # Request blockchain state from peers
            current_height = self.ledger.get_chain_height()
            network_height = self.network_manager.get_network_height()
            
            if network_height > current_height:
                logging.info(f"Syncing blockchain: local={current_height}, network={network_height}")
                
                # Sync missing blocks
                missing_blocks = self.network_manager.request_blocks(
                    start_height=current_height + 1,
                    end_height=network_height
                )
                
                for block in missing_blocks:
                    if self.ledger.verify_and_add_block(block):
                        logging.info(f"Synced block {block.height}")
                    else:
                        raise ConfigurationError(f"Failed to verify block {block.height}")
                
                logging.info("Blockchain sync completed")
            else:
                logging.info("Blockchain is up to date")
                
        except Exception as e:
            raise ConfigurationError(
                f"Failed to sync with network: {e}",
                severity=ErrorSeverity.HIGH
            )

    def get_validator_address(self):
        """Get validator address"""
        return self.node_address

    def get_validator_public_key(self):
        """Get validator public key"""
        return self.node_public_key

    def is_validator_ready(self):
        """Check if validator is ready to participate in consensus"""
        try:
            # Check if validator account exists
            if not self.account_manager.account_exists(self.node_address):
                return False
            
            # Check if connected to network
            if not hasattr(self, 'network_manager') or not self.network_manager.is_connected():
                return False
            
            # Check if blockchain is synced
            if not self.ledger.is_synced():
                return False
            
            return True
            
        except Exception as e:
            logging.error(f"Error checking validator readiness: {e}")
            return False
