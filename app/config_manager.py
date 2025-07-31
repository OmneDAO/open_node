"""
Configuration Manager for Open Omne Node
Handles all configuration values through environment variables and centralized defaults.
Adapted for open-source node deployment with minimal configuration requirements.
"""

import os
import logging
from decimal import Decimal
from typing import Optional, Dict, Any, Union
from dataclasses import dataclass


@dataclass
class OpenNodeConfig:
    """Configuration settings for the Open Omne Node"""
    
    # Network Configuration
    network_port: int = 3400
    network_host: str = "0.0.0.0"
    network_timeout: int = 30
    max_connections: int = 1000
    
    # Node Identity (Required for open nodes)
    steward_address: Optional[str] = None  # Required - wallet address for rewards
    node_id: Optional[str] = None
    
    # Blockchain Configuration
    initial_supply: Decimal = Decimal('22000000')  # Total OMC supply
    decimals: int = 18
    
    # Storage Configuration
    use_mongodb: bool = False
    mongodb_uri: Optional[str] = None
    storage_backend: str = "file"  # Default to file for open nodes
    data_directory: str = "./data"
    
    # Security Configuration
    enable_ssl: bool = False
    ssl_cert_path: Optional[str] = None
    ssl_key_path: Optional[str] = None
    
    # Performance Configuration
    max_block_size: int = 1_000_000  # 1MB
    max_transaction_pool_size: int = 10_000
    transaction_timeout: int = 3600  # 1 hour
    
    # Logging Configuration
    log_level: str = "INFO"
    log_file: Optional[str] = None
    log_max_size: int = 10_000_000  # 10MB
    log_backup_count: int = 5
    
    # Development Configuration
    debug_mode: bool = False
    test_mode: bool = False
    
    # Consensus Configuration
    consensus_timeout: int = 30
    block_time: int = 540  # 9 minutes in seconds
    randao_commit_duration: int = 60
    randao_reveal_duration: int = 60
    poef_task_difficulty: int = 4
    
    # Fee Configuration
    base_fee: Decimal = Decimal('0.0000000000000001')
    fee_multiplier: Decimal = Decimal('0.00000000000001')
    
    # Network Discovery
    bootstrap_nodes: str = ""  # Comma-separated list of bootstrap nodes
    discovery_enabled: bool = True
    
    # Node Role
    node_role: str = "validator"  # validator, observer


class OpenNodeConfigManager:
    """Centralized configuration management for the Open Omne Node"""
    
    def __init__(self):
        self.config = OpenNodeConfig()
        self._load_from_environment()
        self._validate_config()
        self._setup_logging()
    
    def _load_from_environment(self):
        """Load configuration from environment variables"""
        
        # Node Identity (Critical for open nodes)
        self.config.steward_address = os.getenv('STEWARD_ADDRESS')
        self.config.node_id = os.getenv('NODE_ID')
        
        # Network Configuration
        self.config.network_port = int(os.getenv('PORT_NUMBER', os.getenv('OMNE_NETWORK_PORT', self.config.network_port)))
        self.config.network_host = os.getenv('OMNE_NETWORK_HOST', self.config.network_host)
        self.config.network_timeout = int(os.getenv('OMNE_NETWORK_TIMEOUT', self.config.network_timeout))
        self.config.max_connections = int(os.getenv('OMNE_MAX_CONNECTIONS', self.config.max_connections))
        
        # Blockchain Configuration
        self.config.initial_supply = Decimal(os.getenv('OMNE_INITIAL_SUPPLY', str(self.config.initial_supply)))
        self.config.decimals = int(os.getenv('OMNE_DECIMALS', self.config.decimals))
        
        # Storage Configuration
        self.config.use_mongodb = os.getenv('OMNE_USE_MONGODB', 'false').lower() == 'true'
        self.config.mongodb_uri = os.getenv('OMNE_MONGODB_URI')
        self.config.storage_backend = os.getenv('OMNE_STORAGE_BACKEND', self.config.storage_backend)
        self.config.data_directory = os.getenv('OMNE_DATA_DIRECTORY', self.config.data_directory)
        
        # Security Configuration
        self.config.enable_ssl = os.getenv('OMNE_ENABLE_SSL', 'false').lower() == 'true'
        self.config.ssl_cert_path = os.getenv('OMNE_SSL_CERT_PATH')
        self.config.ssl_key_path = os.getenv('OMNE_SSL_KEY_PATH')
        
        # Performance Configuration
        self.config.max_block_size = int(os.getenv('OMNE_MAX_BLOCK_SIZE', self.config.max_block_size))
        self.config.max_transaction_pool_size = int(os.getenv('OMNE_MAX_TRANSACTION_POOL_SIZE', self.config.max_transaction_pool_size))
        self.config.transaction_timeout = int(os.getenv('OMNE_TRANSACTION_TIMEOUT', self.config.transaction_timeout))
        
        # Logging Configuration
        self.config.log_level = os.getenv('OMNE_LOG_LEVEL', self.config.log_level)
        self.config.log_file = os.getenv('OMNE_LOG_FILE')
        self.config.log_max_size = int(os.getenv('OMNE_LOG_MAX_SIZE', self.config.log_max_size))
        self.config.log_backup_count = int(os.getenv('OMNE_LOG_BACKUP_COUNT', self.config.log_backup_count))
        
        # Development Configuration
        self.config.debug_mode = os.getenv('OMNE_DEBUG_MODE', os.getenv('NODE_ENV', '').lower() == 'development').lower() == 'true' if isinstance(os.getenv('OMNE_DEBUG_MODE', os.getenv('NODE_ENV', '').lower() == 'development'), str) else os.getenv('NODE_ENV', '').lower() == 'development'
        self.config.test_mode = os.getenv('OMNE_TEST_MODE', 'false').lower() == 'true'
        
        # Consensus Configuration
        self.config.consensus_timeout = int(os.getenv('OMNE_CONSENSUS_TIMEOUT', self.config.consensus_timeout))
        self.config.block_time = int(os.getenv('OMNE_BLOCK_TIME', self.config.block_time))
        self.config.randao_commit_duration = int(os.getenv('OMNE_RANDAO_COMMIT_DURATION', self.config.randao_commit_duration))
        self.config.randao_reveal_duration = int(os.getenv('OMNE_RANDAO_REVEAL_DURATION', self.config.randao_reveal_duration))
        self.config.poef_task_difficulty = int(os.getenv('OMNE_POEF_DIFFICULTY', self.config.poef_task_difficulty))
        
        # Fee Configuration
        self.config.base_fee = Decimal(os.getenv('OMNE_BASE_FEE', str(self.config.base_fee)))
        self.config.fee_multiplier = Decimal(os.getenv('OMNE_FEE_MULTIPLIER', str(self.config.fee_multiplier)))
        
        # Network Discovery
        self.config.bootstrap_nodes = os.getenv('OMNE_BOOTSTRAP_NODES', self.config.bootstrap_nodes)
        self.config.discovery_enabled = os.getenv('OMNE_DISCOVERY_ENABLED', 'true').lower() == 'true'
        
        # Node Role
        self.config.node_role = os.getenv('NODE_ROLE', self.config.node_role)
    
    def _validate_config(self):
        """Validate configuration values"""
        errors = []
        
        # Validate required steward address for open nodes
        if not self.config.steward_address:
            errors.append("STEWARD_ADDRESS is required for open nodes")
        elif not self.config.steward_address.startswith('0z') or len(self.config.steward_address) != 42:
            errors.append(f"Invalid steward address format: {self.config.steward_address}. Must start with '0z' and be 42 characters long")
        
        # Validate network configuration
        if not (1 <= self.config.network_port <= 65535):
            errors.append(f"Invalid network port: {self.config.network_port}")
        
        if self.config.network_timeout <= 0:
            errors.append(f"Invalid network timeout: {self.config.network_timeout}")
        
        if self.config.max_connections <= 0:
            errors.append(f"Invalid max connections: {self.config.max_connections}")
        
        # Validate blockchain configuration
        if self.config.initial_supply <= 0:
            errors.append(f"Invalid initial supply: {self.config.initial_supply}")
        
        if self.config.decimals < 0:
            errors.append(f"Invalid decimals: {self.config.decimals}")
        
        # Validate SSL configuration
        if self.config.enable_ssl:
            if not self.config.ssl_cert_path or not os.path.exists(self.config.ssl_cert_path):
                errors.append("SSL certificate path is required when SSL is enabled")
            
            if not self.config.ssl_key_path or not os.path.exists(self.config.ssl_key_path):
                errors.append("SSL key path is required when SSL is enabled")
        
        # Validate storage configuration
        if self.config.use_mongodb and not self.config.mongodb_uri:
            errors.append("MongoDB URI is required when MongoDB is enabled")
        
        valid_storage_backends = ['memory', 'file', 'mongodb']
        if self.config.storage_backend not in valid_storage_backends:
            errors.append(f"Invalid storage backend: {self.config.storage_backend}. Must be one of {valid_storage_backends}")
        
        # Validate log level
        valid_log_levels = ['DEBUG', 'INFO', 'WARNING', 'ERROR', 'CRITICAL']
        if self.config.log_level not in valid_log_levels:
            errors.append(f"Invalid log level: {self.config.log_level}. Must be one of {valid_log_levels}")
        
        # Validate node role
        valid_roles = ['validator', 'observer']
        if self.config.node_role not in valid_roles:
            errors.append(f"Invalid node role: {self.config.node_role}. Must be one of {valid_roles}")
        
        if errors:
            raise ValueError(f"Configuration validation failed: {'; '.join(errors)}")
    
    def _setup_logging(self):
        """Setup logging based on configuration"""
        log_level = getattr(logging, self.config.log_level.upper())
        
        # Create formatter
        formatter = logging.Formatter(
            '[%(asctime)s] [%(levelname)s] [%(name)s] %(message)s'
        )
        
        # Setup root logger
        root_logger = logging.getLogger()
        root_logger.setLevel(log_level)
        
        # Clear existing handlers
        for handler in root_logger.handlers[:]:
            root_logger.removeHandler(handler)
        
        # Add console handler
        console_handler = logging.StreamHandler()
        console_handler.setFormatter(formatter)
        root_logger.addHandler(console_handler)
        
        # Add file handler if specified
        if self.config.log_file:
            try:
                # Create log directory if it doesn't exist
                log_dir = os.path.dirname(self.config.log_file)
                if log_dir and not os.path.exists(log_dir):
                    os.makedirs(log_dir, exist_ok=True)
                
                from logging.handlers import RotatingFileHandler
                file_handler = RotatingFileHandler(
                    self.config.log_file,
                    maxBytes=self.config.log_max_size,
                    backupCount=self.config.log_backup_count
                )
                file_handler.setFormatter(formatter)
                root_logger.addHandler(file_handler)
            except Exception as e:
                logging.warning(f"Could not setup file logging: {e}")
    
    def get_config(self) -> OpenNodeConfig:
        """Get the current configuration"""
        return self.config
    
    def is_production_ready(self) -> bool:
        """Check if the configuration is ready for production"""
        try:
            # Check critical settings for production
            if self.config.debug_mode:
                return False
            
            if self.config.log_level == 'DEBUG':
                return False
            
            if not self.config.steward_address:
                return False
            
            if self.config.storage_backend == 'memory':
                return False  # Memory storage not suitable for production
            
            return True
        except Exception:
            return False
    
    def get_summary(self) -> Dict[str, Any]:
        """Get a summary of the current configuration"""
        return {
            'steward_address': self.config.steward_address,
            'node_id': self.config.node_id,
            'network_port': self.config.network_port,
            'storage_backend': self.config.storage_backend,
            'data_directory': self.config.data_directory,
            'log_level': self.config.log_level,
            'debug_mode': self.config.debug_mode,
            'production_ready': self.is_production_ready(),
            'node_role': self.config.node_role
        }
