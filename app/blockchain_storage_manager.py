"""
Enhanced Storage Manager for OMNE Node
Provides blockchain-native storage without external database dependencies
"""

import logging
import threading
from typing import Dict, Any, Optional, List
from pathlib import Path
from datetime import datetime

from storage_abstraction import StorageBackend, FileStorageBackend, MemoryStorageBackend
from error_handling import StorageError, ErrorSeverity, with_error_handling


class BlockchainStorageManager:
    """
    Ethereum/Sui-inspired storage manager for OMNE blockchain
    Handles all blockchain data persistence locally without external dependencies
    """
    
    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.logger = logging.getLogger(__name__)
        self.lock = threading.RLock()
        
        # Initialize storage backend based on configuration
        self.backend = self._initialize_storage_backend()
        
        # Storage statistics
        self.stats = {
            "blocks_stored": 0,
            "transactions_stored": 0,
            "accounts_stored": 0,
            "contracts_stored": 0,
            "startup_time": datetime.utcnow(),
            "last_operation": None
        }
        
        self.logger.info(f"✅ Blockchain Storage Manager initialized with {type(self.backend).__name__}")
    
    def _initialize_storage_backend(self) -> StorageBackend:
        """Initialize the appropriate storage backend based on configuration"""
        storage_type = self.config.get('storage_type', 'file')
        
        if storage_type == 'leveldb':
            try:
                from storage_backends.leveldb_backend import LevelDBStorageBackend
                data_dir = self.config.get('data_directory', './blockchain_data')
                return LevelDBStorageBackend(data_dir)
            except ImportError:
                self.logger.warning("⚠️ LevelDB not available, falling back to file storage")
                storage_type = 'file'
        
        if storage_type == 'file':
            data_dir = self.config.get('data_directory', './blockchain_data')
            return FileStorageBackend(data_dir)
        
        elif storage_type == 'memory':
            self.logger.warning("⚠️ Using memory storage - data will not persist!")
            return MemoryStorageBackend()
        
        else:
            raise StorageError(f"Unknown storage type: {storage_type}", ErrorSeverity.CRITICAL)
    
    # Block Storage Operations
    
    @with_error_handling(reraise=True)
    def store_block(self, block: Dict[str, Any]) -> bool:
        """Store a blockchain block with proper indexing"""
        with self.lock:
            try:
                block_hash = block.get('hash')
                block_index = block.get('index')
                
                if not block_hash:
                    raise StorageError("Block hash is required", ErrorSeverity.HIGH)
                
                # Store block by hash
                if not self.backend.set(f"block:{block_hash}", block):
                    return False
                
                # Store block by index for sequential access
                if block_index is not None:
                    if not self.backend.set(f"block_by_index:{block_index}", block_hash):
                        return False
                
                # Update latest block pointer
                if not self.backend.set("latest_block_hash", block_hash):
                    return False
                
                if not self.backend.set("latest_block_index", block_index or 0):
                    return False
                
                # Update chain height
                current_height = self.get_chain_height()
                if block_index is not None and block_index >= current_height:
                    self.backend.set("chain_height", block_index + 1)
                
                self.stats["blocks_stored"] += 1
                self.stats["last_operation"] = datetime.utcnow()
                
                self.logger.debug(f"📦 Stored block {block_index} with hash {block_hash[:8]}...")
                return True
                
            except Exception as e:
                self.logger.error(f"❌ Failed to store block: {e}")
                return False
    
    @with_error_handling(reraise=True)
    def get_block(self, identifier: str) -> Optional[Dict[str, Any]]:
        """Get block by hash or index"""
        with self.lock:
            try:
                # Try to get by hash first
                if identifier.startswith('0x') or len(identifier) == 64:
                    return self.backend.get(f"block:{identifier}")
                
                # Try to get by index
                try:
                    index = int(identifier)
                    block_hash = self.backend.get(f"block_by_index:{index}")
                    if block_hash:
                        return self.backend.get(f"block:{block_hash}")
                except ValueError:
                    pass
                
                return None
                
            except Exception as e:
                self.logger.error(f"❌ Failed to get block {identifier}: {e}")
                return None
    
    def get_latest_block(self) -> Optional[Dict[str, Any]]:
        """Get the latest block in the chain"""
        latest_hash = self.backend.get("latest_block_hash")
        if latest_hash:
            return self.get_block(latest_hash)
        return None
    
    def get_chain_height(self) -> int:
        """Get current blockchain height"""
        height = self.backend.get("chain_height")
        return height if height is not None else 0
    
    # Transaction Storage Operations
    
    @with_error_handling(reraise=True)
    def store_transaction(self, tx: Dict[str, Any]) -> bool:
        """Store a transaction with indexing"""
        with self.lock:
            try:
                tx_hash = tx.get('hash') or tx.get('txHash')
                if not tx_hash:
                    raise StorageError("Transaction hash is required", ErrorSeverity.HIGH)
                
                # Store transaction
                if not self.backend.set(f"tx:{tx_hash}", tx):
                    return False
                
                # Index by sender and receiver for quick lookup
                sender = tx.get('sender') or tx.get('from')
                receiver = tx.get('receiver') or tx.get('to')
                
                if sender:
                    sender_txs = self.backend.get(f"account_txs:{sender}") or []
                    sender_txs.append(tx_hash)
                    self.backend.set(f"account_txs:{sender}", sender_txs)
                
                if receiver and receiver != sender:
                    receiver_txs = self.backend.get(f"account_txs:{receiver}") or []
                    receiver_txs.append(tx_hash)
                    self.backend.set(f"account_txs:{receiver}", receiver_txs)
                
                self.stats["transactions_stored"] += 1
                self.stats["last_operation"] = datetime.utcnow()
                
                return True
                
            except Exception as e:
                self.logger.error(f"❌ Failed to store transaction: {e}")
                return False
    
    def get_transaction(self, tx_hash: str) -> Optional[Dict[str, Any]]:
        """Get transaction by hash"""
        return self.backend.get(f"tx:{tx_hash}")
    
    def get_account_transactions(self, address: str) -> List[Dict[str, Any]]:
        """Get all transactions for an account"""
        tx_hashes = self.backend.get(f"account_txs:{address}") or []
        transactions = []
        
        for tx_hash in tx_hashes:
            tx = self.get_transaction(tx_hash)
            if tx:
                transactions.append(tx)
        
        return transactions
    
    # Account State Storage Operations
    
    @with_error_handling(reraise=True)
    def store_account_state(self, address: str, state: Dict[str, Any]) -> bool:
        """Store account state"""
        with self.lock:
            try:
                if not self.backend.set(f"account:{address}", state):
                    return False
                
                self.stats["accounts_stored"] += 1
                self.stats["last_operation"] = datetime.utcnow()
                
                return True
                
            except Exception as e:
                self.logger.error(f"❌ Failed to store account state for {address}: {e}")
                return False
    
    def get_account_state(self, address: str) -> Optional[Dict[str, Any]]:
        """Get account state by address"""
        return self.backend.get(f"account:{address}")
    
    def account_exists(self, address: str) -> bool:
        """Check if account exists"""
        return self.backend.exists(f"account:{address}")
    
    # Smart Contract Storage Operations
    
    @with_error_handling(reraise=True)
    def store_contract_state(self, contract_address: str, state: Dict[str, Any]) -> bool:
        """Store smart contract state"""
        with self.lock:
            try:
                if not self.backend.set(f"contract:{contract_address}", state):
                    return False
                
                self.stats["contracts_stored"] += 1
                self.stats["last_operation"] = datetime.utcnow()
                
                return True
                
            except Exception as e:
                self.logger.error(f"❌ Failed to store contract state for {contract_address}: {e}")
                return False
    
    def get_contract_state(self, contract_address: str) -> Optional[Dict[str, Any]]:
        """Get smart contract state"""
        return self.backend.get(f"contract:{contract_address}")
    
    # Blockchain State Operations
    
    def store_state_root(self, block_height: int, state_root: str) -> bool:
        """Store state root hash for a block height"""
        return self.backend.set(f"state_root:{block_height}", state_root)
    
    def get_state_root(self, block_height: int) -> Optional[str]:
        """Get state root hash for a block height"""
        return self.backend.get(f"state_root:{block_height}")
    
    # Storage Management Operations
    
    def get_storage_stats(self) -> Dict[str, Any]:
        """Get comprehensive storage statistics"""
        backend_stats = {}
        
        # Get backend-specific stats if available
        if hasattr(self.backend, 'get_blockchain_stats'):
            backend_stats = self.backend.get_blockchain_stats()
        
        return {
            **self.stats,
            "backend_type": type(self.backend).__name__,
            "backend_stats": backend_stats,
            "chain_height": self.get_chain_height(),
            "latest_block_hash": self.backend.get("latest_block_hash"),
            "storage_healthy": self.health_check()
        }
    
    def health_check(self) -> bool:
        """Perform storage health check"""
        try:
            # Test basic read/write operations
            test_key = "health_check_test"
            test_value = {"timestamp": datetime.utcnow().isoformat()}
            
            if not self.backend.set(test_key, test_value):
                return False
            
            retrieved = self.backend.get(test_key)
            if retrieved != test_value:
                return False
            
            self.backend.delete(test_key)
            return True
            
        except Exception as e:
            self.logger.error(f"❌ Storage health check failed: {e}")
            return False
    
    def backup_blockchain_data(self, backup_path: str) -> bool:
        """Create a backup of blockchain data"""
        try:
            backup_dir = Path(backup_path)
            backup_dir.mkdir(parents=True, exist_ok=True)
            
            # Get all keys and data
            all_keys = self.backend.list_keys()
            backup_data = {}
            
            for key in all_keys:
                value = self.backend.get(key)
                if value is not None:
                    backup_data[key] = value
            
            # Save backup
            import json
            backup_file = backup_dir / f"omne_backup_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}.json"
            
            with open(backup_file, 'w') as f:
                json.dump(backup_data, f, indent=2, default=str)
            
            self.logger.info(f"✅ Blockchain data backed up to {backup_file}")
            return True
            
        except Exception as e:
            self.logger.error(f"❌ Backup failed: {e}")
            return False
    
    def restore_blockchain_data(self, backup_file: str) -> bool:
        """Restore blockchain data from backup"""
        try:
            import json
            
            with open(backup_file, 'r') as f:
                backup_data = json.load(f)
            
            # Clear current data
            self.backend.clear()
            
            # Restore data
            for key, value in backup_data.items():
                self.backend.set(key, value)
            
            self.logger.info(f"✅ Blockchain data restored from {backup_file}")
            return True
            
        except Exception as e:
            self.logger.error(f"❌ Restore failed: {e}")
            return False
    
    def close(self) -> None:
        """Close storage manager and underlying backend"""
        try:
            if self.backend:
                self.backend.close()
            self.logger.info("🔒 Storage manager closed")
        except Exception as e:
            self.logger.error(f"Error closing storage manager: {e}")
    
    def __enter__(self):
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close()
