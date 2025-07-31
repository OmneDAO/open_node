"""
LevelDB Storage Backend for OMNE Node
Implements local persistent storage similar to Ethereum's approach
"""

import plyvel
import json
import logging
import threading
from pathlib import Path
from typing import Any, Dict, List, Optional, Union
from datetime import datetime

import sys
import os
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from storage_abstraction import StorageBackend
from ..error_handling import StorageError, ErrorSeverity, with_error_handling


class LevelDBStorageBackend(StorageBackend):
    """LevelDB-based storage backend for production blockchain storage"""
    
    def __init__(self, data_directory: str = "./blockchain_data"):
        self.data_directory = Path(data_directory)
        self.data_directory.mkdir(parents=True, exist_ok=True)
        self.lock = threading.RLock()
        self.logger = logging.getLogger(__name__)
        
        # Initialize LevelDB databases for different data types
        self.db_path = self.data_directory / "leveldb"
        self.db_path.mkdir(parents=True, exist_ok=True)
        
        try:
            # Main database for blockchain data
            self.db = plyvel.DB(str(self.db_path / "main"), create_if_missing=True)
            
            # Separate databases for different data types
            self.blocks_db = plyvel.DB(str(self.db_path / "blocks"), create_if_missing=True)
            self.state_db = plyvel.DB(str(self.db_path / "state"), create_if_missing=True)
            self.accounts_db = plyvel.DB(str(self.db_path / "accounts"), create_if_missing=True)
            self.contracts_db = plyvel.DB(str(self.db_path / "contracts"), create_if_missing=True)
            self.transactions_db = plyvel.DB(str(self.db_path / "transactions"), create_if_missing=True)
            
            self.logger.info(f"✅ LevelDB initialized at {self.db_path}")
            
        except Exception as e:
            self.logger.error(f"❌ Failed to initialize LevelDB: {e}")
            raise StorageError(f"LevelDB initialization failed: {e}", ErrorSeverity.CRITICAL)
    
    def _serialize_value(self, value: Any) -> bytes:
        """Serialize Python object to bytes for storage"""
        if isinstance(value, (dict, list)):
            return json.dumps(value, default=str).encode('utf-8')
        elif isinstance(value, str):
            return value.encode('utf-8')
        elif isinstance(value, bytes):
            return value
        else:
            return str(value).encode('utf-8')
    
    def _deserialize_value(self, data: bytes) -> Any:
        """Deserialize bytes back to Python object"""
        try:
            text = data.decode('utf-8')
            # Try to parse as JSON first
            try:
                return json.loads(text)
            except json.JSONDecodeError:
                # Return as string if not valid JSON
                return text
        except UnicodeDecodeError:
            # Return raw bytes if not valid UTF-8
            return data
    
    def _get_database_for_key(self, key: str):
        """Route key to appropriate database based on prefix"""
        if key.startswith('block:'):
            return self.blocks_db
        elif key.startswith('state:'):
            return self.state_db
        elif key.startswith('account:'):
            return self.accounts_db
        elif key.startswith('contract:'):
            return self.contracts_db
        elif key.startswith('tx:'):
            return self.transactions_db
        else:
            return self.db
    
    @with_error_handling(reraise=True)
    def get(self, key: str) -> Optional[Any]:
        """Get value by key from appropriate database"""
        with self.lock:
            try:
                db = self._get_database_for_key(key)
                raw_data = db.get(key.encode('utf-8'))
                
                if raw_data is None:
                    return None
                
                return self._deserialize_value(raw_data)
                
            except Exception as e:
                self.logger.error(f"Failed to get key '{key}': {e}")
                return None
    
    @with_error_handling(reraise=True)
    def set(self, key: str, value: Any) -> bool:
        """Set value by key in appropriate database"""
        with self.lock:
            try:
                db = self._get_database_for_key(key)
                serialized_value = self._serialize_value(value)
                db.put(key.encode('utf-8'), serialized_value)
                return True
                
            except Exception as e:
                self.logger.error(f"Failed to set key '{key}': {e}")
                return False
    
    @with_error_handling(reraise=True)
    def delete(self, key: str) -> bool:
        """Delete value by key from appropriate database"""
        with self.lock:
            try:
                db = self._get_database_for_key(key)
                db.delete(key.encode('utf-8'))
                return True
                
            except Exception as e:
                self.logger.error(f"Failed to delete key '{key}': {e}")
                return False
    
    @with_error_handling(reraise=True)
    def exists(self, key: str) -> bool:
        """Check if key exists in appropriate database"""
        with self.lock:
            try:
                db = self._get_database_for_key(key)
                return db.get(key.encode('utf-8')) is not None
                
            except Exception as e:
                self.logger.error(f"Failed to check existence of key '{key}': {e}")
                return False
    
    @with_error_handling(reraise=True)
    def list_keys(self, prefix: str = "") -> List[str]:
        """List all keys with optional prefix across all databases"""
        keys = []
        
        with self.lock:
            try:
                # List keys from all databases
                databases = [
                    ('', self.db),
                    ('block:', self.blocks_db),
                    ('state:', self.state_db),
                    ('account:', self.accounts_db),
                    ('contract:', self.contracts_db),
                    ('tx:', self.transactions_db)
                ]
                
                for db_prefix, db in databases:
                    if not prefix or db_prefix.startswith(prefix):
                        for key, _ in db:
                            key_str = key.decode('utf-8')
                            if key_str.startswith(prefix):
                                keys.append(key_str)
                
                return keys
                
            except Exception as e:
                self.logger.error(f"Failed to list keys with prefix '{prefix}': {e}")
                return []
    
    @with_error_handling(reraise=True)
    def clear(self) -> bool:
        """Clear all data from all databases"""
        with self.lock:
            try:
                databases = [self.db, self.blocks_db, self.state_db, 
                           self.accounts_db, self.contracts_db, self.transactions_db]
                
                for db in databases:
                    # Delete all keys in the database
                    for key, _ in db:
                        db.delete(key)
                
                self.logger.info("🗑️ Cleared all LevelDB data")
                return True
                
            except Exception as e:
                self.logger.error(f"Failed to clear databases: {e}")
                return False
    
    def close(self) -> None:
        """Close all LevelDB databases"""
        try:
            databases = [self.db, self.blocks_db, self.state_db, 
                        self.accounts_db, self.contracts_db, self.transactions_db]
            
            for db in databases:
                if db:
                    db.close()
            
            self.logger.info("🔒 LevelDB databases closed")
            
        except Exception as e:
            self.logger.error(f"Error closing LevelDB: {e}")
    
    # Blockchain-specific convenience methods
    
    def store_block(self, block_hash: str, block_data: dict) -> bool:
        """Store a blockchain block"""
        return self.set(f"block:{block_hash}", block_data)
    
    def get_block(self, block_hash: str) -> Optional[dict]:
        """Retrieve a blockchain block by hash"""
        return self.get(f"block:{block_hash}")
    
    def store_account_state(self, address: str, state: dict) -> bool:
        """Store account state"""
        return self.set(f"account:{address}", state)
    
    def get_account_state(self, address: str) -> Optional[dict]:
        """Retrieve account state by address"""
        return self.get(f"account:{address}")
    
    def store_transaction(self, tx_hash: str, tx_data: dict) -> bool:
        """Store a transaction"""
        return self.set(f"tx:{tx_hash}", tx_data)
    
    def get_transaction(self, tx_hash: str) -> Optional[dict]:
        """Retrieve a transaction by hash"""
        return self.get(f"tx:{tx_hash}")
    
    def store_contract_state(self, contract_address: str, state: dict) -> bool:
        """Store smart contract state"""
        return self.set(f"contract:{contract_address}", state)
    
    def get_contract_state(self, contract_address: str) -> Optional[dict]:
        """Retrieve smart contract state"""
        return self.get(f"contract:{contract_address}")
    
    def get_blockchain_stats(self) -> dict:
        """Get blockchain storage statistics"""
        try:
            stats = {
                "total_blocks": len([k for k in self.list_keys("block:")]),
                "total_accounts": len([k for k in self.list_keys("account:")]),
                "total_transactions": len([k for k in self.list_keys("tx:")]),
                "total_contracts": len([k for k in self.list_keys("contract:")]),
                "storage_path": str(self.db_path),
                "last_updated": datetime.utcnow().isoformat()
            }
            
            return stats
            
        except Exception as e:
            self.logger.error(f"Failed to get blockchain stats: {e}")
            return {}
