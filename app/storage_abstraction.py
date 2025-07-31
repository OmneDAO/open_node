"""
Storage Abstraction Layer for Open Omne Node
Provides pluggable storage backends for flexible data persistence.
"""

import os
import json
import logging
import threading
from abc import ABC, abstractmethod
from typing import Any, Dict, List, Optional, Union
from decimal import Decimal
from datetime import datetime

from error_handling import StorageError, ErrorSeverity


class StorageBackend(ABC):
    """Abstract base class for storage backends"""
    
    @abstractmethod
    def initialize(self) -> bool:
        """Initialize the storage backend"""
        pass
    
    @abstractmethod
    def store(self, key: str, data: Any) -> bool:
        """Store data with a key"""
        pass
    
    @abstractmethod
    def retrieve(self, key: str) -> Optional[Any]:
        """Retrieve data by key"""
        pass
    
    @abstractmethod
    def delete(self, key: str) -> bool:
        """Delete data by key"""
        pass
    
    @abstractmethod
    def exists(self, key: str) -> bool:
        """Check if key exists"""
        pass
    
    @abstractmethod
    def list_keys(self, prefix: Optional[str] = None) -> List[str]:
        """List all keys, optionally filtered by prefix"""
        pass
    
    @abstractmethod
    def clear_all(self) -> bool:
        """Clear all data"""
        pass
    
    @abstractmethod
    def get_info(self) -> Dict[str, Any]:
        """Get backend information"""
        pass


class MemoryStorageBackend(StorageBackend):
    """In-memory storage backend"""
    
    def __init__(self):
        self._data = {}
        self._lock = threading.RLock()
    
    def initialize(self) -> bool:
        """Initialize memory storage"""
        return True
    
    def store(self, key: str, data: Any) -> bool:
        """Store data in memory"""
        with self._lock:
            self._data[key] = data
            return True
    
    def retrieve(self, key: str) -> Optional[Any]:
        """Retrieve data from memory"""
        with self._lock:
            return self._data.get(key)
    
    def delete(self, key: str) -> bool:
        """Delete data from memory"""
        with self._lock:
            if key in self._data:
                del self._data[key]
                return True
            return False
    
    def exists(self, key: str) -> bool:
        """Check if key exists in memory"""
        with self._lock:
            return key in self._data
    
    def list_keys(self, prefix: Optional[str] = None) -> List[str]:
        """List all keys in memory"""
        with self._lock:
            if prefix:
                return [k for k in self._data.keys() if k.startswith(prefix)]
            return list(self._data.keys())
    
    def clear_all(self) -> bool:
        """Clear all data from memory"""
        with self._lock:
            self._data.clear()
            return True
    
    def get_info(self) -> Dict[str, Any]:
        """Get memory storage info"""
        with self._lock:
            return {
                'type': 'memory',
                'initialized': True,
                'key_count': len(self._data),
                'memory_usage': f"{len(str(self._data))} bytes (approximate)"
            }


class FileStorageBackend(StorageBackend):
    """File-based storage backend"""
    
    def __init__(self, data_directory: str = "./data"):
        self.data_directory = data_directory
        self._lock = threading.RLock()
        self._initialized = False
    
    def initialize(self) -> bool:
        """Initialize file storage"""
        try:
            os.makedirs(self.data_directory, exist_ok=True)
            self._initialized = True
            return True
        except Exception as e:
            raise StorageError(f"Failed to initialize file storage: {e}", 
                             severity=ErrorSeverity.HIGH)
    
    def _get_file_path(self, key: str) -> str:
        """Get file path for a key"""
        # Replace invalid filename characters
        safe_key = key.replace('/', '_').replace('\\', '_').replace(':', '_')
        return os.path.join(self.data_directory, f"{safe_key}.json")
    
    def store(self, key: str, data: Any) -> bool:
        """Store data to file"""
        if not self._initialized:
            raise StorageError("Storage backend not initialized", 
                             severity=ErrorSeverity.HIGH)
        
        try:
            with self._lock:
                file_path = self._get_file_path(key)
                
                # Convert Decimal to string for JSON serialization
                json_data = self._serialize_data(data)
                
                with open(file_path, 'w') as f:
                    json.dump(json_data, f, indent=2, default=str)
                
                return True
        except Exception as e:
            raise StorageError(f"Failed to store data for key '{key}': {e}", 
                             severity=ErrorSeverity.MEDIUM)
    
    def retrieve(self, key: str) -> Optional[Any]:
        """Retrieve data from file"""
        if not self._initialized:
            raise StorageError("Storage backend not initialized", 
                             severity=ErrorSeverity.HIGH)
        
        try:
            with self._lock:
                file_path = self._get_file_path(key)
                
                if not os.path.exists(file_path):
                    return None
                
                with open(file_path, 'r') as f:
                    json_data = json.load(f)
                
                return self._deserialize_data(json_data)
        except Exception as e:
            raise StorageError(f"Failed to retrieve data for key '{key}': {e}", 
                             severity=ErrorSeverity.MEDIUM)
    
    def delete(self, key: str) -> bool:
        """Delete data file"""
        if not self._initialized:
            raise StorageError("Storage backend not initialized", 
                             severity=ErrorSeverity.HIGH)
        
        try:
            with self._lock:
                file_path = self._get_file_path(key)
                
                if os.path.exists(file_path):
                    os.remove(file_path)
                    return True
                
                return False
        except Exception as e:
            raise StorageError(f"Failed to delete data for key '{key}': {e}", 
                             severity=ErrorSeverity.MEDIUM)
    
    def exists(self, key: str) -> bool:
        """Check if file exists"""
        if not self._initialized:
            return False
        
        with self._lock:
            file_path = self._get_file_path(key)
            return os.path.exists(file_path)
    
    def list_keys(self, prefix: Optional[str] = None) -> List[str]:
        """List all keys from files"""
        if not self._initialized:
            return []
        
        try:
            with self._lock:
                keys = []
                for filename in os.listdir(self.data_directory):
                    if filename.endswith('.json'):
                        key = filename[:-5]  # Remove .json extension
                        # Convert safe key back to original
                        key = key.replace('_', '/')
                        if not prefix or key.startswith(prefix):
                            keys.append(key)
                return keys
        except Exception as e:
            raise StorageError(f"Failed to list keys: {e}", 
                             severity=ErrorSeverity.MEDIUM)
    
    def clear_all(self) -> bool:
        """Clear all data files"""
        if not self._initialized:
            return False
        
        try:
            with self._lock:
                for filename in os.listdir(self.data_directory):
                    if filename.endswith('.json'):
                        os.remove(os.path.join(self.data_directory, filename))
                return True
        except Exception as e:
            raise StorageError(f"Failed to clear all data: {e}", 
                             severity=ErrorSeverity.MEDIUM)
    
    def get_info(self) -> Dict[str, Any]:
        """Get file storage info"""
        try:
            with self._lock:
                file_count = len([f for f in os.listdir(self.data_directory) 
                                if f.endswith('.json')]) if os.path.exists(self.data_directory) else 0
                
                # Calculate total size
                total_size = 0
                if os.path.exists(self.data_directory):
                    for filename in os.listdir(self.data_directory):
                        if filename.endswith('.json'):
                            file_path = os.path.join(self.data_directory, filename)
                            total_size += os.path.getsize(file_path)
                
                return {
                    'type': 'file',
                    'initialized': self._initialized,
                    'data_directory': self.data_directory,
                    'file_count': file_count,
                    'total_size': f"{total_size} bytes"
                }
        except Exception as e:
            return {
                'type': 'file',
                'initialized': self._initialized,
                'error': str(e)
            }
    
    def _serialize_data(self, data: Any) -> Any:
        """Serialize data for JSON storage"""
        if isinstance(data, Decimal):
            return {'_type': 'Decimal', '_value': str(data)}
        elif isinstance(data, datetime):
            return {'_type': 'datetime', '_value': data.isoformat()}
        elif isinstance(data, dict):
            return {k: self._serialize_data(v) for k, v in data.items()}
        elif isinstance(data, list):
            return [self._serialize_data(item) for item in data]
        else:
            return data
    
    def _deserialize_data(self, data: Any) -> Any:
        """Deserialize data from JSON storage"""
        if isinstance(data, dict):
            if '_type' in data and '_value' in data:
                if data['_type'] == 'Decimal':
                    return Decimal(data['_value'])
                elif data['_type'] == 'datetime':
                    return datetime.fromisoformat(data['_value'])
            else:
                return {k: self._deserialize_data(v) for k, v in data.items()}
        elif isinstance(data, list):
            return [self._deserialize_data(item) for item in data]
        else:
            return data


class StorageManager:
    """Manager for storage backends"""
    
    def __init__(self, backend_type: str = "memory", **kwargs):
        self.backend_type = backend_type
        self.backend = self._create_backend(backend_type, **kwargs)
        self.logger = logging.getLogger(__name__)
    
    def _create_backend(self, backend_type: str, **kwargs) -> StorageBackend:
        """Create appropriate storage backend"""
        if backend_type == "memory":
            return MemoryStorageBackend()
        elif backend_type == "file":
            data_directory = kwargs.get('data_directory', './data')
            return FileStorageBackend(data_directory)
        else:
            raise StorageError(f"Unknown storage backend type: {backend_type}", 
                             severity=ErrorSeverity.CRITICAL)
    
    def initialize(self) -> bool:
        """Initialize the storage backend"""
        try:
            result = self.backend.initialize()
            self.logger.info(f"Storage backend '{self.backend_type}' initialized successfully")
            return result
        except Exception as e:
            self.logger.error(f"Failed to initialize storage backend '{self.backend_type}': {e}")
            raise
    
    def store(self, key: str, data: Any) -> bool:
        """Store data"""
        return self.backend.store(key, data)
    
    def retrieve(self, key: str) -> Optional[Any]:
        """Retrieve data"""
        return self.backend.retrieve(key)
    
    def delete(self, key: str) -> bool:
        """Delete data"""
        return self.backend.delete(key)
    
    def exists(self, key: str) -> bool:
        """Check if key exists"""
        return self.backend.exists(key)
    
    def list_keys(self, prefix: Optional[str] = None) -> List[str]:
        """List keys"""
        return self.backend.list_keys(prefix)
    
    def clear_all(self) -> bool:
        """Clear all data"""
        return self.backend.clear_all()
    
    def get_backend_info(self) -> Dict[str, Any]:
        """Get backend information"""
        return self.backend.get_info()


class BlockStorage:
    """Specialized storage for blockchain data"""
    
    def __init__(self, storage_manager: StorageManager):
        self.storage = storage_manager
        self.logger = logging.getLogger(__name__)
    
    def store_block(self, block_data: Dict) -> bool:
        """Store a block"""
        try:
            block_hash = block_data.get('hash')
            if not block_hash:
                raise StorageError("Block hash is required for storage", 
                                 severity=ErrorSeverity.HIGH)
            
            # Store by hash
            hash_key = f"block_hash_{block_hash}"
            self.storage.store(hash_key, block_data)
            
            # Store by index if available
            if 'index' in block_data:
                index_key = f"block_index_{block_data['index']}"
                self.storage.store(index_key, block_data)
            
            # Update latest block pointer
            self.storage.store("latest_block", block_data)
            
            self.logger.info(f"Block {block_hash} stored successfully")
            return True
            
        except Exception as e:
            self.logger.error(f"Failed to store block: {e}")
            raise
    
    def get_block_by_hash(self, block_hash: str) -> Optional[Dict]:
        """Get block by hash"""
        key = f"block_hash_{block_hash}"
        return self.storage.retrieve(key)
    
    def get_block_by_index(self, index: int) -> Optional[Dict]:
        """Get block by index"""
        key = f"block_index_{index}"
        return self.storage.retrieve(key)
    
    def get_latest_block(self) -> Optional[Dict]:
        """Get the latest block"""
        return self.storage.retrieve("latest_block")
    
    def get_all_blocks(self) -> List[Dict]:
        """Get all blocks"""
        blocks = []
        hash_keys = self.storage.list_keys("block_hash_")
        
        for key in hash_keys:
            block_data = self.storage.retrieve(key)
            if block_data:
                blocks.append(block_data)
        
        # Sort by index if available
        blocks.sort(key=lambda x: x.get('index', 0))
        return blocks


class TransactionStorage:
    """Specialized storage for transaction data"""
    
    def __init__(self, storage_manager: StorageManager):
        self.storage = storage_manager
        self.logger = logging.getLogger(__name__)
    
    def store_transaction(self, tx_data: Dict) -> bool:
        """Store a transaction"""
        try:
            tx_hash = tx_data.get('hash')
            if not tx_hash:
                raise StorageError("Transaction hash is required for storage", 
                                 severity=ErrorSeverity.HIGH)
            
            key = f"tx_{tx_hash}"
            self.storage.store(key, tx_data)
            
            self.logger.debug(f"Transaction {tx_hash} stored successfully")
            return True
            
        except Exception as e:
            self.logger.error(f"Failed to store transaction: {e}")
            raise
    
    def get_transaction(self, tx_hash: str) -> Optional[Dict]:
        """Get transaction by hash"""
        key = f"tx_{tx_hash}"
        return self.storage.retrieve(key)
    
    def get_transactions_by_sender(self, sender_address: str) -> List[Dict]:
        """Get transactions by sender address"""
        transactions = []
        tx_keys = self.storage.list_keys("tx_")
        
        for key in tx_keys:
            tx_data = self.storage.retrieve(key)
            if tx_data and tx_data.get('sender') == sender_address:
                transactions.append(tx_data)
        
        return transactions
