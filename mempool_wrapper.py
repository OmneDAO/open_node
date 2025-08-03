"""
Mempool Wrapper - Compatibility Layer

This module provides a compatibility wrapper that maintains the same API
as the original Mempool while using the separated core and genesis
components internally.
"""

import logging
from typing import Dict, List, Optional, Tuple, TYPE_CHECKING

from mempool_core import MempoolCore
from genesis_mempool_operations import GenesisMempoolOperations

if TYPE_CHECKING:
    from ledger import Ledger
    from consensus_engine import ConsensusEngine
    from dynamic_fee_calculator import DynamicFeeCalculator


class Mempool:
    """
    Compatibility wrapper for the separated mempool architecture.
    
    This class maintains the same public API as the original Mempool
    while delegating to the appropriate separated components internally.
    """

    def __init__(
        self,
        max_size: int = 1000,
        min_size: int = 100,
        max_priority_age_hours: int = 6,
        ledger=None,
        consensus_engine=None,
        dynamic_fee_calculator=None,
        network_manager=None,
        is_genesis_node: bool = False
    ):
        """
        Initialize the mempool wrapper.
        """
        # Initialize core mempool
        self.core = MempoolCore(
            max_size=max_size,
            min_size=min_size,
            max_priority_age_hours=max_priority_age_hours
        )

        # Initialize genesis operations
        self.genesis_ops = GenesisMempoolOperations(
            mempool_core=self.core,
            ledger=ledger,
            consensus_engine=consensus_engine,
            dynamic_fee_calculator=dynamic_fee_calculator,
            network_manager=network_manager,
            is_genesis_node=is_genesis_node
        )

        # Store references for compatibility
        self.max_size = max_size
        self.min_size = min_size
        self.max_priority_age_hours = max_priority_age_hours
        self.is_genesis_node = is_genesis_node

        # Logger
        self.logger = logging.getLogger('Mempool')
        self.logger.setLevel(logging.INFO)
        handler = logging.StreamHandler()
        formatter = logging.Formatter('[%(asctime)s] [%(levelname)s] [%(name)s] %(message)s')
        handler.setFormatter(formatter)
        if not self.logger.handlers:
            self.logger.addHandler(handler)

        self.logger.info(f"Mempool wrapper initialized (max_size: {max_size})")

    # === Core Mempool Delegation Methods ===

    @property
    def transactions(self) -> Dict:
        """Get transactions dictionary."""
        return self.core.transactions

    @property
    def pending_queue(self) -> List:
        """Get pending queue."""
        return self.core.pending_queue

    @property
    def mempool_lock(self):
        """Get mempool lock."""
        return self.core.mempool_lock

    @property
    def stats(self) -> Dict:
        """Get mempool statistics."""
        return self.core.stats

    def add_transaction(self, transaction: Dict) -> Tuple[bool, Optional[str]]:
        """
        Add a transaction to the mempool.
        
        This method automatically uses network sync and enhanced validation
        if genesis operations are available, otherwise falls back to core only.
        """
        if hasattr(self.genesis_ops, 'add_transaction_with_network_sync'):
            return self.genesis_ops.add_transaction_with_network_sync(transaction)
        else:
            return self.core.add_transaction(transaction)

    def remove_transaction(self, tx_id: str) -> bool:
        """Remove a transaction from the mempool."""
        if hasattr(self.genesis_ops, 'remove_transaction_with_cleanup'):
            return self.genesis_ops.remove_transaction_with_cleanup(tx_id)
        else:
            return self.core.remove_transaction(tx_id)

    def get_pending_transactions(self, limit: int = 100) -> List[Dict]:
        """Get pending transactions for block creation."""
        if hasattr(self.genesis_ops, 'get_transactions_for_block'):
            return self.genesis_ops.get_transactions_for_block(limit)
        else:
            return self.core.get_pending_transactions(limit)

    def get_transactions_by_sender(self, sender: str) -> List[Dict]:
        """Get transactions by sender."""
        return self.core.get_transactions_by_sender(sender)

    def get_transactions_by_receiver(self, receiver: str) -> List[Dict]:
        """Get transactions by receiver."""
        return self.core.get_transactions_by_receiver(receiver)

    def has_transaction(self, tx_id: str) -> bool:
        """Check if transaction exists."""
        return self.core.has_transaction(tx_id)

    def get_transaction(self, tx_id: str) -> Optional[Dict]:
        """Get specific transaction."""
        return self.core.get_transaction(tx_id)

    def get_mempool_size(self) -> int:
        """Get current mempool size."""
        return self.core.get_mempool_size()

    def get_mempool_stats(self) -> Dict:
        """Get mempool statistics."""
        return self.core.get_mempool_stats()

    def clear_mempool(self) -> int:
        """Clear all transactions."""
        return self.core.clear_mempool()

    def cleanup_expired_transactions(self) -> int:
        """Clean up expired transactions."""
        if hasattr(self.genesis_ops, 'cleanup_mempool'):
            cleanup_stats = self.genesis_ops.cleanup_mempool()
            return cleanup_stats.get('expired_removed', 0)
        else:
            return self.core.cleanup_expired_transactions()

    def get_next_nonce(self, address: str) -> int:
        """Get next expected nonce for address."""
        return self.core.get_next_nonce(address)

    # === Genesis Operations Delegation Methods ===

    def set_ledger(self, ledger: 'Ledger'):
        """Set ledger reference."""
        self.genesis_ops.set_ledger(ledger)

    def set_consensus_engine(self, consensus_engine: 'ConsensusEngine'):
        """Set consensus engine reference."""
        self.genesis_ops.set_consensus_engine(consensus_engine)

    def set_dynamic_fee_calculator(self, calculator: 'DynamicFeeCalculator'):
        """Set dynamic fee calculator reference."""
        self.genesis_ops.set_dynamic_fee_calculator(calculator)

    def sync_with_network(self) -> bool:
        """Sync with network."""
        return self.genesis_ops.sync_with_network()

    def handle_network_transaction(self, transaction: Dict, source_peer: str = None) -> bool:
        """Handle network transaction."""
        return self.genesis_ops.handle_network_transaction(transaction, source_peer)

    def process_consensus_block_transactions(self, block_transactions: List[Dict]) -> int:
        """Process transactions from consensus block."""
        return self.genesis_ops.process_consensus_block_transactions(block_transactions)

    def get_genesis_mempool_status(self) -> Dict:
        """Get genesis mempool status."""
        return self.genesis_ops.get_genesis_mempool_status()

    # === Compatibility Methods for Existing Code ===

    def validate_transaction(self, transaction: Dict) -> Tuple[bool, Optional[str]]:
        """
        Validate a transaction without adding it to mempool.
        """
        # Use enhanced validation if available
        if hasattr(self.genesis_ops, '_enhanced_transaction_validation'):
            return self.genesis_ops._enhanced_transaction_validation(transaction)
        else:
            # Fall back to core validation
            structure_result = self.core._validate_transaction_structure(transaction)
            if not structure_result[0]:
                return structure_result
            return self.core._validate_transaction_content(transaction)

    def get_transaction_priority(self, tx_id: str) -> Optional[float]:
        """
        Get transaction priority.
        """
        transaction = self.get_transaction(tx_id)
        if transaction:
            return self.core._calculate_transaction_priority(transaction)
        return None

    def get_fee_statistics(self) -> Dict:
        """
        Get fee statistics.
        """
        stats = self.get_mempool_stats()
        return stats.get('fee_stats', {})

    def get_sender_transaction_count(self, sender: str) -> int:
        """
        Get number of transactions from a sender.
        """
        transactions = self.get_transactions_by_sender(sender)
        return len(transactions)

    def get_pending_transaction_fees(self) -> List[float]:
        """
        Get list of fees from pending transactions.
        """
        transactions = self.get_pending_transactions(1000)  # Get many transactions
        return [float(tx.get('fee', 0)) for tx in transactions]

    def evict_low_priority_transactions(self, count: int = 1) -> int:
        """
        Evict low priority transactions.
        """
        evicted = 0
        for _ in range(count):
            if self.core._evict_low_priority_transactions():
                evicted += 1
            else:
                break
        return evicted

    def get_mempool_health(self) -> Dict:
        """
        Get mempool health metrics.
        """
        stats = self.get_mempool_stats()
        size = self.get_mempool_size()
        
        health = {
            'current_size': size,
            'max_size': self.max_size,
            'utilization': size / self.max_size if self.max_size > 0 else 0,
            'total_added': stats.get('total_added', 0),
            'total_removed': stats.get('total_removed', 0),
            'rejection_rate': 0
        }
        
        if stats.get('total_added', 0) > 0:
            health['rejection_rate'] = stats.get('rejections', 0) / stats['total_added']
        
        return health

    def force_cleanup(self) -> Dict[str, int]:
        """
        Force comprehensive cleanup.
        """
        if hasattr(self.genesis_ops, 'cleanup_mempool'):
            return self.genesis_ops.cleanup_mempool()
        else:
            expired = self.core.cleanup_expired_transactions()
            return {
                'expired_removed': expired,
                'invalid_removed': 0,
                'cache_cleared': 0,
                'total_remaining': self.get_mempool_size()
            }

    # === Network Integration Methods ===

    def enable_network_sync(self):
        """Enable network synchronization."""
        if hasattr(self.genesis_ops, 'sync_enabled'):
            self.genesis_ops.sync_enabled = True
            self.logger.info("Network sync enabled")

    def disable_network_sync(self):
        """Disable network synchronization."""
        if hasattr(self.genesis_ops, 'sync_enabled'):
            self.genesis_ops.sync_enabled = False
            self.logger.info("Network sync disabled")

    def is_network_sync_enabled(self) -> bool:
        """Check if network sync is enabled."""
        return getattr(self.genesis_ops, 'sync_enabled', False)

    def get_validation_cache_stats(self) -> Dict:
        """Get validation cache statistics."""
        if hasattr(self.genesis_ops, 'validation_cache'):
            return {
                'cache_size': len(self.genesis_ops.validation_cache),
                'cache_enabled': True
            }
        else:
            return {
                'cache_size': 0,
                'cache_enabled': False
            }

    # === Backward Compatibility Properties and Methods ===

    def size(self) -> int:
        """Backward compatibility: get mempool size."""
        return self.get_mempool_size()

    def is_full(self) -> bool:
        """Check if mempool is full."""
        return self.get_mempool_size() >= self.max_size

    def is_empty(self) -> bool:
        """Check if mempool is empty."""
        return self.get_mempool_size() == 0

    def get_all_transactions(self) -> List[Dict]:
        """Get all transactions in mempool."""
        return list(self.transactions.values())

    def contains(self, tx_id: str) -> bool:
        """Check if mempool contains transaction (alias for has_transaction)."""
        return self.has_transaction(tx_id)

    def __len__(self) -> int:
        """Support len() operator."""
        return self.get_mempool_size()

    def __contains__(self, tx_id: str) -> bool:
        """Support 'in' operator."""
        return self.has_transaction(tx_id)

    def __getattr__(self, name):
        """
        Fallback for any attributes not explicitly defined.
        First try core, then genesis_ops.
        """
        if hasattr(self.core, name):
            return getattr(self.core, name)
        elif hasattr(self.genesis_ops, name):
            return getattr(self.genesis_ops, name)
        else:
            raise AttributeError(f"'{self.__class__.__name__}' object has no attribute '{name}'")
