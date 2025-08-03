"""
Mempool Core - Pure Transaction Pool Management

This module contains the core mempool functionality that must be identical
across all node types for nexum validation. Genesis and network-specific
operations are handled by separate classes.
"""

import heapq
import logging
import threading
import time
from decimal import Decimal
from typing import Dict, List, Optional, Tuple
from datetime import datetime
from dateutil import parser

from crypto_utils import CryptoUtils


class MempoolCore:
    """
    Pure mempool core containing only essential transaction pool management.
    
    This class contains the core transaction validation and ordering logic
    that must be identical across all node types. Network operations and
    genesis-specific functionality are handled by separate components.
    """

    def __init__(
        self,
        max_size: int = 1000,
        min_size: int = 100,
        max_priority_age_hours: int = 6
    ):
        """
        Initialize the pure mempool core.
        """
        self.max_size = max_size
        self.min_size = min_size
        self.max_priority_age_hours = max_priority_age_hours

        # Core transaction storage
        self.transactions = {}  # tx_id -> transaction
        self.pending_queue = []  # Priority heap: (-priority, tx_id)
        self.mempool_lock = threading.Lock()
        
        # Transaction indexing
        self.sender_transactions = {}  # sender -> [tx_ids]
        self.receiver_transactions = {}  # receiver -> [tx_ids]
        self.nonce_tracking = {}  # sender -> highest_nonce
        
        # Fee and priority tracking
        self.fee_stats = {
            'min_fee': Decimal('0.001'),
            'avg_fee': Decimal('0.01'),
            'max_fee': Decimal('1.0'),
            'total_fees': Decimal('0')
        }
        
        # Core utilities
        self.crypto_utils = CryptoUtils()
        
        # Metrics
        self.stats = {
            'total_added': 0,
            'total_removed': 0,
            'rejections': 0,
            'current_size': 0
        }

        # Logger
        self.logger = logging.getLogger('MempoolCore')
        self.logger.setLevel(logging.INFO)
        handler = logging.StreamHandler()
        formatter = logging.Formatter('[%(asctime)s] [%(levelname)s] [%(name)s] %(message)s')
        handler.setFormatter(formatter)
        if not self.logger.handlers:
            self.logger.addHandler(handler)

        self.logger.info(f"MempoolCore initialized (max_size: {max_size})")

    def add_transaction(self, transaction: Dict) -> Tuple[bool, Optional[str]]:
        """
        Add a transaction to the mempool core.
        
        Args:
            transaction: Transaction dictionary
            
        Returns:
            Tuple of (success, error_message)
        """
        with self.mempool_lock:
            try:
                # Validate transaction structure
                validation_result = self._validate_transaction_structure(transaction)
                if not validation_result[0]:
                    self.stats['rejections'] += 1
                    return validation_result

                tx_id = transaction['transaction_id']
                
                # Check if transaction already exists
                if tx_id in self.transactions:
                    return False, f"Transaction {tx_id} already in mempool"

                # Validate transaction content
                content_validation = self._validate_transaction_content(transaction)
                if not content_validation[0]:
                    self.stats['rejections'] += 1
                    return content_validation

                # Check mempool capacity
                if len(self.transactions) >= self.max_size:
                    # Try to evict low-priority transactions
                    if not self._evict_low_priority_transactions():
                        self.stats['rejections'] += 1
                        return False, "Mempool full and cannot evict transactions"

                # Calculate transaction priority
                priority = self._calculate_transaction_priority(transaction)
                
                # Add to storage
                self.transactions[tx_id] = transaction
                heapq.heappush(self.pending_queue, (-priority, tx_id))
                
                # Update indices
                self._update_transaction_indices(transaction)
                
                # Update statistics
                self.stats['total_added'] += 1
                self.stats['current_size'] = len(self.transactions)
                self._update_fee_stats(transaction)
                
                self.logger.debug(f"Added transaction {tx_id} with priority {priority}")
                return True, None
                
            except Exception as e:
                self.logger.error(f"Error adding transaction: {e}")
                self.stats['rejections'] += 1
                return False, f"Internal error: {str(e)}"

    def remove_transaction(self, tx_id: str) -> bool:
        """
        Remove a transaction from the mempool core.
        """
        with self.mempool_lock:
            try:
                if tx_id not in self.transactions:
                    return False
                
                transaction = self.transactions[tx_id]
                
                # Remove from storage
                del self.transactions[tx_id]
                
                # Remove from priority queue (will be cleaned up during iteration)
                # Note: heapq doesn't support efficient removal, so we mark as removed
                
                # Update indices
                self._remove_from_indices(transaction)
                
                # Update statistics
                self.stats['total_removed'] += 1
                self.stats['current_size'] = len(self.transactions)
                
                self.logger.debug(f"Removed transaction {tx_id}")
                return True
                
            except Exception as e:
                self.logger.error(f"Error removing transaction {tx_id}: {e}")
                return False

    def get_pending_transactions(self, limit: int = 100) -> List[Dict]:
        """
        Get pending transactions ordered by priority.
        """
        with self.mempool_lock:
            transactions = []
            temp_queue = []
            
            # Extract transactions from priority queue
            while self.pending_queue and len(transactions) < limit:
                priority, tx_id = heapq.heappop(self.pending_queue)
                
                if tx_id in self.transactions:
                    transactions.append(self.transactions[tx_id])
                    temp_queue.append((priority, tx_id))
                # If tx_id not in transactions, it was removed - skip it
            
            # Restore the queue
            for item in temp_queue:
                heapq.heappush(self.pending_queue, item)
            
            return transactions

    def get_transactions_by_sender(self, sender: str) -> List[Dict]:
        """
        Get all transactions from a specific sender.
        """
        with self.mempool_lock:
            tx_ids = self.sender_transactions.get(sender, [])
            return [self.transactions[tx_id] for tx_id in tx_ids if tx_id in self.transactions]

    def get_transactions_by_receiver(self, receiver: str) -> List[Dict]:
        """
        Get all transactions to a specific receiver.
        """
        with self.mempool_lock:
            tx_ids = self.receiver_transactions.get(receiver, [])
            return [self.transactions[tx_id] for tx_id in tx_ids if tx_id in self.transactions]

    def has_transaction(self, tx_id: str) -> bool:
        """
        Check if a transaction exists in the mempool.
        """
        with self.mempool_lock:
            return tx_id in self.transactions

    def get_transaction(self, tx_id: str) -> Optional[Dict]:
        """
        Get a specific transaction by ID.
        """
        with self.mempool_lock:
            return self.transactions.get(tx_id)

    def get_mempool_size(self) -> int:
        """
        Get current mempool size.
        """
        with self.mempool_lock:
            return len(self.transactions)

    def get_mempool_stats(self) -> Dict:
        """
        Get mempool statistics.
        """
        with self.mempool_lock:
            return {
                **self.stats,
                'fee_stats': self.fee_stats.copy(),
                'max_size': self.max_size,
                'min_size': self.min_size
            }

    def clear_mempool(self) -> int:
        """
        Clear all transactions from mempool.
        """
        with self.mempool_lock:
            count = len(self.transactions)
            self.transactions.clear()
            self.pending_queue.clear()
            self.sender_transactions.clear()
            self.receiver_transactions.clear()
            self.nonce_tracking.clear()
            
            self.stats['current_size'] = 0
            
            self.logger.info(f"Cleared {count} transactions from mempool")
            return count

    def _validate_transaction_structure(self, transaction: Dict) -> Tuple[bool, Optional[str]]:
        """
        Validate basic transaction structure.
        """
        required_fields = [
            'transaction_id', 'from_address', 'to_address', 
            'amount', 'fee', 'timestamp', 'nonce'
        ]
        
        for field in required_fields:
            if field not in transaction:
                return False, f"Missing required field: {field}"
        
        # Validate field types
        try:
            Decimal(str(transaction['amount']))
            Decimal(str(transaction['fee']))
            int(transaction['nonce'])
            parser.parse(transaction['timestamp'])
        except (ValueError, TypeError) as e:
            return False, f"Invalid field format: {e}"
        
        return True, None

    def _validate_transaction_content(self, transaction: Dict) -> Tuple[bool, Optional[str]]:
        """
        Validate transaction content and logic.
        """
        try:
            # Validate amounts
            amount = Decimal(str(transaction['amount']))
            fee = Decimal(str(transaction['fee']))
            
            if amount <= 0:
                return False, "Amount must be positive"
            
            if fee < 0:
                return False, "Fee cannot be negative"
            
            # Validate addresses
            from_address = transaction['from_address']
            to_address = transaction['to_address']
            
            if from_address == to_address:
                return False, "Cannot send to same address"
            
            # Validate nonce ordering
            nonce = int(transaction['nonce'])
            sender_highest_nonce = self.nonce_tracking.get(from_address, -1)
            
            if nonce <= sender_highest_nonce:
                return False, f"Invalid nonce: {nonce} <= {sender_highest_nonce}"
            
            # Validate timestamp (not too old or too far in future)
            tx_time = parser.parse(transaction['timestamp'])
            now = datetime.now(tx_time.tzinfo)
            age_hours = (now - tx_time).total_seconds() / 3600
            
            if age_hours > 24:  # Too old
                return False, "Transaction too old"
            
            if age_hours < -1:  # Too far in future
                return False, "Transaction timestamp too far in future"
            
            return True, None
            
        except Exception as e:
            return False, f"Validation error: {e}"

    def _calculate_transaction_priority(self, transaction: Dict) -> float:
        """
        Calculate transaction priority based on fee and age.
        """
        try:
            fee = float(Decimal(str(transaction['fee'])))
            amount = float(Decimal(str(transaction['amount'])))
            
            # Base priority from fee rate
            fee_rate = fee / amount if amount > 0 else fee
            priority = fee_rate * 1000  # Scale up
            
            # Age bonus (older transactions get slight priority boost)
            tx_time = parser.parse(transaction['timestamp'])
            now = datetime.now(tx_time.tzinfo)
            age_hours = (now - tx_time).total_seconds() / 3600
            
            if age_hours > 0:
                age_bonus = min(age_hours * 0.1, 1.0)  # Max 1.0 bonus
                priority += age_bonus
            
            return max(priority, 0.001)  # Minimum priority
            
        except Exception as e:
            self.logger.error(f"Error calculating priority: {e}")
            return 0.001

    def _update_transaction_indices(self, transaction: Dict):
        """
        Update transaction indices for efficient lookup.
        """
        tx_id = transaction['transaction_id']
        from_address = transaction['from_address']
        to_address = transaction['to_address']
        nonce = int(transaction['nonce'])
        
        # Update sender index
        if from_address not in self.sender_transactions:
            self.sender_transactions[from_address] = []
        self.sender_transactions[from_address].append(tx_id)
        
        # Update receiver index
        if to_address not in self.receiver_transactions:
            self.receiver_transactions[to_address] = []
        self.receiver_transactions[to_address].append(tx_id)
        
        # Update nonce tracking
        self.nonce_tracking[from_address] = max(
            self.nonce_tracking.get(from_address, -1), 
            nonce
        )

    def _remove_from_indices(self, transaction: Dict):
        """
        Remove transaction from indices.
        """
        tx_id = transaction['transaction_id']
        from_address = transaction['from_address']
        to_address = transaction['to_address']
        
        # Remove from sender index
        if from_address in self.sender_transactions:
            if tx_id in self.sender_transactions[from_address]:
                self.sender_transactions[from_address].remove(tx_id)
            if not self.sender_transactions[from_address]:
                del self.sender_transactions[from_address]
        
        # Remove from receiver index
        if to_address in self.receiver_transactions:
            if tx_id in self.receiver_transactions[to_address]:
                self.receiver_transactions[to_address].remove(tx_id)
            if not self.receiver_transactions[to_address]:
                del self.receiver_transactions[to_address]

    def _update_fee_stats(self, transaction: Dict):
        """
        Update fee statistics.
        """
        try:
            fee = Decimal(str(transaction['fee']))
            
            self.fee_stats['total_fees'] += fee
            self.fee_stats['min_fee'] = min(self.fee_stats['min_fee'], fee)
            self.fee_stats['max_fee'] = max(self.fee_stats['max_fee'], fee)
            
            # Recalculate average (simple running average)
            total_txs = self.stats['total_added']
            if total_txs > 0:
                self.fee_stats['avg_fee'] = self.fee_stats['total_fees'] / total_txs
                
        except Exception as e:
            self.logger.error(f"Error updating fee stats: {e}")

    def _evict_low_priority_transactions(self) -> bool:
        """
        Evict lowest priority transactions to make room.
        """
        try:
            # Find lowest priority transactions
            if len(self.transactions) < self.min_size:
                return False  # Don't evict if below minimum
            
            # Remove the lowest priority transaction
            if self.pending_queue:
                # Find the actual lowest priority (highest negative value)
                temp_items = []
                removed = False
                
                while self.pending_queue and not removed:
                    priority, tx_id = heapq.heappop(self.pending_queue)
                    
                    if tx_id in self.transactions:
                        # This is the lowest priority active transaction
                        self.remove_transaction(tx_id)
                        removed = True
                        self.logger.debug(f"Evicted low priority transaction {tx_id}")
                    else:
                        # Transaction was already removed, continue
                        continue
                
                # Restore remaining items
                for item in temp_items:
                    heapq.heappush(self.pending_queue, item)
                
                return removed
            
            return False
            
        except Exception as e:
            self.logger.error(f"Error evicting transactions: {e}")
            return False

    def cleanup_expired_transactions(self) -> int:
        """
        Remove transactions that have been in mempool too long.
        """
        with self.mempool_lock:
            expired_count = 0
            now = datetime.now()
            
            expired_tx_ids = []
            
            for tx_id, transaction in self.transactions.items():
                try:
                    tx_time = parser.parse(transaction['timestamp'])
                    age_hours = (now - tx_time.replace(tzinfo=None)).total_seconds() / 3600
                    
                    if age_hours > self.max_priority_age_hours:
                        expired_tx_ids.append(tx_id)
                        
                except Exception as e:
                    self.logger.error(f"Error checking transaction age for {tx_id}: {e}")
                    expired_tx_ids.append(tx_id)  # Remove problematic transactions
            
            # Remove expired transactions
            for tx_id in expired_tx_ids:
                if self.remove_transaction(tx_id):
                    expired_count += 1
            
            if expired_count > 0:
                self.logger.info(f"Cleaned up {expired_count} expired transactions")
            
            return expired_count

    def get_next_nonce(self, address: str) -> int:
        """
        Get the next expected nonce for an address.
        """
        with self.mempool_lock:
            return self.nonce_tracking.get(address, -1) + 1
