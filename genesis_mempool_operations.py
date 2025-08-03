"""
Genesis Mempool Operations - Network Integration and Special Transaction Handling

This module handles genesis-specific mempool operations including:
- Network transaction broadcasting and synchronization
- Special transaction types (validator registration, governance)
- Integration with consensus engine and ledger
- Dynamic fee calculation and adjustment
"""

import asyncio
import logging
import threading
import time
from typing import Dict, List, Optional, Tuple, TYPE_CHECKING
from decimal import Decimal

if TYPE_CHECKING:
    from ledger import Ledger
    from consensus_engine import ConsensusEngine
    from dynamic_fee_calculator import DynamicFeeCalculator


class GenesisMempoolOperations:
    """
    Handles genesis-specific mempool operations that are not part of
    the core transaction pool management. This includes network integration,
    special transaction handling, and dynamic operations.
    """

    def __init__(
        self,
        mempool_core,
        ledger=None,
        consensus_engine=None,
        dynamic_fee_calculator=None,
        network_manager=None,
        is_genesis_node: bool = False
    ):
        """
        Initialize genesis mempool operations.
        """
        self.mempool_core = mempool_core
        self.ledger = ledger
        self.consensus_engine = consensus_engine
        self.dynamic_fee_calculator = dynamic_fee_calculator
        self.network_manager = network_manager
        self.is_genesis_node = is_genesis_node

        # Genesis-specific state
        self.special_transaction_handlers = {}
        self.transaction_broadcast_queue = asyncio.Queue()
        self.validation_cache = {}
        self.genesis_lock = threading.Lock()

        # Network synchronization
        self.sync_enabled = True
        self.last_sync_time = 0
        self.sync_interval = 30  # seconds

        # Logger
        self.logger = logging.getLogger('GenesisMempoolOps')
        self.logger.setLevel(logging.INFO)
        handler = logging.StreamHandler()
        formatter = logging.Formatter('[%(asctime)s] [%(levelname)s] [%(name)s] %(message)s')
        handler.setFormatter(formatter)
        if not self.logger.handlers:
            self.logger.addHandler(handler)

        self.logger.info(f"GenesisMempoolOperations initialized (genesis_node: {is_genesis_node})")

        # Register special transaction handlers
        self._register_special_transaction_handlers()

    def set_ledger(self, ledger: 'Ledger'):
        """Set the ledger reference."""
        self.ledger = ledger
        self.logger.info("Ledger reference set")

    def set_consensus_engine(self, consensus_engine: 'ConsensusEngine'):
        """Set the consensus engine reference."""
        self.consensus_engine = consensus_engine
        self.logger.info("Consensus engine reference set")

    def set_dynamic_fee_calculator(self, calculator: 'DynamicFeeCalculator'):
        """Set the dynamic fee calculator reference."""
        self.dynamic_fee_calculator = calculator
        self.logger.info("Dynamic fee calculator reference set")

    def add_transaction_with_network_sync(self, transaction: Dict) -> Tuple[bool, Optional[str]]:
        """
        Add a transaction with network synchronization and special handling.
        """
        try:
            # Enhanced validation with ledger integration
            validation_result = self._enhanced_transaction_validation(transaction)
            if not validation_result[0]:
                return validation_result

            # Add to core mempool
            core_result = self.mempool_core.add_transaction(transaction)
            if not core_result[0]:
                return core_result

            # Handle special transaction types
            self._handle_special_transaction_type(transaction)

            # Broadcast to network if enabled
            if self.sync_enabled and self.network_manager:
                self._broadcast_transaction_to_network(transaction)

            # Update dynamic fee calculations
            if self.dynamic_fee_calculator:
                self.dynamic_fee_calculator.update_fee_stats(transaction)

            self.logger.debug(f"Added transaction {transaction['transaction_id']} with network sync")
            return True, None

        except Exception as e:
            self.logger.error(f"Error adding transaction with network sync: {e}")
            return False, f"Network sync error: {str(e)}"

    def remove_transaction_with_cleanup(self, tx_id: str) -> bool:
        """
        Remove a transaction with additional cleanup operations.
        """
        try:
            # Remove from core
            success = self.mempool_core.remove_transaction(tx_id)
            
            if success:
                # Clear from validation cache
                if tx_id in self.validation_cache:
                    del self.validation_cache[tx_id]
                
                # Notify network of removal if needed
                if self.sync_enabled and self.network_manager:
                    removal_message = {
                        'type': 'transaction_removed',
                        'transaction_id': tx_id,
                        'reason': 'processed'
                    }
                    self.network_manager.broadcast_message(removal_message)

                self.logger.debug(f"Removed transaction {tx_id} with cleanup")

            return success

        except Exception as e:
            self.logger.error(f"Error removing transaction with cleanup: {e}")
            return False

    def sync_with_network(self) -> bool:
        """
        Synchronize mempool with network peers.
        """
        if not self.sync_enabled or not self.network_manager:
            return False

        try:
            current_time = time.time()
            if current_time - self.last_sync_time < self.sync_interval:
                return True  # Too soon to sync again

            self.logger.info("Starting mempool network synchronization")

            # Request mempool state from peers
            sync_request = {
                'type': 'mempool_sync_request',
                'current_size': self.mempool_core.get_mempool_size(),
                'request_time': current_time
            }
            self.network_manager.broadcast_message(sync_request)

            self.last_sync_time = current_time
            self.logger.info("Mempool sync request sent")
            return True

        except Exception as e:
            self.logger.error(f"Error syncing with network: {e}")
            return False

    def handle_network_transaction(self, transaction: Dict, source_peer: str = None) -> bool:
        """
        Handle a transaction received from the network.
        """
        try:
            # Verify transaction hasn't been seen before
            tx_id = transaction.get('transaction_id')
            if not tx_id:
                return False

            if self.mempool_core.has_transaction(tx_id):
                self.logger.debug(f"Already have transaction {tx_id}")
                return True

            # Enhanced validation for network transactions
            validation_result = self._enhanced_network_transaction_validation(transaction, source_peer)
            if not validation_result[0]:
                self.logger.warning(f"Network transaction validation failed: {validation_result[1]}")
                return False

            # Add to mempool (without re-broadcasting)
            old_sync_state = self.sync_enabled
            self.sync_enabled = False  # Temporarily disable to prevent re-broadcast
            
            result = self.add_transaction_with_network_sync(transaction)
            
            self.sync_enabled = old_sync_state
            
            if result[0]:
                self.logger.debug(f"Accepted network transaction {tx_id} from {source_peer}")
            
            return result[0]

        except Exception as e:
            self.logger.error(f"Error handling network transaction: {e}")
            return False

    def process_consensus_block_transactions(self, block_transactions: List[Dict]) -> int:
        """
        Process transactions that were included in a consensus block.
        """
        processed_count = 0
        
        try:
            for tx_data in block_transactions:
                tx_id = tx_data.get('transaction_id')
                if tx_id and self.mempool_core.has_transaction(tx_id):
                    if self.remove_transaction_with_cleanup(tx_id):
                        processed_count += 1

            self.logger.info(f"Processed {processed_count} transactions from consensus block")
            return processed_count

        except Exception as e:
            self.logger.error(f"Error processing consensus block transactions: {e}")
            return processed_count

    def get_transactions_for_block(self, max_transactions: int = 100) -> List[Dict]:
        """
        Get optimal transactions for block creation with enhanced selection.
        """
        try:
            # Get base transactions from core
            base_transactions = self.mempool_core.get_pending_transactions(max_transactions * 2)
            
            # Enhanced selection based on network conditions
            selected_transactions = []
            total_fees = Decimal('0')
            
            for transaction in base_transactions:
                if len(selected_transactions) >= max_transactions:
                    break

                # Additional validation for block inclusion
                if self._validate_for_block_inclusion(transaction):
                    selected_transactions.append(transaction)
                    total_fees += Decimal(str(transaction.get('fee', '0')))

            self.logger.debug(f"Selected {len(selected_transactions)} transactions for block (total fees: {total_fees})")
            return selected_transactions

        except Exception as e:
            self.logger.error(f"Error selecting transactions for block: {e}")
            return []

    def cleanup_mempool(self) -> Dict[str, int]:
        """
        Perform comprehensive mempool cleanup.
        """
        cleanup_stats = {
            'expired_removed': 0,
            'invalid_removed': 0,
            'cache_cleared': 0,
            'total_remaining': 0
        }

        try:
            # Clean expired transactions from core
            cleanup_stats['expired_removed'] = self.mempool_core.cleanup_expired_transactions()

            # Clean invalid transactions (re-validate against current ledger state)
            if self.ledger:
                cleanup_stats['invalid_removed'] = self._cleanup_invalid_transactions()

            # Clear validation cache
            cache_size = len(self.validation_cache)
            self.validation_cache.clear()
            cleanup_stats['cache_cleared'] = cache_size

            # Get final size
            cleanup_stats['total_remaining'] = self.mempool_core.get_mempool_size()

            self.logger.info(f"Mempool cleanup completed: {cleanup_stats}")
            return cleanup_stats

        except Exception as e:
            self.logger.error(f"Error during mempool cleanup: {e}")
            return cleanup_stats

    def _enhanced_transaction_validation(self, transaction: Dict) -> Tuple[bool, Optional[str]]:
        """
        Enhanced transaction validation with ledger integration.
        """
        try:
            # Check validation cache first
            tx_id = transaction.get('transaction_id')
            if tx_id in self.validation_cache:
                cached_result = self.validation_cache[tx_id]
                if cached_result['timestamp'] + 300 > time.time():  # 5 minute cache
                    return cached_result['result']

            # Basic core validation
            core_validation = self.mempool_core._validate_transaction_structure(transaction)
            if not core_validation[0]:
                return core_validation

            content_validation = self.mempool_core._validate_transaction_content(transaction)
            if not content_validation[0]:
                return content_validation

            # Enhanced validation with ledger
            if self.ledger:
                ledger_validation = self._validate_against_ledger(transaction)
                if not ledger_validation[0]:
                    return ledger_validation

            # Cache the result
            result = (True, None)
            if tx_id:
                self.validation_cache[tx_id] = {
                    'result': result,
                    'timestamp': time.time()
                }

            return result

        except Exception as e:
            return False, f"Enhanced validation error: {e}"

    def _enhanced_network_transaction_validation(self, transaction: Dict, source_peer: str = None) -> Tuple[bool, Optional[str]]:
        """
        Enhanced validation for transactions received from network.
        """
        try:
            # Basic enhanced validation
            basic_result = self._enhanced_transaction_validation(transaction)
            if not basic_result[0]:
                return basic_result

            # Additional network-specific validation
            # TODO: Add peer reputation checks, rate limiting, etc.
            
            return True, None

        except Exception as e:
            return False, f"Network validation error: {e}"

    def _validate_against_ledger(self, transaction: Dict) -> Tuple[bool, Optional[str]]:
        """
        Validate transaction against current ledger state.
        """
        try:
            from_address = transaction['from_address']
            amount = Decimal(str(transaction['amount']))
            fee = Decimal(str(transaction['fee']))
            total_needed = amount + fee

            # Check account balance
            balance = self.ledger.get_balance(from_address)
            if balance < total_needed:
                return False, f"Insufficient balance: {balance} < {total_needed}"

            # Check account nonce
            account_nonce = self.ledger.get_account_nonce(from_address)
            tx_nonce = int(transaction['nonce'])
            
            if tx_nonce <= account_nonce:
                return False, f"Invalid nonce: {tx_nonce} <= {account_nonce}"

            return True, None

        except Exception as e:
            return False, f"Ledger validation error: {e}"

    def _validate_for_block_inclusion(self, transaction: Dict) -> bool:
        """
        Validate transaction for inclusion in a block.
        """
        try:
            # Check if transaction is still valid against current state
            if self.ledger:
                validation_result = self._validate_against_ledger(transaction)
                if not validation_result[0]:
                    return False

            # Check transaction age (don't include very old transactions)
            # This is handled by the core mempool cleanup, but double-check
            return True

        except Exception as e:
            self.logger.error(f"Error validating for block inclusion: {e}")
            return False

    def _handle_special_transaction_type(self, transaction: Dict):
        """
        Handle special transaction types (validator registration, governance, etc.)
        """
        try:
            tx_type = transaction.get('type', 'transfer')
            
            if tx_type in self.special_transaction_handlers:
                handler = self.special_transaction_handlers[tx_type]
                handler(transaction)
            else:
                # Standard transfer transaction - no special handling needed
                pass

        except Exception as e:
            self.logger.error(f"Error handling special transaction type: {e}")

    def _broadcast_transaction_to_network(self, transaction: Dict):
        """
        Broadcast transaction to network peers.
        """
        try:
            if self.network_manager:
                broadcast_message = {
                    'type': 'new_transaction',
                    'transaction': transaction,
                    'timestamp': time.time()
                }
                self.network_manager.broadcast_message(broadcast_message)
                self.logger.debug(f"Broadcasted transaction {transaction['transaction_id']}")

        except Exception as e:
            self.logger.error(f"Error broadcasting transaction: {e}")

    def _cleanup_invalid_transactions(self) -> int:
        """
        Remove transactions that are no longer valid against current ledger state.
        """
        invalid_count = 0
        
        try:
            all_transactions = []
            for tx_id in list(self.mempool_core.transactions.keys()):
                transaction = self.mempool_core.get_transaction(tx_id)
                if transaction:
                    all_transactions.append(transaction)

            for transaction in all_transactions:
                validation_result = self._validate_against_ledger(transaction)
                if not validation_result[0]:
                    tx_id = transaction['transaction_id']
                    if self.remove_transaction_with_cleanup(tx_id):
                        invalid_count += 1
                        self.logger.debug(f"Removed invalid transaction {tx_id}: {validation_result[1]}")

        except Exception as e:
            self.logger.error(f"Error cleaning invalid transactions: {e}")

        return invalid_count

    def _register_special_transaction_handlers(self):
        """
        Register handlers for special transaction types.
        """
        self.special_transaction_handlers = {
            'validator_registration': self._handle_validator_registration,
            'validator_stake': self._handle_validator_stake,
            'governance_proposal': self._handle_governance_proposal,
            'governance_vote': self._handle_governance_vote
        }

    def _handle_validator_registration(self, transaction: Dict):
        """Handle validator registration transaction."""
        self.logger.info(f"Processing validator registration: {transaction.get('validator_id')}")
        # TODO: Add validator registration logic

    def _handle_validator_stake(self, transaction: Dict):
        """Handle validator staking transaction."""
        self.logger.info(f"Processing validator stake: {transaction.get('amount')}")
        # TODO: Add validator staking logic

    def _handle_governance_proposal(self, transaction: Dict):
        """Handle governance proposal transaction."""
        self.logger.info(f"Processing governance proposal: {transaction.get('proposal_id')}")
        # TODO: Add governance proposal logic

    def _handle_governance_vote(self, transaction: Dict):
        """Handle governance vote transaction."""
        self.logger.info(f"Processing governance vote: {transaction.get('vote')}")
        # TODO: Add governance vote logic

    def get_genesis_mempool_status(self) -> Dict:
        """
        Get genesis mempool status.
        """
        return {
            'is_genesis_node': self.is_genesis_node,
            'sync_enabled': self.sync_enabled,
            'last_sync_time': self.last_sync_time,
            'validation_cache_size': len(self.validation_cache),
            'special_handlers': list(self.special_transaction_handlers.keys()),
            'core_stats': self.mempool_core.get_mempool_stats()
        }
