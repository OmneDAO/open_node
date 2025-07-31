import logging
import threading
import time
import heapq
from typing import List, Dict, Optional, Tuple
from decimal import Decimal
from dateutil import parser  # Ensure python-dateutil is installed

from crypto_utils import CryptoUtils, DecimalEncoder
from dynamic_fee_calculator import DynamicFeeCalculator
from consensus_engine import ConsensusEngine

class Mempool:
    """
    Manages pending transactions awaiting inclusion in blocks.
    Validates fields, ensures nonce/balance correctness, and integrates with
    the ledger for final checks. Supports dynamic sizing and stale‐transaction purging.
    """

    def __init__(
        self,
        crypto_utils: CryptoUtils,
        fee_calculator: DynamicFeeCalculator,
        max_size: int = 1000,
        min_size: int = 500,
        adjustment_interval: int = 60,
        high_activity_threshold: int = 100,
        low_activity_threshold: int = 10,
        stale_time: int = 3600
    ):
        """
        :param crypto_utils: A CryptoUtils instance for signature hashing/verifications.
        :param fee_calculator: DynamicFeeCalculator for applying fee rules if needed.
        :param max_size: Initial maximum capacity of mempool.
        :param min_size: Minimum mempool size to prevent it from shrinking too far.
        :param adjustment_interval: Frequency (seconds) of mempool size self‐adjustment.
        :param high_activity_threshold: If average txs exceed this, the mempool grows.
        :param low_activity_threshold: If average txs dip below, the mempool shrinks.
        :param stale_time: Transactions older than this (seconds) are purged periodically.
        """
        self.transactions: List[Dict] = []
        self.lock = threading.Lock()
        self.crypto_utils = crypto_utils
        self.fee_calculator = fee_calculator

        # References to be set externally to avoid circular imports
        self.consensus_engine: Optional[ConsensusEngine] = None
        self.ledger: Optional['Ledger'] = None

        # Mempool dynamic sizing
        self.max_size = max_size
        self.min_size = min_size
        self.adjustment_interval = adjustment_interval
        self.high_activity_threshold = high_activity_threshold
        self.low_activity_threshold = low_activity_threshold

        # Transaction counting for dynamic resizing
        self.transaction_counts: List[int] = []
        self.current_interval_count = 0

        # Priority queue (max‐heap) for fees:  ( -fee_value, tx_timestamp, tx_dict )
        self.fee_heap: List[Tuple[Decimal, str, Dict]] = []

        # Start background threads for dynamic resizing and stale purge
        self.size_adjustment_thread = threading.Thread(
            target=self._dynamic_size_adjustment_routine, daemon=True
        )
        self.size_adjustment_thread.start()

        self.purging_thread = threading.Thread(
            target=self._purge_stale_transactions_routine, args=(stale_time,), daemon=True
        )
        self.purging_thread.start()

        # Logger
        self.logger = logging.getLogger('Mempool')
        self.logger.info(f"[Mempool] Initialized with max_size={self.max_size}, min_size={self.min_size}.")

    def set_consensus_engine(self, consensus_engine: ConsensusEngine):
        """Sets the reference to the ConsensusEngine (for advanced checks if needed)."""
        self.consensus_engine = consensus_engine
        self.logger.info("[Mempool] ConsensusEngine has been set.")

    def set_ledger(self, ledger: 'Ledger'):
        """Sets the reference to the Ledger (for nonce/balance checks)."""
        self.ledger = ledger
        self.logger.info("[Mempool] Ledger has been set.")

    def add_transaction(self, transaction: Dict) -> Tuple[bool, Optional[str]]:
        """
        Validates the transaction (fields, signature, nonce, balance) and
        adds it to the mempool if valid. Returns (True, tx_hash) on success,
        or (False, None) on failure.
        """
        # Basic classification by 'type'
        required_fields_by_type = {
            "account_creation": ["sender", "balance", "nonce", "public_key", "signature",
                                 "timestamp", "type", "data"],
            "deploy_contract": ["sender", "compiled_code", "abi", "public_key", "signature",
                                "timestamp", "type"],
            "execute_contract": ["sender", "contract_id", "function_name", "args", "public_key",
                                 "nonce", "signature", "timestamp", "type", "data"],
            "transfer": ["sender", "receiver", "amount", "nonce", "timestamp", "fee",
                         "public_key", "signature", "type", "data"],
        }
        tx_type = transaction.get('type')
        if not tx_type:
            self.logger.error("[Mempool] Transaction missing 'type' field.")
            return (False, None)

        required_fields = required_fields_by_type.get(tx_type)
        if required_fields is None:
            self.logger.error(f"[Mempool] Unknown transaction type: {tx_type}")
            return (False, None)

        # Check required fields
        for field in required_fields:
            if transaction.get(field) is None:
                self.logger.error(f"[Mempool] Transaction missing required field: {field}")
                return (False, None)

        # Guarantee 'data' and 'confirmations' exist
        transaction.setdefault('data', {})
        transaction.setdefault('confirmations', "0")

        # Compute & store transaction hash
        tx_hash = self.crypto_utils.calculate_sha256_hash(transaction)
        # If not already present, store the numeric epoch time for stale checks
        # if 'timestamp_unix' not in transaction:
        #     transaction['timestamp_unix'] = time.time()

        self.logger.info(f"[Mempool] Computed local transaction hash: {tx_hash}")

        # Verify signature
        is_valid_sig = self.crypto_utils.verify_transaction(
            transaction.get('public_key'), transaction, transaction.get('signature')
        )
        if not is_valid_sig:
            self.logger.warning(
                f"[Mempool] Transaction {tx_hash} from sender={transaction.get('sender')} "
                f"rejected due to invalid signature."
            )
            return (False, None)

        with self.lock:
            if not self.ledger:
                self.logger.error("[Mempool] Ledger not set, cannot validate nonce/balance.")
                return (False, None)

            # Check nonce in ledger + mempool
            last_confirmed_nonce = self.ledger.account_manager.get_last_nonce(transaction['sender'])
            mempool_nonce = self._get_last_mempool_nonce(transaction['sender'])
            expected_nonce = mempool_nonce + 1

            if str(transaction['nonce']) != str(expected_nonce):
                self.logger.warning(
                    f"[Mempool] Transaction {tx_hash} has invalid nonce. "
                    f"Expected {expected_nonce}, got {transaction['nonce']}."
                )
                return (False, None)

            # Check balance
            ledger_balance = self.ledger.account_manager.get_account_balance(transaction['sender'])
            try:
                if tx_type == "account_creation":
                    amt = Decimal(transaction.get('balance', "0"))
                else:
                    amt = Decimal(transaction.get('amount', "0"))
                fee = Decimal(transaction.get('fee', "0"))
            except Exception as exc:
                self.logger.error(f"[Mempool] Failed converting amounts to Decimal: {exc}")
                return (False, None)

            if ledger_balance < (amt + fee):
                self.logger.warning(
                    f"[Mempool] Transaction {tx_hash} from {transaction['sender']} "
                    f"rejected (Insufficient balance: {ledger_balance} < {amt+fee})."
                )
                return (False, None)

            # Check mempool capacity
            if len(self.transactions) >= self.max_size:
                if self.fee_heap:
                    # Compare fees
                    lowest_fee_item = self.fee_heap[0]  # ( -fee_val, timestamp, tx_dict )
                    lowest_fee_val = -lowest_fee_item[0]
                    if fee > lowest_fee_val:
                        # remove the low‐fee tx
                        _, _, old_tx = heapq.heappop(self.fee_heap)
                        self.transactions.remove(old_tx)
                        self.logger.info(
                            f"[Mempool] Removed transaction {old_tx.get('hash')} to fit higher fee TX {tx_hash}."
                        )
                    else:
                        self.logger.warning(f"[Mempool] Full. TX {tx_hash} with fee={fee} is rejected.")
                        return (False, None)
                else:
                    self.logger.warning(f"[Mempool] Full, no fee_heap. TX {tx_hash} is rejected.")
                    return (False, None)

            # All checks pass -> add transaction
            transaction['hash'] = tx_hash
            self.transactions.append(transaction)
            heapq.heappush(self.fee_heap, (-fee, transaction['timestamp'], transaction))
            self.current_interval_count += 1
            self.logger.info(f"[Mempool] Transaction {tx_hash} successfully added.")
        return (True, tx_hash)

    def _get_last_mempool_nonce(self, sender: str) -> int:
        """
        Checks all mempool transactions for 'sender' to find the highest nonce used so far.
        Then compares with ledger's last confirmed nonce, returning the max.
        """
        mempool_txs = [tx for tx in self.transactions if tx.get('sender') == sender]
        ledger_nonce = self.ledger.account_manager.get_last_nonce(sender)
        if not mempool_txs:
            return ledger_nonce
        highest_mempool_nonce = max(int(tx.get('nonce', ledger_nonce)) for tx in mempool_txs)
        return max(ledger_nonce, highest_mempool_nonce)

    def remove_transaction(self, tx_hash: str) -> bool:
        """
        Removes a single transaction matching tx_hash from the mempool and fee_heap.
        """
        with self.lock:
            for tx in self.transactions:
                if tx.get('hash') == tx_hash:
                    self.transactions.remove(tx)
                    # Also remove from fee_heap
                    self.fee_heap = [
                        item for item in self.fee_heap if item[2].get('hash') != tx_hash
                    ]
                    heapq.heapify(self.fee_heap)
                    self.logger.info(f"[Mempool] Transaction {tx_hash} removed.")
                    return True
        self.logger.warning(f"[Mempool] Transaction {tx_hash} not found for removal.")
        return False

    def remove_transactions(self, tx_list: List[Dict]) -> None:
        """
        Removes multiple transactions, typically after they are included in a block.
        Matching is by 'hash' to ensure exact removal.
        """
        with self.lock:
            for tx in tx_list:
                h = tx.get('hash')
                if h:
                    self.remove_transaction(h)

    def get_transactions(self) -> List[Dict]:
        """
        Returns all transactions in the mempool, sorted by descending fee.
        """
        with self.lock:
            return sorted(self.transactions, key=lambda tx: Decimal(tx.get('fee', '0')), reverse=True)

    def get_transactions_for_block(self, max_block_txs: int = 500, max_block_size: int = 1_000_000) -> List[Dict]:
        """
        Retrieves up to `max_block_txs` transactions from the mempool, sorted by highest fee.
        If `size` is tracked per TX, skip any that would exceed `max_block_size`.
        """
        with self.lock:
            sorted_by_fee = self.get_transactions()  # already sorted desc by fee
            chosen = []
            total_size = 0
            for tx in sorted_by_fee:
                tx_size = tx.get('size', 250)  # default or actual size
                if len(chosen) < max_block_txs and (total_size + tx_size) <= max_block_size:
                    chosen.append(tx)
                    total_size += tx_size
                else:
                    break
            return chosen

    def drain_verified_transactions(self) -> List[Dict]:
        """
        Empties the mempool, returning all transactions in descending fee order.
        Normally used in dev/test scenarios.
        """
        with self.lock:
            txs = self.get_transactions()  # sorted desc
            self.transactions.clear()
            self.fee_heap.clear()
            self.current_interval_count += len(txs)
            self.logger.info(f"[Mempool] Drained {len(txs)} transactions.")
            return txs

    def return_transactions(self, transactions: List[Dict]) -> None:
        """
        Re‐adds transactions to the mempool if block creation fails. Typically verifies
        signature, ledger state (balance/nonce) again, and discards if not valid anymore.
        """
        with self.lock:
            for tx in transactions:
                h = tx.get('hash')
                if not h:
                    self.logger.warning("[Mempool] Transaction missing 'hash' field on return. Skipped.")
                    continue
                # Check duplicates
                if any(existing.get('hash') == h for existing in self.transactions):
                    self.logger.warning(f"[Mempool] Duplicate TX {h} detected. Skipped re‐add.")
                    continue

                if not self.ledger:
                    self.logger.error("[Mempool] Ledger not set; cannot re‐verify transaction.")
                    continue

                # Quick balance check
                sender_balance = self.ledger.account_manager.get_account_balance(tx.get('sender'))
                if tx.get('type') == 'account_creation':
                    amt = Decimal(tx.get('balance', '0'))
                else:
                    amt = Decimal(tx.get('amount', '0'))
                fee_val = Decimal(tx.get('fee', '0'))
                if sender_balance < (amt + fee_val):
                    self.logger.warning(f"[Mempool] TX {h} re‐add failed (insufficient balance).")
                    continue

                # Re‐verify signature
                if not self.crypto_utils.verify_transaction(tx.get('public_key'), tx, tx.get('signature')):
                    self.logger.warning(f"[Mempool] Invalid signature on re‐add for TX {h}.")
                    continue

                # If you'd like, recheck consensus_engine validations
                # (Not mandatory if ledger checks are enough.)
                if self.consensus_engine and not self.consensus_engine.validate_transaction(tx):
                    self.logger.warning(f"[Mempool] TX {h} rejected by consensus engine on re‐add.")
                    continue

                # Passed all => push
                self.transactions.append(tx)
                heapq.heappush(self.fee_heap, (-fee_val, tx.get('timestamp', ''), tx))
                self.logger.debug(f"[Mempool] TX {h} re‐added to mempool.")

    def has_transactions(self) -> bool:
        with self.lock:
            return bool(self.transactions)

    def get_transaction_count(self) -> int:
        with self.lock:
            return len(self.transactions)

    def clear_mempool(self):
        """Empties the mempool entirely."""
        with self.lock:
            self.transactions.clear()
            self.fee_heap.clear()
            self.current_interval_count = 0
            self.logger.info("[Mempool] Cleared all transactions from the mempool.")

    def _dynamic_size_adjustment_routine(self):
        """
        Periodically updates self.max_size based on transaction activity in the last intervals.
        """
        while True:
            time.sleep(self.adjustment_interval)
            with self.lock:
                self.transaction_counts.append(self.current_interval_count)
                # Look at last 5 intervals (or fewer if not enough data)
                recent_counts = self.transaction_counts[-5:]
                avg_txs = sum(recent_counts) / len(recent_counts) if recent_counts else 0
                self.logger.info(f"[Mempool] Average transactions per interval: {avg_txs}")

                if avg_txs > self.high_activity_threshold and self.max_size < 5000:
                    old_size = self.max_size
                    self.max_size = min(self.max_size + 1000, 5000)
                    self.logger.info(
                        f"[Mempool] High activity -> Increased mempool max_size from {old_size} to {self.max_size}."
                    )
                elif avg_txs < self.low_activity_threshold and self.max_size > self.min_size:
                    old_size = self.max_size
                    self.max_size = max(self.max_size - 500, self.min_size)
                    # Optionally remove excess if over new max
                    if len(self.transactions) > self.max_size:
                        excess = len(self.transactions) - self.max_size
                        for _ in range(excess):
                            if self.fee_heap:
                                _, _, low_fee_tx = heapq.heappop(self.fee_heap)
                                self.transactions.remove(low_fee_tx)
                        self.logger.info(
                            f"[Mempool] Decreased max_size from {old_size} to {self.max_size}. "
                            f"Removed {excess} low‐fee transactions."
                        )
                else:
                    self.logger.info(
                        f"[Mempool] Mempool size remains at {self.max_size}."
                    )

                self.current_interval_count = 0

    def _purge_stale_transactions_routine(self, stale_time: int):
        """
        Purges transactions older than stale_time seconds. Needs 'timestamp_unix' in each TX.
        """
        while True:
            time.sleep(stale_time)
            with self.lock:
                now = time.time()
                original_count = len(self.transactions)
                self.transactions = [
                    tx for tx in self.transactions
                    if (now - tx.get('timestamp_unix', now)) <= stale_time
                ]
                # Rebuild fee_heap
                self.fee_heap = []
                for tx in self.transactions:
                    fee_decimal = Decimal(tx.get('fee', '0'))
                    heapq.heappush(self.fee_heap, (-fee_decimal, tx.get('timestamp', ''), tx))
                purged = original_count - len(self.transactions)
                if purged > 0:
                    self.logger.info(f"[Mempool] Purged {purged} stale TXs older than {stale_time}s.")

    def get_high_priority_transactions(self, count: int) -> List[Dict]:
        """
        Returns up to 'count' highest‐fee transactions from the mempool.
        """
        with self.lock:
            top_items = heapq.nsmallest(count, self.fee_heap)
            return [entry[2] for entry in top_items]

    def shutdown(self):
        """
        Gracefully shuts down the mempool. Daemon threads will exit automatically.
        """
        self.logger.info("[Mempool] Shutting down mempool.")
        # Additional cleanup if needed
