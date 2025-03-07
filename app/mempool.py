# mempool.py

import logging
import threading
from typing import List, Dict, Optional
from decimal import Decimal, InvalidOperation
import hashlib
import json
import heapq
import time
from dateutil import parser  # Ensure dateutil is installed

from crypto_utils import CryptoUtils, DecimalEncoder
from dynamic_fee_calculator import DynamicFeeCalculator
from consensus_engine import ConsensusEngine  # For consensus-specific validations

class Mempool:
    """
    Manages pending transactions awaiting inclusion in blocks.
    Ensures transactions are valid by verifying sender's balance, nonce, signature, and consensus-specific criteria.
    Includes performance optimizations like dynamic sizing, fee prioritization, and purging stale transactions.
    """

    def __init__(
        self,
        crypto_utils: CryptoUtils,
        fee_calculator: DynamicFeeCalculator,
        max_size: int = 1000,  # Initial max size
        min_size: int = 500,    # Minimum mempool size to prevent too small pools
        adjustment_interval: int = 60,  # Seconds between size adjustments
        high_activity_threshold: int = 100,  # Transactions per adjustment interval to consider high activity
        low_activity_threshold: int = 10,     # Transactions per adjustment interval to consider low activity
        stale_time: int = 3600                # Seconds after which transactions are considered stale
    ):
        """
        :param crypto_utils: Instance of CryptoUtils for cryptographic operations.
        :param fee_calculator: Instance of DynamicFeeCalculator for fee calculations.
        :param max_size: Initial maximum number of transactions the mempool can hold.
        :param min_size: Minimum mempool size to prevent it from becoming too small.
        :param adjustment_interval: Time in seconds between dynamic size adjustments.
        :param high_activity_threshold: Transaction count to trigger mempool size increase.
        :param low_activity_threshold: Transaction count to trigger mempool size decrease.
        :param stale_time: Time in seconds after which transactions are considered stale.
        """
        self.transactions: List[Dict] = []
        self.lock = threading.Lock()
        self.crypto_utils = crypto_utils
        self.fee_calculator = fee_calculator

        # ConsensusEngine reference, to be set via setter to avoid circular import
        self.consensus_engine: Optional[ConsensusEngine] = None

        # Ledger reference, to be set via setter to avoid circular import
        self.ledger: Optional['Ledger'] = None

        # Dynamic sizing parameters
        self.max_size = max_size
        self.min_size = min_size
        self.adjustment_interval = adjustment_interval
        self.high_activity_threshold = high_activity_threshold
        self.low_activity_threshold = low_activity_threshold

        # For tracking transaction counts in each interval
        self.transaction_counts: List[int] = []
        self.current_interval_count = 0

        # For prioritizing transactions by fee (max-heap)
        self.fee_heap: List[tuple] = []  # List of tuples (-fee, timestamp, transaction)

        # Start the dynamic sizing thread
        self.size_adjustment_thread = threading.Thread(target=self._dynamic_size_adjustment_routine, daemon=True)
        self.size_adjustment_thread.start()

        # Start the stale transaction purging thread
        self.purging_thread = threading.Thread(target=self._purge_stale_transactions_routine, args=(stale_time,), daemon=True)
        self.purging_thread.start()

        # Initialize logger
        self.logger = logging.getLogger('Mempool')
        self.logger.info(f"[Mempool] Initialized with max_size={self.max_size}, min_size={self.min_size}.")

    def set_consensus_engine(self, consensus_engine: ConsensusEngine):
        """
        Sets the ConsensusEngine instance for consensus-specific validations.
        """
        self.consensus_engine = consensus_engine
        self.logger.info("[Mempool] ConsensusEngine has been set.")

    def set_ledger(self, ledger: 'Ledger'):
        """
        Sets the Ledger instance to allow interaction with the blockchain state.
        """
        self.ledger = ledger
        self.logger.info("[Mempool] Ledger has been set.")

    def compute_tx_hash(self, transaction: Dict) -> str:
        # Core keys always included.
        canonical_keys = ["sender", "type", "nonce", "timestamp", "fee", "public_key"]
        
        # For the transaction amount, include 'amount' if it exists; otherwise, include 'balance'
        if "amount" in transaction:
            canonical_keys.append("amount")
        elif "balance" in transaction:
            canonical_keys.append("balance")
        
        # If there is a metadata object, include its keys.
        metadata = transaction.get("metadata", {})
        # For future-proofing, you can merge the metadata into the canonical payload.
        for key in metadata:
            canonical_keys.append(key)
        
        # Remove duplicates (if any) and sort the final list.
        canonical_keys = sorted(set(canonical_keys))
        
        # Build the canonical dictionary. We also include any additional top-level keys if needed.
        canonical_data = { key: str(transaction[key]) for key in canonical_keys if key in transaction }
        # Merge metadata into canonical_data (if keys overlap, you could decide whether metadata overrides or not)
        for key, value in metadata.items():
            canonical_data[key] = str(value)
        
        # Serialize with compact separators for consistency.
        canonical_string = json.dumps(canonical_data, sort_keys=True, separators=(',', ':'))
        return hashlib.sha256(canonical_string.encode('utf-8')).hexdigest()

    def add_transaction(self, transaction: Dict) -> bool:
        """
        Adds a transaction to the mempool after validating balance, nonce, signature,
        and consensus-specific criteria.
        """
        sender = transaction.get('sender')
        receiver = transaction.get('receiver')
        amount = transaction.get('amount')
        balance = transaction.get('balance')
        fee = transaction.get('fee', '0')
        nonce = transaction.get('nonce')
        public_key = transaction.get('public_key')
        signature = transaction.get('signature')
        timestamp = transaction.get('timestamp')
        tx_type = transaction.get('type', '')
        
        # For "account_creation" transactions, we do not use 'receiver' or 'amount'
        if tx_type == 'account_creation':
            required_fields = [sender, balance, nonce, public_key, signature]
        else:
            required_fields = [sender, receiver, amount, public_key, nonce, signature]
        
        if any(field is None for field in required_fields):
            self.logger.error("[Mempool] Transaction is missing required fields (one is None).")
            return False
        
        try:
            if tx_type == 'account_creation':
                amount = Decimal(str(balance))
            else:
                amount = Decimal(str(amount))
            fee = Decimal(str(fee))
            nonce = int(nonce)
        except (ValueError, InvalidOperation) as e:
            self.logger.error(f"[Mempool] Invalid transaction amount or nonce: {e}")
            return False
        
        # Ensure the transaction includes a 'data' field (required)
        if 'data' not in transaction:
            transaction['data'] = {}
        
        # Optionally, ensure that 'confirmations' is set (default to 0).
        if 'confirmations' not in transaction:
            transaction['confirmations'] = 0
        
        # Compute transaction hash using our canonicalization method.
        tx_hash = self.compute_tx_hash(transaction)
        transaction['hash'] = tx_hash
        
        transaction['timestamp'] = timestamp  # preserve incoming timestamp
        
        # Build the canonical payload for signature verification.
        canonical_payload = json.dumps(
            {k: transaction[k] for k in sorted(transaction) if k not in ['signature', 'hash']},
            sort_keys=True,
            cls=DecimalEncoder,
            separators=(',', ':')
        )
        
        # Verify the signature using the canonical payload.
        if not self.crypto_utils.verify_signature(
                transaction.get('public_key'), canonical_payload, signature):
            self.logger.warning(f"[Mempool] Transaction {tx_hash} from {sender} rejected due to invalid signature.")
            return False
        
        # (Optional: consensus-specific validation here.)
        
        with self.lock:
            if not self.ledger:
                self.logger.error("[Mempool] Ledger not set. Cannot validate transaction against ledger state.")
                return False
            
            last_confirmed_nonce = self.ledger.account_manager.get_last_nonce(sender)
            last_mempool_nonce = self._get_last_mempool_nonce(sender)
            expected_nonce = last_mempool_nonce + 1
            if nonce != expected_nonce:
                self.logger.warning(
                    f"[Mempool] Transaction {tx_hash} from {sender} has invalid nonce. Expected: {expected_nonce}, Got: {nonce}."
                )
                return False
            
            balance_on_ledger = self.ledger.account_manager.get_account_balance(sender)
            if balance_on_ledger < (amount + fee):
                self.logger.warning(
                    f"[Mempool] Transaction {tx_hash} from {sender} rejected due to insufficient balance. "
                    f"Balance: {balance_on_ledger}, Required: {amount + fee}."
                )
                return False
            
            if len(self.transactions) >= self.max_size:
                if self.fee_heap:
                    lowest_fee_tx = self.fee_heap[0][2]
                    lowest_fee = self.fee_heap[0][0]
                    if fee > (-lowest_fee):
                        _, _, tx_to_remove = heapq.heappop(self.fee_heap)
                        self.transactions.remove(tx_to_remove)
                        self.logger.info(f"[Mempool] Removed transaction {tx_to_remove['hash']} to make space for higher fee transaction.")
                    else:
                        self.logger.warning(f"[Mempool] Mempool full. Transaction {tx_hash} with fee {fee} rejected.")
                        return False
                else:
                    self.logger.warning(f"[Mempool] Mempool full. Transaction {tx_hash} rejected.")
                    return False
            
            self.transactions.append(transaction)
            heapq.heappush(self.fee_heap, (-fee, transaction['timestamp'], transaction))
            self.current_interval_count += 1
            self.logger.info(f"[Mempool] Transaction {tx_hash} from {sender} added to mempool with fee {fee}.")
            return True
                        
    def _get_last_mempool_nonce(self, sender: str) -> int:
        """
        Retrieves the last nonce for a sender within the mempool.
        If the sender is involved in a staking contract, checks the last staking transaction nonce.
        """
        mempool_transactions = [tx for tx in self.transactions if tx['sender'] == sender]

        # Find the last confirmed nonce from the ledger
        last_confirmed_nonce = self.ledger.account_manager.get_last_nonce(sender)

        # If there are staking transactions, check their last nonce
        staking_transactions = [tx for tx in mempool_transactions if tx.get('type') == 'staking']
        
        if staking_transactions:
            # Find highest nonce in staking transactions
            return max(tx['nonce'] for tx in staking_transactions)

        # Otherwise, return the highest nonce in normal transactions
        return max([tx['nonce'] for tx in mempool_transactions], default=last_confirmed_nonce)

    def remove_transaction(self, tx_hash: str) -> bool:
        """
        Removes a transaction from the mempool based on its hash.

        :param tx_hash: The hash of the transaction to remove.
        :return: True if transaction was found and removed, False otherwise.
        """
        with self.lock:
            for tx in self.transactions:
                if tx['hash'] == tx_hash:
                    self.transactions.remove(tx)
                    # Remove from fee heap
                    for idx, item in enumerate(self.fee_heap):
                        if item[2]['hash'] == tx_hash:
                            del self.fee_heap[idx]
                            heapq.heapify(self.fee_heap)
                            break
                    self.logger.info(f"[Mempool] Transaction {tx_hash} removed from mempool.")
                    return True
        self.logger.warning(f"[Mempool] Transaction {tx_hash} not found in mempool.")
        return False

    def get_transactions(self) -> List[Dict]:
        """
        Returns a list of all transactions in the mempool, prioritized by fee.
        """
        with self.lock:
            # Return transactions sorted by fee in descending order
            return sorted(self.transactions, key=lambda tx: Decimal(tx['fee']), reverse=True)

    def drain_verified_transactions(self) -> List[Dict]:
        """
        Drains and returns all verified transactions from the mempool, prioritized by fee.

        :return: List of drained transactions.
        """
        with self.lock:
            prioritized_transactions = self.get_transactions()
            self.transactions.clear()
            self.fee_heap.clear()
            self.current_interval_count += len(prioritized_transactions)
            self.logger.info(f"[Mempool] Drained {len(prioritized_transactions)} transactions from mempool.")
            return prioritized_transactions

    def return_transactions(self, transactions: List[Dict]) -> None:
        """
        Returns transactions to the mempool, e.g., if block creation failed.

        :param transactions: List of transactions to return.
        """
        with self.lock:
            for tx in transactions:
                tx_hash = tx.get('hash')
                sender = tx.get('sender')
                receiver = tx.get('receiver')
                amount = Decimal(tx.get('amount', '0'))
                fee = Decimal(tx.get('fee', '0'))
                nonce = int(tx.get('nonce', '0'))

                # Check for duplicates
                if any(existing_tx['hash'] == tx_hash for existing_tx in self.transactions):
                    self.logger.warning(f"[Mempool] Duplicate transaction {tx_hash} detected when returning to mempool. Skipping.")
                    continue

                # Verify sender's balance again against the ledger's current state
                if not self.ledger:
                    self.logger.error("[Mempool] Ledger not set. Cannot verify balance for returning transactions.")
                    continue

                sender_balance = self.ledger.account_manager.get_account_balance(sender)
                if sender_balance < (amount + fee):
                    self.logger.warning(f"[Mempool] Cannot return transaction {tx_hash} due to insufficient balance for sender {sender}. Required: {amount + fee}, Available: {sender_balance}.")
                    continue

                # Verify signature again
                if not self.crypto_utils.verify_signature(tx):
                    self.logger.warning(f"[Mempool] Invalid signature for transaction {tx_hash} when returning to mempool.")
                    continue

                # Verify that fee meets the minimum required
                try:
                    min_fee = self.fee_calculator.calculate_fee(transaction_size=tx.get('size', 250))  # Assuming transaction has a 'size' field
                except Exception as e:
                    self.logger.error(f"[Mempool] Error calculating minimum fee for transaction {tx_hash}: {e}")
                    continue

                if fee < min_fee:
                    self.logger.warning(f"[Mempool] Fee {fee} below minimum required {min_fee} for transaction {tx_hash} when returning to mempool.")
                    continue

                # Consensus-specific validation
                if not self.consensus_engine.validate_transaction(tx):
                    self.logger.warning(f"[Mempool] Transaction {tx_hash} rejected by consensus engine when returning to mempool.")
                    continue

                # Add the transaction back to mempool
                self.transactions.append(tx)
                heapq.heappush(self.fee_heap, (-fee, tx['timestamp'], tx))
                self.logger.debug(f"[Mempool] Transaction {tx_hash} returned to mempool.")

    def _dynamic_size_adjustment_routine(self):
        """
        Periodically adjusts the mempool size based on transaction activity.
        Increases the mempool size during high activity and decreases it during low activity.
        """
        while True:
            time.sleep(self.adjustment_interval)
            with self.lock:
                self.transaction_counts.append(self.current_interval_count)
                avg_transactions = sum(self.transaction_counts[-5:]) / min(len(self.transaction_counts), 5)  # Moving average over last 5 intervals
                self.logger.info(f"[Mempool] Average transactions per interval: {avg_transactions}")

                if avg_transactions > self.high_activity_threshold and self.max_size < 5000:
                    # Increase mempool size by 1000, up to a maximum of 5000
                    self.max_size = min(self.max_size + 1000, 5000)
                    self.logger.info(f"[Mempool] High activity detected. Increased mempool max_size to {self.max_size}.")
                elif avg_transactions < self.low_activity_threshold and self.max_size > self.min_size:
                    # Decrease mempool size by 500, down to min_size
                    self.max_size = max(self.max_size - 500, self.min_size)
                    # Optionally, remove excess transactions if current size exceeds new max_size
                    if len(self.transactions) > self.max_size:
                        excess = len(self.transactions) - self.max_size
                        # Remove lowest fee transactions
                        for _ in range(excess):
                            if self.fee_heap:
                                _, _, tx_to_remove = heapq.heappop(self.fee_heap)
                                self.transactions.remove(tx_to_remove)
                        self.logger.info(f"[Mempool] Low activity detected. Decreased mempool max_size to {self.max_size} and removed {excess} excess transactions.")
                else:
                    self.logger.info(f"[Mempool] Mempool size remains at {self.max_size}.")

                # Reset current interval count
                self.current_interval_count = 0

    def _purge_stale_transactions_routine(self, stale_time: int):
        """
        Periodically purges transactions that have been in the mempool longer than stale_time seconds.
        """
        while True:
            time.sleep(stale_time)
            with self.lock:
                current_time = time.time()
                original_count = len(self.transactions)
                self.transactions = [
                    tx for tx in self.transactions
                    if (current_time - tx.get('timestamp', current_time)) <= stale_time
                ]
                # Rebuild the fee heap
                self.fee_heap = [(-Decimal(tx['fee']), tx['timestamp'], tx) for tx in self.transactions]
                heapq.heapify(self.fee_heap)
                purged_count = original_count - len(self.transactions)
                if purged_count > 0:
                    self.logger.info(f"[Mempool] Purged {purged_count} stale transactions from mempool.")

    def get_high_priority_transactions(self, count: int) -> List[Dict]:
        """
        Retrieves a specified number of high-priority transactions based on fee.

        :param count: Number of transactions to retrieve.
        :return: List of high-priority transactions.
        """
        with self.lock:
            return [item[2] for item in heapq.nsmallest(count, self.fee_heap)]

    def has_transactions(self) -> bool:
        """
        Checks if the mempool has any transactions.

        :return: True if mempool is not empty, False otherwise.
        """
        with self.lock:
            return len(self.transactions) > 0

    def get_transaction_count(self) -> int:
        """
        Returns the current number of transactions in the mempool.

        :return: Integer count of transactions.
        """
        with self.lock:
            return len(self.transactions)

    def clear_mempool(self):
        """
        Clears all transactions from the mempool. Used during chain reorganization.
        """
        with self.lock:
            self.transactions.clear()
            self.fee_heap.clear()
            self.current_interval_count = 0
            self.logger.info("[Mempool] All transactions have been cleared from the mempool.")

    def shutdown(self):
        """
        Gracefully shuts down the mempool by terminating background threads.
        Note: Since threads are daemonized, they will exit when the main program exits.
        If additional cleanup is needed, implement here.
        """
        self.logger.info("[Mempool] Shutting down mempool.")
        # No explicit action needed due to daemon threads
