# account_manager.py

from typing import Dict, Optional, List, Callable
from decimal import Decimal, InvalidOperation
import logging
from threading import Lock, RLock

# Initialize logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s [%(levelname)s] %(message)s')


class Event:
    """
    Simple Event class to handle event subscriptions and emissions.
    """
    def __init__(self):
        self.subscribers: List[Callable] = []

    def subscribe(self, callback: Callable):
        """
        Subscribes a callback function to the event.

        :param callback: Callable to be invoked when the event is emitted.
        """
        self.subscribers.append(callback)

    def emit(self, *args, **kwargs):
        """
        Emits the event, invoking all subscribed callbacks.

        :param args: Positional arguments to pass to callbacks.
        :param kwargs: Keyword arguments to pass to callbacks.
        """
        for subscriber in self.subscribers:
            try:
                subscriber(*args, **kwargs)
            except Exception as e:
                logging.error(f"Error in event subscriber: {e}")


class AccountManager:
    """
    Manages user balances, staking contracts, and public keys with enhanced features:
      - Supports multiple concurrent staking contracts per address.
      - Utilizes granular locking for improved concurrency.
      - Emits events upon significant account and staking actions.
    """

    def __init__(self):
        # Store balances: address -> balance
        self.balances: Dict[str, Decimal] = {}
        self.balances_lock = RLock()

        # Store staking contracts: contract_id -> {'address': str, 'amount': Decimal, 'min_term': int, 'start_block': int}
        self.staking_contracts: Dict[int, Dict] = {}
        self.staking_contracts_lock = RLock()
        self.next_contract_id = 1

        # Store validator public keys: address -> public_key
        self.public_keys: Dict[str, str] = {}
        self.public_keys_lock = RLock()

        # Track total staked per validator: address -> total_staked_amount
        self.validator_stakes: Dict[str, Decimal] = {}
        self.validator_stakes_lock = RLock()

        # Initialize events
        self.on_balance_updated = Event()
        self.on_staking_contract_created = Event()
        self.on_staking_contract_removed = Event()
        self.on_public_key_updated = Event()

        self.logger = logging.info("[AccountManager] Initialized with empty balances, staking contracts, and public keys.")

    # ----------------------------
    # Event Subscription Methods
    # ----------------------------
    def subscribe_to_balance_updates(self, callback: Callable):
        """
        Subscribes to balance update events.

        :param callback: Callable to be invoked on balance updates.
        """
        self.on_balance_updated.subscribe(callback)

    def subscribe_to_staking_contract_creation(self, callback: Callable):
        """
        Subscribes to staking contract creation events.

        :param callback: Callable to be invoked when a staking contract is created.
        """
        self.on_staking_contract_created.subscribe(callback)

    def subscribe_to_staking_contract_removal(self, callback: Callable):
        """
        Subscribes to staking contract removal events.

        :param callback: Callable to be invoked when a staking contract is removed.
        """
        self.on_staking_contract_removed.subscribe(callback)

    def subscribe_to_public_key_updates(self, callback: Callable):
        """
        Subscribes to public key update events.

        :param callback: Callable to be invoked when a public key is updated.
        """
        self.on_public_key_updated.subscribe(callback)

    # ----------------------------
    # Balance Management
    # ----------------------------
    def get_account_balance(self, address: str) -> Optional[Decimal]:
        """
        Retrieves the balance of a given account.

        :param address: The address of the account.
        :return: Balance as Decimal or None if account does not exist.
        """
        with self.balances_lock:
            balance = self.balances.get(address)
            if balance is not None:
                logger.debug(f"[AccountManager] Retrieved balance for {address}: {balance} OMC.")
            else:
                logger.debug(f"[AccountManager] Balance for {address} not found.")
            return balance

    def credit_account(self, address: str, amount: Decimal) -> bool:
        """
        Credits an amount to an account.

        :param address: The address of the account.
        :param amount: Amount to credit.
        :return: True if successful, False otherwise.
        """
        if amount < Decimal('0'):
            logging.error(f"[AccountManager] Cannot credit negative amount: {amount} OMC to {address}.")
            return False

        with self.balances_lock:
            previous_balance = self.balances.get(address, Decimal('0'))
            new_balance = previous_balance + amount
            self.balances[address] = new_balance
            logging.debug(f"[AccountManager] Credited {amount} OMC to {address}. New balance: {new_balance} OMC.")

        # Emit balance update event
        self.on_balance_updated.emit(address=address, previous_balance=previous_balance, new_balance=new_balance)
        return True

    def debit_account(self, address: str, amount: Decimal) -> bool:
        """
        Debits an amount from an account if sufficient balance exists.

        :param address: The address of the account.
        :param amount: Amount to debit.
        :return: True if successful, False otherwise.
        """
        if amount < Decimal('0'):
            logging.error(f"[AccountManager] Cannot debit negative amount: {amount} OMC from {address}.")
            return False

        with self.balances_lock:
            current_balance = self.balances.get(address, Decimal('0'))
            if current_balance >= amount:
                new_balance = current_balance - amount
                self.balances[address] = new_balance
                logging.debug(f"[AccountManager] Debited {amount} OMC from {address}. New balance: {new_balance} OMC.")
            else:
                logging.error(f"[AccountManager] Insufficient balance for {address}. Attempted to debit {amount} OMC, but current balance is {current_balance} OMC.")
                return False

        # Emit balance update event
        self.on_balance_updated.emit(address=address, previous_balance=current_balance, new_balance=new_balance)
        return True

    # ----------------------------
    # Staking Contract Management
    # ----------------------------
    def stake_coins(
        self,
        address: str,
        node_address: str,
        amount: Decimal,
        min_term: int,
        pub_key: str,
        current_block_height: int = 0  # Placeholder for block height
    ) -> bool:
        """
        Stakes coins from an account to become a validator.

        :param address: The address of the account staking the coins.
        :param node_address: The node address of the validator.
        :param amount: Amount to stake.
        :param min_term: Minimum staking term in blocks.
        :param pub_key: Public key of the validator.
        :param current_block_height: The current block height (for staking term tracking).
        :return: True if staking was successful, False otherwise.
        """
        if amount <= Decimal('0'):
            logging.error(f"[AccountManager] Cannot stake non-positive amount: {amount} OMC by {address}.")
            return False

        if min_term <= 0:
            logging.error(f"[AccountManager] Minimum staking term must be positive. Provided: {min_term} blocks.")
            return False

        if not pub_key:
            logging.error(f"[AccountManager] Public key is required for staking by {address}.")
            return False

        if self.debit_account(address, amount):
            with self.staking_contracts_lock:
                contract_id = self.next_contract_id
                self.staking_contracts[contract_id] = {
                    'address': node_address,
                    'amount': amount,
                    'min_term': min_term,
                    'start_block': current_block_height
                }
                self.next_contract_id += 1
                logging.info(f"[AccountManager] {node_address} has staked {amount} OMC with contract ID {contract_id}.")

            # Register or update validator's public key
            self.add_validator_public_key(node_address, pub_key)

            # Update total staked for the validator
            with self.validator_stakes_lock:
                previous_stake = self.validator_stakes.get(node_address, Decimal('0'))
                self.validator_stakes[node_address] = previous_stake + amount
                logging.debug(f"[AccountManager] Total staked for {node_address}: {self.validator_stakes[node_address]} OMC.")

            # Emit staking contract creation event
            self.on_staking_contract_created.emit(
                contract_id=contract_id,
                address=node_address,
                amount=amount,
                min_term=min_term
            )
            return True
        else:
            logging.error(f"[AccountManager] Failed to stake {amount} OMC for {node_address}.")
            return False

    def unstake_coins(
        self,
        address: str,
        contract_id: int,
        current_block_height: int = 0,  # Placeholder for block height
        force: bool = False
    ) -> bool:
        """
        Unstakes coins from a staking contract.

        :param address: The address of the validator.
        :param contract_id: The ID of the staking contract.
        :param current_block_height: The current block height (for term checking).
        :param force: If True, force unstake even if minimum term not met.
        :return: True if unstaking was successful, False otherwise.
        """
        with self.staking_contracts_lock:
            contract = self.staking_contracts.get(contract_id)
            if not contract:
                logging.error(f"[AccountManager] Staking contract ID {contract_id} not found.")
                return False

            if contract['address'] != address:
                logging.error(f"[AccountManager] Address mismatch for staking contract ID {contract_id}. Expected {contract['address']}, got {address}.")
                return False

            # Check if minimum term is met
            if not force:
                if current_block_height < contract['start_block'] + contract['min_term']:
                    remaining_term = (contract['start_block'] + contract['min_term']) - current_block_height
                    logging.error(f"[AccountManager] Cannot unstake from contract ID {contract_id}. Remaining term: {remaining_term} blocks.")
                    return False

            amount = contract['amount']
            del self.staking_contracts[contract_id]
            logging.info(f"[AccountManager] {address} has unstaked {amount} OMC from contract ID {contract_id}.")

        # Credit the account back
        self.credit_account(address, amount)

        # Update total staked for the validator
        with self.validator_stakes_lock:
            if address in self.validator_stakes:
                self.validator_stakes[address] -= amount
                if self.validator_stakes[address] <= Decimal('0'):
                    del self.validator_stakes[address]
                logging.debug(f"[AccountManager] Total staked for {address}: {self.validator_stakes.get(address, Decimal('0'))} OMC.")

        # Emit staking contract removal event
        self.on_staking_contract_removed.emit(
            contract_id=contract_id,
            address=address,
            amount=amount
        )
        return True

    def get_all_staking_contracts(self) -> List[Dict]:
        """
        Retrieves all active staking contracts.

        :return: List of staking contract dictionaries.
        """
        with self.staking_contracts_lock:
            contracts = list(self.staking_contracts.values())
            logging.debug(f"[AccountManager] Retrieved all staking contracts: {contracts}")
            return contracts

    def get_staked_amount(self, validator_address: str) -> Decimal:
        """
        Retrieves the total staked amount for a given validator.

        :param validator_address: The validator's address.
        :return: The total staked amount.
        """
        with self.validator_stakes_lock:
            stake = self.validator_stakes.get(validator_address, Decimal('0'))
            logging.debug(f"[AccountManager] Retrieved staked amount for {validator_address}: {stake} OMC.")
            return stake

    # ----------------------------
    # Public Key Management
    # ----------------------------
    def add_validator_public_key(self, address: str, public_key: str) -> bool:
        """
        Adds or updates a validator's public key.

        :param address: Validator's address.
        :param public_key: Validator's public key.
        :return: True if successful, False otherwise.
        """
        if not public_key:
            logging.error(f"[AccountManager] Public key is empty for address {address}.")
            return False

        with self.public_keys_lock:
            previous_key = self.public_keys.get(address)
            self.public_keys[address] = public_key
            logging.debug(f"[AccountManager] Added/Updated public key for {address}.")

        # Emit public key update event
        self.on_public_key_updated.emit(address=address, previous_key=previous_key, new_key=public_key)
        return True

    def get_public_key(self, address: str) -> Optional[str]:
        """
        Retrieves the public key of a validator.

        :param address: Validator's address.
        :return: Public key as a string or None if not found.
        """
        with self.public_keys_lock:
            public_key = self.public_keys.get(address)
            logging.debug(f"[AccountManager] Retrieved public key for {address}: {public_key}")
            return public_key

    # ----------------------------
    # Utility Methods
    # ----------------------------
    # Implement additional utility methods as needed, such as term checking for staking contracts.

    # Example placeholder method for term checking
    def _is_min_term_met(self, contract_id: int, current_block_height: int) -> bool:
        """
        Checks if the minimum staking term has been met for a contract.

        :param contract_id: The ID of the staking contract.
        :param current_block_height: The current block height.
        :return: True if term is met, False otherwise.
        """
        with self.staking_contracts_lock:
            contract = self.staking_contracts.get(contract_id)
            if not contract:
                logging.error(f"[AccountManager] Staking contract ID {contract_id} not found for term checking.")
                return False
            return current_block_height >= (contract['start_block'] + contract['min_term'])

    # ----------------------------
    # Example Usage and Event Handlers
    # ----------------------------
    if __name__ == "__main__":
        # Create an instance of AccountManager
        account_manager = AccountManager()

        # Define event handlers
        def handle_balance_update(address, previous_balance, new_balance):
            logging.info(f"Balance updated for {address}: {previous_balance} -> {new_balance} OMC")

        def handle_staking_contract_creation(contract_id, address, amount, min_term):
            logging.info(f"Staking Contract Created - ID: {contract_id}, Address: {address}, Amount: {amount} OMC, Min Term: {min_term} blocks")

        def handle_staking_contract_removal(contract_id, address, amount):
            logging.info(f"Staking Contract Removed - ID: {contract_id}, Address: {address}, Amount: {amount} OMC")

        def handle_public_key_update(address, previous_key, new_key):
            logging.info(f"Public Key Updated for {address}: {previous_key} -> {new_key}")

        # Subscribe to events
        account_manager.subscribe_to_balance_updates(handle_balance_update)
        account_manager.subscribe_to_staking_contract_creation(handle_staking_contract_creation)
        account_manager.subscribe_to_staking_contract_removal(handle_staking_contract_removal)
        account_manager.subscribe_to_public_key_updates(handle_public_key_update)

        # Example operations
        user_address = "0xUserAddress123"
        validator_address = "0xValidatorAddress456"
        validator_pub_key = "ValidatorPublicKeyABC"

        # Credit account (e.g., initial funding)
        account_manager.credit_account(user_address, Decimal('1000'))

        # Stake coins
        staking_success = account_manager.stake_coins(
            address=user_address,
            node_address=validator_address,
            amount=Decimal('500'),
            min_term=100,
            pub_key=validator_pub_key,
            current_block_height=50  # Example current block height
        )

        # Attempt to unstake before term is met
        unstake_success = account_manager.unstake_coins(
            address=validator_address,
            contract_id=1,
            current_block_height=120,  # Example block height after min_term
            force=False
        )

        # Add/update public key
        account_manager.add_validator_public_key(validator_address, "NewValidatorPublicKeyDEF")
