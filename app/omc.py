# omc.py

import logging
from decimal import Decimal, getcontext, ROUND_DOWN, InvalidOperation
from datetime import datetime, timedelta, timezone
import threading
from typing import Dict, Any, Optional, List, Set, Tuple
import secrets
import re
import queue  # Import queue for handling transfer requests

# Import AccountManager from account_manager.py
from account_manager import AccountManager

# Set decimal precision higher to handle financial calculations accurately
getcontext().prec = 28
getcontext().rounding = ROUND_DOWN


class TransferRequest:
    def __init__(self, from_address: str, to_address: str, amount: Decimal, permission: Dict[str, Any], sender_pub: Optional[str] = None, permission_sig: Optional[str] = None):
        self.from_address = from_address
        self.to_address = to_address
        self.amount = amount
        self.permission = permission  # Should include 'id' and 'processed' status
        self.sender_pub = sender_pub
        self.permission_sig = permission_sig
        self.timestamp = datetime.now(timezone.utc)
        self.status = "pending"  # Possible statuses: pending, approved, declined, processed


class OMC:
    def __init__(
        self,
        account_manager: AccountManager,
        treasury_address: str,
        coin_max: Decimal = Decimal('22000000'),
        initial_supply: Decimal = Decimal('2200000'),
        initial_reward: Decimal = Decimal('50'),
        halving_interval_days: int = 1461,
        governance_vote_threshold: int = 10,
        minting_rules: Optional[Dict[str, Any]] = None
    ):
        self.logger = logging.getLogger('OMC')
        self.logger.setLevel(logging.INFO)
        handler = logging.StreamHandler()
        formatter = logging.Formatter('[%(asctime)s] [%(levelname)s] [%(name)s] %(message)s')
        handler.setFormatter(formatter)
        if not self.logger.handlers:
            self.logger.addHandler(handler)

        self.account_manager = account_manager
        self.treasury_address = treasury_address
        self.name = 'Omne Coin'
        self.symbol = 'OMC'
        self.decimals = 18
        self.image = "https://bafkreidygcfusnh6kilszq7be3j33f4t4hzxcimkgpmhkrxw4v23endhbu.ipfs.w3s.link/"
        # Scale the values:
        self.coin_max = coin_max * (10 ** self.decimals)
        self.initial_supply = Decimal(initial_supply) * (10 ** self.decimals)
        self.initial_reward = initial_reward
        self.halving_interval = timedelta(days=halving_interval_days)
        self.staking_manager = None

        self.lock = threading.RLock()
        self.last_halving_date = datetime.now(timezone.utc)
        self.current_reward = self.initial_reward
        self.total_minted = Decimal('0')
        self.reward_distribution: Dict[str, Decimal] = {'validator': Decimal('0.8'), 'treasury': Decimal('0.2')}
        self.governance_vote_threshold = governance_vote_threshold
        self.pending_ratio_changes: List[Dict[str, Any]] = []
        self.active_validators: Set[str] = set()
        self.validator_url_mapping: Dict[str, str] = {}
        self.transfer_history: List[Tuple[str, str, Decimal]] = []
        self.minting_history: List[Tuple[str, Decimal]] = []
        self.burning_history: List[Decimal] = []
        self.request_queue = queue.Queue()

        self.logger.info(
            f"OMC initialized with max supply {self.coin_max} OMC, initial reward {self.initial_reward} OMC per block."
        )
        self.logger.info(f"Initial reward distribution: {self.reward_distribution}")

        if minting_rules:
            self._process_minting_rules(minting_rules)

    # ----------------------------
    # Minting Rules Processing
    # ----------------------------
    def _process_minting_rules(self, minting_rules: Dict[str, Any]) -> None:
        """
        Processes additional minting rules provided during initialization.

        :param minting_rules: Dictionary containing minting configurations.
        """
        initial_mint = minting_rules.get('initial_mint')
        block_reward_multiplier = minting_rules.get('block_reward_multiplier')

        if initial_mint:
            try:
                initial_mint_decimal = Decimal(initial_mint)
                # Credit the initial supply to the treasury address
                self.account_manager.credit_account(self.treasury_address, initial_mint_decimal)
                self.total_minted += initial_mint_decimal
                self.logger.info(f"Minted initial supply of {initial_mint_decimal} OMC to treasury.")
            except (InvalidOperation, ValueError) as e:
                self.logger.error(f"Invalid initial_mint value in minting_rules: {e}")

        if block_reward_multiplier:
            try:
                self.block_reward_multiplier = Decimal(block_reward_multiplier)
                self.logger.info(f"Block reward multiplier set to {self.block_reward_multiplier} based on minting rules.")
            except (InvalidOperation, ValueError) as e:
                self.logger.error(f"Invalid block_reward_multiplier value in minting_rules: {e}")

    # ----------------------------
    # Validator Management
    # ----------------------------
    def register_validator(self, validator_address: str) -> bool:
        """
        Registers a new validator by adding them to the active validators.

        :param validator_address: The identifier/address of the validator.
        :return: True if registration is successful, False if already registered.
        """
        with self.lock:
            if validator_address in self.active_validators:
                self.logger.warning(f"Validator {validator_address} is already registered.")
                return False
            self.active_validators.add(validator_address)
            self.logger.info(f"Validator {validator_address} registered successfully.")
            return True

    def deregister_validator(self, validator_address: str) -> bool:
        """
        Deregisters an existing validator by removing them from active validators.

        :param validator_address: The identifier/address of the validator.
        :return: True if deregistration is successful, False if not found.
        """
        with self.lock:
            if validator_address not in self.active_validators:
                self.logger.warning(f"Validator {validator_address} is not registered.")
                return False
            self.active_validators.remove(validator_address)
            self.logger.info(f"Validator {validator_address} deregistered successfully.")
            return True

    def set_staking_manager(self, staking_manager: 'StakingMngr'):
        """
        Sets the StakingMngr instance to interface with active staking agreements.

        :param staking_manager: Instance of StakingMngr.
        """
        self.staking_manager = staking_manager
        self.logger.info("StakingManager has been set in OMC.")

    def get_active_validators(self) -> List[str]:
        """
        Retrieves a list of active validator addresses based on active staking agreements.

        :return: List of validator addresses.
        """
        if not self.staking_manager:
            self.logger.error("StakingManager not set in OMC. Cannot retrieve active validators.")
            return []

        active_validators = [
            agreement['address'] for agreement in self.staking_manager.staking_agreements
            if self._is_staking_active(agreement)
        ]
        self.logger.debug(f"Active validators retrieved: {active_validators}")
        return active_validators

    def _is_staking_active(self, agreement: Dict[str, Any]) -> bool:
        """
        Determines if a staking agreement is active based on its start date and minimum term.

        :param agreement: A staking agreement dictionary.
        :return: True if active, False otherwise.
        """
        start_date = datetime.fromisoformat(agreement['start_date'])
        min_term = agreement['min_term']  # in days or blocks, depending on implementation

        # Example: Check if the current time is past the staking period
        current_time = datetime.now(timezone.utc)
        staking_duration = timedelta(days=min_term)  # Adjust based on actual min_term unit

        return current_time >= (start_date + staking_duration)

    # ----------------------------
    # Governance Mechanism
    # ----------------------------
    def propose_reward_distribution_change(self, new_distribution: Dict[str, Decimal], proposer: str) -> bool:
        """
        Propose a new reward distribution ratio.

        :param new_distribution: Dictionary with keys 'validator' and 'treasury' representing the new ratios.
        :param proposer: Identifier for the entity proposing the change.
        :return: True if proposal is accepted for voting, False otherwise.
        """
        if not self._validate_distribution(new_distribution):
            self.logger.error("Invalid reward distribution ratios proposed.")
            return False

        with self.lock:
            proposal = {
                'new_distribution': new_distribution,
                'proposer': proposer,
                'votes': 0,
                'approved': False
            }
            self.pending_ratio_changes.append(proposal)
            self.logger.info(
                f"Proposal to change reward distribution to {new_distribution} by {proposer} has been submitted."
            )
            return True

    def vote_on_distribution_change(self, proposal_index: int, voter: str) -> bool:
        """
        Vote on a pending reward distribution change proposal.

        :param proposal_index: Index of the proposal in the pending_ratio_changes list.
        :param voter: Identifier for the entity voting.
        :return: True if vote is successful and proposal is approved, False otherwise.
        """
        with self.lock:
            if proposal_index >= len(self.pending_ratio_changes) or proposal_index < 0:
                self.logger.error("Invalid proposal index.")
                return False

            proposal = self.pending_ratio_changes[proposal_index]

            if proposal['approved']:
                self.logger.warning(f"Proposal {proposal_index} has already been approved.")
                return False

            # Simple voting mechanism: increment vote count
            proposal['votes'] += 1
            self.logger.info(
                f"{voter} voted on proposal {proposal_index}. Total votes: {proposal['votes']}."
            )

            # Check if vote threshold is met
            if proposal['votes'] >= self.governance_vote_threshold:
                self._apply_reward_distribution_change(proposal['new_distribution'])
                proposal['approved'] = True
                self.logger.info(
                    f"Proposal {proposal_index} approved. Reward distribution updated to {proposal['new_distribution']}."
                )
            return True

    def _apply_reward_distribution_change(self, new_distribution: Dict[str, Decimal]) -> None:
        """
        Apply the approved reward distribution change.

        :param new_distribution: The new distribution ratios.
        """
        with self.lock:
            self.reward_distribution = new_distribution
            self.logger.info(f"Reward distribution successfully updated to {self.reward_distribution}.")

    def _validate_distribution(self, distribution: Dict[str, Decimal]) -> bool:
        """
        Validate the proposed reward distribution ratios.

        :param distribution: The distribution ratios to validate.
        :return: True if valid, False otherwise.
        """
        try:
            total = sum(distribution.values())
            if total != Decimal('1.0'):
                self.logger.error(f"Total distribution ratios sum to {total}, expected 1.0.")
                return False
            if any(r < Decimal('0') for r in distribution.values()):
                self.logger.error("Negative distribution ratios are not allowed.")
                return False
            return True
        except (InvalidOperation, TypeError) as e:
            self.logger.error(f"Error validating distribution ratios: {e}")
            return False

    # ----------------------------
    # Minting and Reward Mechanism
    # ----------------------------
    def mint_coins_and_send(self, address: str, amount: Decimal) -> None:
        self.logger.info(f"mint_coins_and_send called with address {address} and amount {amount}")
        if self.total_minted + amount > self.coin_max:
            self.logger.warning("Max supply reached. Cannot mint more coins.")
            return
        success = self.account_manager.credit_account(address, amount)
        if success:
            self.total_minted += amount
            self.logger.info(f"Minted {amount} OMC and sent to {address}.")
        else:
            self.logger.error(f"Failed to credit {amount} OMC to {address}.")
                    
    def mint_for_block_fee(
        self, 
        total_fee: Decimal, 
        current_block_height: int, 
        validator_address: str, 
        miner_address: Optional[str] = None
    ) -> Dict[str, Decimal]:
        """
        Mints new OMC as block rewards, based on the current block height and halving schedule.
        Distributes minted coins to the validator, miner, and treasury.

        :param total_fee: Total fees collected in the block.
        :param current_block_height: The index of the current block.
        :param validator_address: The address of the validator.
        :param miner_address: The address of the miner.
        :return: Dictionary with minted amounts for 'validator', 'miner', and 'treasury'.
        """
        with self.lock:
            # Check if it's time to halve the reward
            self._check_and_halve_reward()

            # Calculate total reward: block reward + fees
            block_reward = self.current_reward
            total_reward = block_reward + total_fee

            # Define reward distribution ratios
            # Example: Validator - 50%, Miner - 30%, Treasury - 20%
            distribution = self.reward_distribution

            # Calculate individual rewards
            validator_reward = (total_reward * distribution.get('validator', Decimal('0.0'))).quantize(Decimal('0.000000000000000001'))
            miner_reward = (total_reward * distribution.get('miner', Decimal('0.0'))).quantize(Decimal('0.000000000000000001')) if miner_address else Decimal('0')
            treasury_reward = (total_reward * distribution.get('treasury', Decimal('0.0'))).quantize(Decimal('0.000000000000000001'))

            # Ensure not exceeding max supply
            if self.total_minted + total_reward > self.coin_max:
                allowed_reward = self.coin_max - self.total_minted
                if allowed_reward <= Decimal('0'):
                    self.logger.warning("Max supply reached. No more rewards can be minted.")
                    return {
                        'validator': Decimal('0.000000000000000000'), 
                        'miner': Decimal('0.000000000000000000'), 
                        'treasury': Decimal('0.000000000000000000')
                    }

                # Adjust rewards proportionally
                validator_reward = (allowed_reward * distribution.get('validator', Decimal('0.0'))).quantize(Decimal('0.000000000000000001'))
                miner_reward = (allowed_reward * distribution.get('miner', Decimal('0.0'))).quantize(Decimal('0.000000000000000001')) if miner_address else Decimal('0')
                treasury_reward = (allowed_reward * distribution.get('treasury', Decimal('0.0'))).quantize(Decimal('0.000000000000000001'))
                total_reward = validator_reward + miner_reward + treasury_reward
                self.logger.warning(
                    f"Minting adjusted to not exceed max supply. Minted {total_reward} OMC instead of {block_reward + total_fee} OMC."
                )

            # Update total minted
            self.total_minted += total_reward

            self.logger.info(
                f"Minted {total_reward} OMC for block {current_block_height}: "
                f"{validator_reward} OMC to validator, {miner_reward} OMC to miner, and {treasury_reward} OMC to treasury."
            )

            # Distribute rewards
            self._distribute_rewards(validator_address, validator_reward, miner_address, miner_reward, treasury_reward)

            return {
                'validator': validator_reward, 
                'miner': miner_reward, 
                'treasury': treasury_reward
            }

    def _check_and_halve_reward(self):
        """
        Checks if the halving interval has passed and halves the current block reward if necessary.
        """
        now = datetime.now(timezone.utc)
        if now - self.last_halving_date >= self.halving_interval:
            new_reward = (self.current_reward / 2).quantize(Decimal('0.000000000000000001'))
            if new_reward < Decimal('1.000000000000000000'):
                new_reward = Decimal('1.000000000000000000')  # Set a minimum block reward to prevent it from becoming too small
                self.logger.info(
                    f"Block reward halved from {self.current_reward} to {new_reward} OMC. Minimum reward reached."
                )
            else:
                self.logger.info(
                    f"Block reward halved from {self.current_reward} to {new_reward} OMC."
                )
            self.current_reward = new_reward
            self.last_halving_date = now

    def _distribute_rewards(
        self, 
        validator_address: str, 
        validator_reward: Decimal, 
        miner_address: Optional[str], 
        miner_reward: Decimal, 
        treasury_reward: Decimal
    ) -> None:
        """
        Distributes the minted rewards to the validator, miner, and treasury.

        :param validator_address: The address of the validator.
        :param validator_reward: Amount to distribute to the validator.
        :param miner_address: The address of the miner.
        :param miner_reward: Amount to distribute to the miner.
        :param treasury_reward: Amount to distribute to the treasury.
        """
        # Distribute to validator
        if validator_address:
            success_validator = self.account_manager.credit_account(validator_address, validator_reward)
            if success_validator:
                self.logger.info(f"Distributed {validator_reward} OMC to validator {validator_address}.")
            else:
                self.logger.error(f"Failed to distribute {validator_reward} OMC to validator {validator_address}.")

        # Distribute to miner
        if miner_address and miner_reward > 0:
            success_miner = self.account_manager.credit_account(miner_address, miner_reward)
            if success_miner:
                self.logger.info(f"Distributed {miner_reward} OMC to miner {miner_address}.")
            else:
                self.logger.error(f"Failed to distribute {miner_reward} OMC to miner {miner_address}.")

        # Distribute to treasury
        success_treasury = self.account_manager.credit_account(self.treasury_address, treasury_reward)
        if success_treasury:
            self.logger.info(f"Distributed {treasury_reward} OMC to treasury {self.treasury_address}.")
        else:
            self.logger.error(f"Failed to distribute {treasury_reward} OMC to treasury {self.treasury_address}.")

    # ----------------------------
    # Transfer Methods
    # ----------------------------
    def create_transfer_request(self, from_address: str, to_address: str, amount: Decimal, permission: Dict[str, Any]) -> TransferRequest:
        """
        Creates a new transfer request.

        :param from_address: Sender's address.
        :param to_address: Recipient's address.
        :param amount: Amount to transfer.
        :param permission: Permission dictionary, initially {'permission': 'pending'}.
        :return: TransferRequest instance.
        """
        # Check for double-spending
        if self.check_double_spending(from_address, to_address, amount):
            raise DoubleSpendingError("Double spending detected.")

        # Generate a unique transfer request ID
        request_id = self.generate_request_id()
        permission['id'] = request_id
        permission['processed'] = None  # None indicates pending

        # Create the TransferRequest object
        transfer_request = TransferRequest(from_address, to_address, amount, permission)

        # Add the transfer request to the queue
        with self.lock:
            self.request_queue.put(transfer_request)
            self.logger.info(f"Transfer request {request_id} created from {from_address} to {to_address} for amount {amount} OMC.")

        return transfer_request

    def approve_transfer_request(self, request_id: str, sender_pub: str, permission_sig: str) -> bool:
        """
        Approves a transfer request.

        :param request_id: ID of the transfer request.
        :param sender_pub: Sender's public key.
        :param permission_sig: Signature for permission.
        :return: True if approval is successful, False otherwise.
        """
        with self.lock:
            # Iterate through the queue to find the request
            found = False
            temp_queue = queue.Queue()
            while not self.request_queue.empty():
                request = self.request_queue.get()
                if request.permission['id'] == request_id:
                    request.sender_pub = sender_pub
                    request.permission_sig = permission_sig
                    request.permission['processed'] = datetime.now(timezone.utc).isoformat()
                    request.status = "approved"
                    self.logger.info(f"Transfer request {request_id} approved.")
                    found = True
                temp_queue.put(request)

            # Restore the queue
            self.request_queue = temp_queue

            return found

    def decline_transfer_request(self, request_id: str) -> bool:
        """
        Declines a transfer request.

        :param request_id: ID of the transfer request.
        :return: True if decline is successful, False otherwise.
        """
        with self.lock:
            # Iterate through the queue to find and remove the request
            found = False
            temp_queue = queue.Queue()
            while not self.request_queue.empty():
                request = self.request_queue.get()
                if request.permission['id'] == request_id:
                    request.status = "declined"
                    self.logger.info(f"Transfer request {request_id} declined.")
                    found = True
                    continue  # Skip adding to temp_queue to remove it
                temp_queue.put(request)

            # Restore the queue
            self.request_queue = temp_queue

            return found

    def process_transfer_request(self, request_id: str) -> bool:
        """
        Processes an approved transfer request.

        :param request_id: ID of the transfer request.
        :return: True if processing is successful, False otherwise.
        """
        with self.lock:
            # Iterate through the queue to find the approved request
            found = False
            temp_queue = queue.Queue()
            while not self.request_queue.empty():
                request = self.request_queue.get()
                if request.permission['id'] == request_id and request.permission['processed']:
                    try:
                        success = self.transfer(request.from_address, request.to_address, request.amount)
                        if success:
                            self.logger.info(f"Transfer request {request_id} processed successfully.")
                            found = True
                    except Exception as e:
                        self.logger.error(f"Failed to process transfer request {request_id}: {e}")
                        # Optionally, re-add the request to the queue or mark as failed
                else:
                    temp_queue.put(request)

            # Restore the queue
            self.request_queue = temp_queue

            return found

    def get_request_by_id(self, request_id: str) -> Optional[TransferRequest]:
        """
        Retrieves a transfer request by its ID.

        :param request_id: ID of the transfer request.
        :return: TransferRequest instance or None if not found.
        """
        with self.lock:
            temp_queue = queue.Queue()
            found_request = None
            while not self.request_queue.empty():
                request = self.request_queue.get()
                if request.permission['id'] == request_id:
                    found_request = request
                temp_queue.put(request)
            self.request_queue = temp_queue
            return found_request

    def get_pending_requests_for_user(self, address: str) -> List[Dict[str, Any]]:
        """
        Retrieves all pending transfer requests for a specific user.

        :param address: User's address.
        :return: List of pending transfer request dictionaries.
        """
        with self.lock:
            temp_queue = queue.Queue()
            pending_requests = []
            while not self.request_queue.empty():
                request = self.request_queue.get()
                if request.to_address == address and request.status == "pending":
                    pending_requests.append({
                        'from_address': request.from_address,
                        'to_address': request.to_address,
                        'amount': str(request.amount),
                        'request_id': request.permission['id'],
                        'timestamp': request.timestamp.isoformat()
                    })
                temp_queue.put(request)
            self.request_queue = temp_queue
            return pending_requests

    def update_request_permissions(self, request_id: str, sender_pub: str, permission_sig: str, permission_approval: str) -> bool:
        """
        Updates permissions for a specific transfer request.

        :param request_id: ID of the transfer request.
        :param sender_pub: Sender's public key.
        :param permission_sig: Permission signature.
        :param permission_approval: Approval status ('approved' or 'declined').
        :return: True if update is successful, False otherwise.
        """
        with self.lock:
            found = False
            temp_queue = queue.Queue()
            while not self.request_queue.empty():
                request = self.request_queue.get()
                if request.permission['id'] == request_id:
                    request.sender_pub = sender_pub
                    request.permission_sig = permission_sig
                    request.permission['processed'] = permission_approval
                    request.status = "approved" if permission_approval.lower() == 'approved' else "declined"
                    self.logger.info(f"Transfer request {request_id} permissions updated to {permission_approval}.")
                    found = True
                temp_queue.put(request)
            self.request_queue = temp_queue
            return found

    # ----------------------------
    # Transfer Execution Method
    # ----------------------------
    def transfer(self, from_address: str, to_address: str, amount: Decimal) -> bool:
        """
        Executes a transfer from one address to another.

        :param from_address: Sender's address.
        :param to_address: Recipient's address.
        :param amount: Amount to transfer.
        :return: True if transfer is successful, False otherwise.
        """
        with self.account_manager.balances_lock:
            if from_address not in self.account_manager.balances:
                self.logger.error("Sender address does not exist.")
                return False

            if self.account_manager.balances[from_address] < amount:
                self.logger.error("Insufficient balance for transfer.")
                return False

            # Debit sender
            self.account_manager.debit_account(from_address, amount)

            # Credit recipient
            self.account_manager.credit_account(to_address, amount)

            # Log the transfer
            self.transfer_history.append((from_address, to_address, amount))
            self.logger.info(f"Transferred {amount} OMC from {from_address} to {to_address}.")

            return True

    # ----------------------------
    # Utility Methods
    # ----------------------------
    def generate_request_id(self) -> str:
        """
        Generates a unique transfer request ID.

        :return: Unique request ID string.
        """
        random_number = secrets.randbelow(10**40)
        cryptographic_number = f'0r{random_number:040d}'
        return cryptographic_number

    def get_balance(self, address: str) -> Optional[Decimal]:
        """
        Retrieves the OMC balance of a given account.

        :param address: The address of the account.
        :return: OMC balance as Decimal or None if account does not exist.
        """
        with self.account_manager.balances_lock:
            balance = self.account_manager.balances.get(address)
            if balance is not None:
                self.logger.debug(f"[OMC] Retrieved balance for {address}: {balance} OMC.")
            else:
                self.logger.debug(f"[OMC] Balance for {address} not found.")
            return balance

    # ----------------------------
    # Shutdown Method
    # ----------------------------
    def shutdown(self):
        """
        Gracefully shuts down the OMC.
        """
        self.logger.info("Shutting down OMC.")
        # Implement any necessary cleanup here
        # For example, persisting state, notifying other components, etc.
        pass  # Placeholder for actual shutdown logic

# Custom Exception for Double Spending
class DoubleSpendingError(Exception):
    pass
