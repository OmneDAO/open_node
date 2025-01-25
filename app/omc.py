# omc.py

import logging
from decimal import Decimal, getcontext, ROUND_DOWN, InvalidOperation
from datetime import datetime, timedelta, timezone
import threading
from typing import Dict, Any, Optional, List, Set
import secrets  # For generating secure contract IDs

# Assuming AccountManager is defined in account_manager.py
from account_manager import AccountManager

# Set decimal precision higher to handle financial calculations accurately
getcontext().prec = 28
getcontext().rounding = ROUND_DOWN


class OMC:
    """
    Manages the Omne Coin (OMC) supply, minting, and distribution.
    Enforces max supply and a time-based halving schedule.
    Supports dynamic adjustment of reward distribution ratios based on governance or economic feedback.
    Manages active validators and their network URLs.
    """

    def __init__(
        self,
        account_manager: AccountManager,
        treasury_address: str,
        coin_max: Decimal = Decimal('22000000'),
        initial_reward: Decimal = Decimal('50'),
        halving_interval_days: int = 1461,  # 4 years accounting for leap years
        governance_vote_threshold: int = 10,  # Number of votes needed to approve ratio changes
        minting_rules: Optional[Dict[str, Any]] = None  # Additional minting configurations
    ):
        """
        Initializes the OMC class with specified parameters.

        :param account_manager: Instance of AccountManager for managing account balances.
        :param treasury_address: Address where a portion of minted coins are sent.
        :param coin_max: Maximum total supply of OMC.
        :param initial_reward: Initial block reward.
        :param halving_interval_days: Days after which the block reward halves.
        :param governance_vote_threshold: Votes required to approve distribution ratio changes.
        :param minting_rules: Additional minting configurations.
        """

        # ----------------------------
        # Logger Initialization
        # ----------------------------
        self.logger = logging.getLogger('OMC')
        self.logger.setLevel(logging.INFO)
        handler = logging.StreamHandler()
        formatter = logging.Formatter('[%(asctime)s] [%(levelname)s] [%(name)s] %(message)s')
        handler.setFormatter(formatter)
        if not self.logger.handlers:
            self.logger.addHandler(handler)

        # ----------------------------
        # Attribute Initialization
        # ----------------------------
        self.account_manager = account_manager
        self.treasury_address = treasury_address
        self.coin_max = coin_max
        self.initial_reward = initial_reward
        self.halving_interval = timedelta(days=halving_interval_days)
        self.staking_manager = None

        self.lock = threading.RLock()  # Reentrant lock to allow nested acquisitions

        # Track the last halving date (network launch date)
        self.last_halving_date = datetime.now(timezone.utc)

        # Current block reward
        self.current_reward = self.initial_reward

        # Total minted coins
        self.total_minted = Decimal('0')

        # Reward distribution ratios
        # Example: {'validator': Decimal('0.8'), 'treasury': Decimal('0.2')}
        self.reward_distribution: Dict[str, Decimal] = {'validator': Decimal('0.8'), 'treasury': Decimal('0.2')}

        # Governance parameters
        self.governance_vote_threshold = governance_vote_threshold
        self.pending_ratio_changes: List[Dict[str, Any]] = []  # List of proposed ratio changes

        # Active Validators and their URLs
        self.active_validators: Set[str] = set()  # Set of active validator IDs (e.g., addresses)
        self.validator_url_mapping: Dict[str, str] = {}  # Maps validator_id to validator_url

        # Initialize logger before processing minting rules
        self.logger.info(
            f"OMC initialized with max supply {self.coin_max} OMC, initial reward {self.initial_reward} OMC per block."
        )
        self.logger.info(f"Initial reward distribution: {self.reward_distribution}")

        # Process minting_rules if provided
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
        
    def set_staking_manager(self, staking_manager: StakingMngr):
        """
        Sets the StakingMngr instance to interface with active staking agreements.

        :param staking_manager: Instance of StakingMngr.
        """
        self.staking_manager = staking_manager
        logging.info("StakingManager has been set in OMC.")

    def get_active_validators(self) -> List[str]:
        """
        Retrieves a list of active validator addresses based on active staking agreements.

        :return: List of validator addresses.
        """
        if not self.staking_manager:
            logging.error("StakingManager not set in OMC. Cannot retrieve active validators.")
            return []

        active_validators = [
            agreement['address'] for agreement in self.staking_manager.staking_agreements
            if self._is_staking_active(agreement)
        ]
        logging.debug(f"Active validators retrieved: {active_validators}")
        return active_validators

    def _is_staking_active(self, agreement: dict) -> bool:
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
    def mint_for_block_fee(
        self, 
        total_fee: Decimal, 
        current_block_height: int, 
        validator_address: str, 
        miner_address: str
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
            distribution = {
                'validator': Decimal('0.5'),
                'miner': Decimal('0.3'),
                'treasury': Decimal('0.2')
            }

            # Calculate individual rewards
            validator_reward = (total_reward * distribution['validator']).quantize(Decimal('0.000000000000000001'))
            miner_reward = (total_reward * distribution['miner']).quantize(Decimal('0.000000000000000001')) if miner_address else Decimal('0')
            treasury_reward = (total_reward * distribution['treasury']).quantize(Decimal('0.000000000000000001'))

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
                validator_reward = (allowed_reward * distribution['validator']).quantize(Decimal('0.000000000000000001'))
                miner_reward = (allowed_reward * distribution['miner']).quantize(Decimal('0.000000000000000001')) if miner_address else Decimal('0')
                treasury_reward = (allowed_reward * distribution['treasury']).quantize(Decimal('0.000000000000000001'))
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
        miner_address: str, 
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
    # Reward and Slashing Methods
    # ----------------------------
    def reward_validator(self, validator_id: str, block_index: int) -> None:
        """
        Rewards a validator for proposing a block.

        :param validator_id: The identifier/address of the validator.
        :param block_index: The index of the block being rewarded.
        """
        # Assuming that the ConsensusEngine has already determined the leader and passed the necessary information
        # For simplicity, we'll simulate total_fee as 0 here. Adjust as needed.
        total_fee = Decimal('0')  # This should be fetched from the block or consensus context
        self.mint_for_block_fee(total_fee, block_index, validator_id)

    def slash_validator(self, validator_id: str) -> None:
        """
        Slashes a validator for misconduct.

        :param validator_id: The identifier/address of the validator.
        """
        # Implement slashing logic here
        # This could involve removing the validator, reducing their stake, etc.
        if self.remove_validator(validator_id):
            self.logger.warning(f"Validator {validator_id} has been slashed and deregistered from active validators.")
        else:
            self.logger.error(f"Failed to slash validator {validator_id}. Validator may not be active.")

    # ----------------------------
    # Governance Methods
    # ----------------------------
    def approve_reward_distribution_change(self, proposal_index: int) -> bool:
        """
        Approves a reward distribution change proposal manually.

        :param proposal_index: Index of the proposal in the pending_ratio_changes list.
        :return: True if approval is successful, False otherwise.
        """
        with self.lock:
            if proposal_index >= len(self.pending_ratio_changes) or proposal_index < 0:
                self.logger.error("Invalid proposal index.")
                return False

            proposal = self.pending_ratio_changes[proposal_index]

            if proposal['approved']:
                self.logger.warning(f"Proposal {proposal_index} has already been approved.")
                return False

            # Directly approve the proposal
            self._apply_reward_distribution_change(proposal['new_distribution'])
            proposal['approved'] = True
            self.logger.info(
                f"Proposal {proposal_index} manually approved. Reward distribution updated to {proposal['new_distribution']}."
            )
            return True

    # ----------------------------
    # Accessor Methods
    # ----------------------------
    def get_current_reward(self) -> Decimal:
        """
        Returns the current block reward.
        """
        with self.lock:
            return self.current_reward

    def get_total_minted(self) -> Decimal:
        """
        Returns the total amount of OMC minted so far.
        """
        with self.lock:
            return self.total_minted

    def get_treasury_address(self) -> str:
        """
        Returns the treasury address.
        """
        return self.treasury_address

    def get_reward_distribution(self) -> Dict[str, Decimal]:
        """
        Returns the current reward distribution ratios.
        """
        with self.lock:
            return self.reward_distribution.copy()

    # ----------------------------
    # Utility Methods
    # ----------------------------
    def calculate_average_block_time(self, last_n_blocks: int = 100) -> Decimal:
        """
        Calculates the average block time over the last N blocks.

        :param last_n_blocks: Number of recent blocks to consider.
        :return: Average block time in seconds.
        """
        with self.lock:
            blocks = self.ledger.get_last_n_blocks(last_n_blocks)
            if len(blocks) < 2:
                self.logger.warning("Not enough blocks to calculate average block time.")
                return Decimal('0')

            total_time = Decimal('0')
            for i in range(1, len(blocks)):
                prev_block = blocks[i - 1]
                current_block = blocks[i]
                block_time = datetime.fromisoformat(current_block.timestamp) - datetime.fromisoformat(prev_block.timestamp)
                total_time += Decimal(block_time.total_seconds())

            average_time = total_time / Decimal(len(blocks) - 1)
            self.logger.info(f"Average block time over last {last_n_blocks} blocks: {average_time} seconds.")
            return average_time

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
