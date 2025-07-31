import logging
from decimal import Decimal, getcontext, ROUND_DOWN, InvalidOperation
from datetime import datetime, timedelta, timezone
import threading
from typing import Dict, Any, Optional, List, Set, Tuple
import secrets
import re
import queue

from account_manager import AccountManager

getcontext().prec = 28
getcontext().rounding = ROUND_DOWN

class TransferRequest:
    def __init__(self, from_address: str, to_address: str, amount: Decimal, permission: Dict[str, Any],
                 sender_pub: Optional[str] = None, permission_sig: Optional[str] = None):
        self.from_address = from_address
        self.to_address = to_address
        self.amount = amount
        self.permission = permission
        self.sender_pub = sender_pub
        self.permission_sig = permission_sig
        self.timestamp = datetime.now(timezone.utc)
        self.status = "pending"

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
        self.image = "https://w3s.link/ipfs/bafybeih4yyumkffmdze4rb3hy3yfz66hbv5jxb76czr25xvpjufvbwd22a"

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
        self.total_staked = Decimal('0')
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
            
    def set_staking_manager(self, staking_manager):
        self.staking_manager = staking_manager
        self.logger.info("StakingManager has been set in OMC.")

    def _process_minting_rules(self, minting_rules: Dict[str, Any]) -> None:
        initial_mint = minting_rules.get('initial_mint')
        block_reward_multiplier = minting_rules.get('block_reward_multiplier')

        if initial_mint:
            try:
                initial_mint_decimal = Decimal(initial_mint)
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

    ## [CHANGED] We no longer rely on self.active_validators set. Instead, read from staking agreements:
    def get_active_validators(self) -> List[str]:
        if not self.staking_manager:
            return []
        all_agreements = self.staking_manager.get_active_staking_agreements()
        # Return each agreement's validator address:
        return [agr['validator_address'] for agr in all_agreements]

    def register_validator(self, validator_address: str) -> bool:
        # (Potentially unused if you rely fully on staking agreements.)
        with self.lock:
            if validator_address in self.active_validators:
                self.logger.warning(f"Validator {validator_address} is already registered.")
                return False
            self.active_validators.add(validator_address)
            self.logger.info(f"Validator {validator_address} registered successfully.")
            return True

    def deregister_validator(self, validator_address: str) -> bool:
        with self.lock:
            if validator_address not in self.active_validators:
                self.logger.warning(f"Validator {validator_address} is not registered.")
                return False
            self.active_validators.remove(validator_address)
            self.logger.info(f"Validator {validator_address} deregistered successfully.")
            return True

    def propose_reward_distribution_change(self, new_distribution: Dict[str, Decimal], proposer: str) -> bool:
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
        with self.lock:
            if proposal_index >= len(self.pending_ratio_changes) or proposal_index < 0:
                self.logger.error("Invalid proposal index.")
                return False

            proposal = self.pending_ratio_changes[proposal_index]

            if proposal['approved']:
                self.logger.warning(f"Proposal {proposal_index} has already been approved.")
                return False

            proposal['votes'] += 1
            self.logger.info(
                f"{voter} voted on proposal {proposal_index}. Total votes: {proposal['votes']}."
            )

            if proposal['votes'] >= self.governance_vote_threshold:
                self._apply_reward_distribution_change(proposal['new_distribution'])
                proposal['approved'] = True
                self.logger.info(
                    f"Proposal {proposal_index} approved. Reward distribution updated to {proposal['new_distribution']}."
                )
            return True

    def _apply_reward_distribution_change(self, new_distribution: Dict[str, Decimal]) -> None:
        with self.lock:
            self.reward_distribution = new_distribution
            self.logger.info(f"Reward distribution successfully updated to {self.reward_distribution}.")

    def _validate_distribution(self, distribution: Dict[str, Decimal]) -> bool:
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
        with self.lock:
            self._check_and_halve_reward()
            block_reward = self.current_reward
            total_reward = block_reward + total_fee

            distribution = self.reward_distribution
            validator_reward = (total_reward * distribution.get('validator', Decimal('0.0'))).quantize(Decimal('0.000000000000000001'))
            miner_reward = (
                (total_reward * distribution.get('miner', Decimal('0.0')))
                .quantize(Decimal('0.000000000000000001')) if miner_address else Decimal('0')
            )
            treasury_reward = (total_reward * distribution.get('treasury', Decimal('0.0'))).quantize(Decimal('0.000000000000000001'))

            if self.total_minted + total_reward > self.coin_max:
                allowed_reward = self.coin_max - self.total_minted
                if allowed_reward <= Decimal('0'):
                    self.logger.warning("Max supply reached. No more rewards can be minted.")
                    return {
                        'validator': Decimal('0'), 
                        'miner': Decimal('0'), 
                        'treasury': Decimal('0')
                    }
                validator_reward = (allowed_reward * distribution.get('validator', Decimal('0.0'))).quantize(Decimal('0.000000000000000001'))
                miner_reward = (allowed_reward * distribution.get('miner', Decimal('0.0'))).quantize(Decimal('0.000000000000000001')) if miner_address else Decimal('0')
                treasury_reward = (allowed_reward * distribution.get('treasury', Decimal('0.0'))).quantize(Decimal('0.000000000000000001'))
                total_reward = validator_reward + miner_reward + treasury_reward
                self.logger.warning(
                    f"Minting adjusted to not exceed max supply. Minted {total_reward} OMC instead of {block_reward + total_fee} OMC."
                )

            self.total_minted += total_reward

            self.logger.info(
                f"Minted {total_reward} OMC for block {current_block_height}: "
                f"{validator_reward} OMC to validator, {miner_reward} OMC to miner, and {treasury_reward} OMC to treasury."
            )

            self._distribute_rewards(validator_address, validator_reward, miner_address, miner_reward, treasury_reward)
            return {
                'validator': validator_reward, 
                'miner': miner_reward, 
                'treasury': treasury_reward
            }

    ## [CHANGED] Called by the consensus engine after the block is added,
    ## so we can figure out who the steward is and pay them.
    def reward_validator(self, validator_address: str, block_index: int) -> None:
        """
        Looks up the staking agreement for this validator, 
        finds the steward address, and mints the block reward to that steward.
        """
        if not self.staking_manager:
            self.logger.warning("No staking manager set; cannot reward validator.")
            return

        # This call might also be integrated with 'mint_for_block_fee' if you prefer.
        block_reward = Decimal('0')
        # Example: you might want to do some custom logic. For now just do a default reward:
        block_reward = self.current_reward  # or something else

        agreement = None
        all_agreements = self.staking_manager.get_active_staking_agreements()
        for agr in all_agreements:
            if agr['validator_address'] == validator_address:
                agreement = agr
                break

        if not agreement:
            self.logger.warning(f"No staking agreement found for validator {validator_address}. No reward minted.")
            return

        steward_addr = agreement['steward_address']
        self.logger.info(f"Rewarding steward {steward_addr} for block {block_index}, validator={validator_address}")

        self.mint_coins_and_send(steward_addr, block_reward)

    def _check_and_halve_reward(self):
        now = datetime.now(timezone.utc)
        if now - self.last_halving_date >= self.halving_interval:
            new_reward = (self.current_reward / 2).quantize(Decimal('0.000000000000000001'))
            if new_reward < Decimal('1.000000000000000000'):
                new_reward = Decimal('1.000000000000000000')
                self.logger.info(
                    f"Block reward halved from {self.current_reward} to {new_reward} OMC. Minimum reward reached."
                )
            else:
                self.logger.info(
                    f"Block reward halved from {self.current_reward} to {new_reward} OMC."
                )
            self.current_reward = new_reward
            self.last_halving_date = now

    def _distribute_rewards(self, validator_address: str, validator_reward: Decimal,
                            miner_address: Optional[str], miner_reward: Decimal,
                            treasury_reward: Decimal) -> None:
        # Distribute to validator (if you are *directly* crediting the VRF address).
        # But if you want them to get 0 because the steward is the real payee,
        # you can set validator_reward=0 above. Or leave it as is if your design
        # wants them also to get a partial reward.
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

    def create_transfer_request(self, from_address: str, to_address: str, amount: Decimal, permission: Dict[str, Any]) -> TransferRequest:
        if self.check_double_spending(from_address, to_address, amount):
            raise DoubleSpendingError("Double spending detected.")
        request_id = self.generate_request_id()
        permission['id'] = request_id
        permission['processed'] = None
        transfer_request = TransferRequest(from_address, to_address, amount, permission)
        with self.lock:
            self.request_queue.put(transfer_request)
            self.logger.info(f"Transfer request {request_id} created from {from_address} to {to_address} for amount {amount} OMC.")
        return transfer_request

    def approve_transfer_request(self, request_id: str, sender_pub: str, permission_sig: str) -> bool:
        with self.lock:
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
            self.request_queue = temp_queue
            return found

    def decline_transfer_request(self, request_id: str) -> bool:
        with self.lock:
            found = False
            temp_queue = queue.Queue()
            while not self.request_queue.empty():
                request = self.request_queue.get()
                if request.permission['id'] == request_id:
                    request.status = "declined"
                    self.logger.info(f"Transfer request {request_id} declined.")
                    found = True
                    continue
                temp_queue.put(request)
            self.request_queue = temp_queue
            return found

    def process_transfer_request(self, request_id: str) -> bool:
        with self.lock:
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
                else:
                    temp_queue.put(request)
            self.request_queue = temp_queue
            return found

    def get_request_by_id(self, request_id: str) -> Optional[TransferRequest]:
        with self.lock:
            temp_queue = queue.Queue()
            found_request = None
            while not self.request_queue.empty():
                req = self.request_queue.get()
                if req.permission['id'] == request_id:
                    found_request = req
                temp_queue.put(req)
            self.request_queue = temp_queue
            return found_request

    def get_pending_requests_for_user(self, address: str) -> List[Dict[str, Any]]:
        with self.lock:
            temp_queue = queue.Queue()
            pending_requests = []
            while not self.request_queue.empty():
                request = self.request_queue.get()
                if request.to_address == address and request.status == "pending":
                    pending_requests.append({
                        'from_address': request.from_address,
                        'to_address': request.to_address,
                        'amount': request.amount,
                        'request_id': request.permission['id'],
                        'timestamp': request.timestamp.isoformat()
                    })
                temp_queue.put(request)
            self.request_queue = temp_queue
            return pending_requests

    def update_request_permissions(self, request_id: str, sender_pub: str, permission_sig: str, permission_approval: str) -> bool:
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

    def transfer(self, from_address: str, to_address: str, amount: Decimal) -> bool:
        with self.account_manager.balances_lock:
            if from_address not in self.account_manager.accounts:
                self.logger.error("Sender address does not exist.")
                return False

            if self.account_manager.accounts[from_address]["OMC"] < amount:
                self.logger.error("Insufficient balance for transfer.")
                return False

            self.account_manager.debit_account(from_address, amount)
            self.account_manager.credit_account(to_address, amount)
            self.transfer_history.append((from_address, to_address, amount))
            self.logger.info(f"Transferred {amount} OMC from {from_address} to {to_address}.")
            return True

    def generate_request_id(self) -> str:
        random_number = secrets.randbelow(10**40)
        cryptographic_number = f'0r{random_number:040d}'
        return cryptographic_number

    def get_balance(self, address: str) -> Optional[Decimal]:
        with self.account_manager.balances_lock:
            balance = self.account_manager.balances.get(address)
            if balance is not None:
                self.logger.debug(f"[OMC] Retrieved balance for {address}: {balance} OMC.")
            else:
                self.logger.debug(f"[OMC] Balance for {address} not found.")
            return balance

    def shutdown(self):
        self.logger.info("Shutting down OMC.")
        # Implement any necessary cleanup

class DoubleSpendingError(Exception):
    pass
