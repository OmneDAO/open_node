"""
OMC Core - Pure Token Implementation without Genesis Operations

This module contains the core OMC token functionality that must be identical
across all nodes for nexum validation. Genesis and treasury operations are
handled by separate classes to maintain separation of concerns.
"""

import logging
import threading
from datetime import datetime, timezone, timedelta
from decimal import Decimal, InvalidOperation
from typing import Dict, List, Set, Optional, Any, Tuple
import queue


class OMCCore:
    """
    Core OMC token implementation without genesis-specific operations.
    
    This class contains only the essential token mechanics that must be
    identical across all node types for network consensus.
    """
    
    def __init__(
        self,
        account_manager,
        coin_max: Decimal = Decimal('22000000'),
        halving_interval_days: int = 1461,
        governance_vote_threshold: int = 10
    ):
        self.logger = logging.getLogger('OMCCore')
        self.logger.setLevel(logging.INFO)
        handler = logging.StreamHandler()
        formatter = logging.Formatter('[%(asctime)s] [%(levelname)s] [%(name)s] %(message)s')
        handler.setFormatter(formatter)
        if not self.logger.handlers:
            self.logger.addHandler(handler)

        self.account_manager = account_manager
        self.name = 'Omne Coin'
        self.symbol = 'OMC'
        self.decimals = 18
        self.image = "https://w3s.link/ipfs/bafybeih4yyumkffmdze4rb3hy3yfz66hbv5jxb76czr25xvpjufvbwd22a"

        self.coin_max = coin_max * (10 ** self.decimals)
        self.halving_interval = timedelta(days=halving_interval_days)
        self.staking_manager = None

        self.lock = threading.RLock()
        self.last_halving_date = datetime.now(timezone.utc)
        self.current_reward = Decimal('50')  # Default reward
        self.total_minted = Decimal('0')
        self.governance_vote_threshold = governance_vote_threshold
        self.pending_ratio_changes: List[Dict[str, Any]] = []
        self.total_staked = Decimal('0')
        self.active_validators: Set[str] = set()
        self.validator_url_mapping: Dict[str, str] = {}
        self.transfer_history: List[Tuple[str, str, Decimal]] = []
        self.minting_history: List[Tuple[str, Decimal]] = []
        self.burning_history: List[Decimal] = []
        self.request_queue = queue.Queue()

        self.logger.info(f"OMCCore initialized with max supply {self.coin_max} OMC")
            
    def set_staking_manager(self, staking_manager):
        self.staking_manager = staking_manager
        self.logger.info("StakingManager has been set in OMCCore.")

    def update_reward(self, new_reward: Decimal) -> bool:
        """Update the current block reward"""
        with self.lock:
            self.current_reward = new_reward
            self.logger.info(f"Block reward updated to {new_reward} OMC")
            return True

    def check_halving(self) -> bool:
        """Check if halving should occur based on time interval"""
        with self.lock:
            now = datetime.now(timezone.utc)
            if now - self.last_halving_date >= self.halving_interval:
                self.current_reward = self.current_reward / 2
                self.last_halving_date = now
                self.logger.info(f"Halving triggered. New reward: {self.current_reward} OMC")
                return True
            return False

    def get_balance(self, address: str) -> Decimal:
        """Get the OMC balance for an address"""
        return self.account_manager.get_balance(address)

    def transfer(self, from_address: str, to_address: str, amount: Decimal) -> bool:
        """Transfer OMC between addresses"""
        try:
            amount_decimal = Decimal(str(amount))
            if amount_decimal <= 0:
                self.logger.error("Transfer amount must be positive")
                return False

            with self.lock:
                # Check balance
                current_balance = self.get_balance(from_address)
                if current_balance < amount_decimal:
                    self.logger.error(f"Insufficient balance: {current_balance} < {amount_decimal}")
                    return False

                # Perform transfer
                if self.account_manager.debit_account(from_address, amount_decimal):
                    if self.account_manager.credit_account(to_address, amount_decimal):
                        self.transfer_history.append((from_address, to_address, amount_decimal))
                        self.logger.info(f"Transfer: {amount_decimal} OMC from {from_address} to {to_address}")
                        return True
                    else:
                        # Rollback debit if credit fails
                        self.account_manager.credit_account(from_address, amount_decimal)
                        self.logger.error("Transfer failed: could not credit recipient")
                        return False
                else:
                    self.logger.error("Transfer failed: could not debit sender")
                    return False

        except (InvalidOperation, ValueError) as e:
            self.logger.error(f"Invalid transfer amount: {e}")
            return False

    def mint_tokens(self, recipient: str, amount: Decimal) -> bool:
        """Mint new tokens (for block rewards, etc.)"""
        try:
            amount_decimal = Decimal(str(amount))
            if amount_decimal <= 0:
                self.logger.error("Mint amount must be positive")
                return False

            with self.lock:
                # Check if minting would exceed max supply
                if self.total_minted + amount_decimal > self.coin_max:
                    self.logger.error(f"Minting would exceed max supply: {self.total_minted + amount_decimal} > {self.coin_max}")
                    return False

                # Mint tokens
                if self.account_manager.credit_account(recipient, amount_decimal):
                    self.total_minted += amount_decimal
                    self.minting_history.append((recipient, amount_decimal))
                    self.logger.info(f"Minted {amount_decimal} OMC to {recipient}")
                    return True
                else:
                    self.logger.error("Minting failed: could not credit account")
                    return False

        except (InvalidOperation, ValueError) as e:
            self.logger.error(f"Invalid mint amount: {e}")
            return False

    def burn_tokens(self, from_address: str, amount: Decimal) -> bool:
        """Burn tokens by removing them from circulation"""
        try:
            amount_decimal = Decimal(str(amount))
            if amount_decimal <= 0:
                self.logger.error("Burn amount must be positive")
                return False

            with self.lock:
                current_balance = self.get_balance(from_address)
                if current_balance < amount_decimal:
                    self.logger.error(f"Insufficient balance to burn: {current_balance} < {amount_decimal}")
                    return False

                if self.account_manager.debit_account(from_address, amount_decimal):
                    self.total_minted -= amount_decimal  # Reduce total supply
                    self.burning_history.append(amount_decimal)
                    self.logger.info(f"Burned {amount_decimal} OMC from {from_address}")
                    return True
                else:
                    self.logger.error("Burning failed: could not debit account")
                    return False

        except (InvalidOperation, ValueError) as e:
            self.logger.error(f"Invalid burn amount: {e}")
            return False

    def reward_validator(self, validator_address: str, block_index: int) -> bool:
        """Reward validator for block production"""
        try:
            with self.lock:
                # Check if halving should occur
                self.check_halving()

                reward_amount = self.current_reward
                if reward_amount <= 0:
                    self.logger.info("No reward to distribute")
                    return True

                # Mint reward tokens
                if self.mint_tokens(validator_address, reward_amount):
                    self.logger.info(f"Rewarded validator {validator_address} with {reward_amount} OMC for block {block_index}")
                    return True
                else:
                    self.logger.error(f"Failed to reward validator {validator_address}")
                    return False

        except Exception as e:
            self.logger.error(f"Error rewarding validator: {e}")
            return False

    def get_total_supply(self) -> Decimal:
        """Get the current total supply of OMC"""
        return self.total_minted

    def get_max_supply(self) -> Decimal:
        """Get the maximum possible supply of OMC"""
        return self.coin_max

    def get_current_reward(self) -> Decimal:
        """Get the current block reward"""
        return self.current_reward

    def get_validator_info(self, validator_id: str) -> Optional[Dict[str, Any]]:
        """Get information about a validator"""
        if validator_id in self.active_validators:
            return {
                'validator_id': validator_id,
                'active': True,
                'url': self.validator_url_mapping.get(validator_id),
                'balance': self.get_balance(validator_id)
            }
        return None

    def get_active_validators(self) -> List[str]:
        """Get list of active validators"""
        return list(self.active_validators)

    def add_validator(self, validator_id: str, url: Optional[str] = None) -> bool:
        """Add a validator to the active set"""
        with self.lock:
            self.active_validators.add(validator_id)
            if url:
                self.validator_url_mapping[validator_id] = url
            self.logger.info(f"Added validator {validator_id}")
            return True

    def remove_validator(self, validator_id: str) -> bool:
        """Remove a validator from the active set"""
        with self.lock:
            if validator_id in self.active_validators:
                self.active_validators.remove(validator_id)
                if validator_id in self.validator_url_mapping:
                    del self.validator_url_mapping[validator_id]
                self.logger.info(f"Removed validator {validator_id}")
                return True
            return False

    def get_minimum_stake(self) -> Decimal:
        """Get the minimum stake required for validation"""
        return Decimal('1000') * (10 ** self.decimals)  # 1000 OMC minimum stake


class TransferRequest:
    """Request structure for OMC transfers"""
    
    def __init__(self, from_address: str, to_address: str, amount: Decimal, timestamp: Optional[datetime] = None):
        self.from_address = from_address
        self.to_address = to_address
        self.amount = amount
        self.timestamp = timestamp or datetime.now(timezone.utc)
        self.request_id = f"{from_address}_{to_address}_{amount}_{int(self.timestamp.timestamp())}"

    def to_dict(self) -> Dict[str, Any]:
        return {
            'request_id': self.request_id,
            'from_address': self.from_address,
            'to_address': self.to_address,
            'amount': str(self.amount),
            'timestamp': self.timestamp.isoformat()
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'TransferRequest':
        return cls(
            from_address=data['from_address'],
            to_address=data['to_address'],
            amount=Decimal(data['amount']),
            timestamp=datetime.fromisoformat(data['timestamp'])
        )

    def validate(self) -> bool:
        """Validate the transfer request"""
        if not self.from_address or not self.to_address:
            return False
        if self.amount <= 0:
            return False
        if self.from_address == self.to_address:
            return False
        return True
