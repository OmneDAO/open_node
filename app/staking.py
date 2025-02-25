# staking.py

from __future__ import annotations
import logging
import secrets
from datetime import datetime, timezone
from decimal import Decimal
from typing import Union, List, Dict, Optional, TYPE_CHECKING
import threading

from omc import OMC
from account_manager import AccountManager

if TYPE_CHECKING:
    from omc import OMC

logger = logging.getLogger('StakingModule')
logger.setLevel(logging.INFO)
handler = logging.StreamHandler()
formatter = logging.Formatter('[%(asctime)s] [%(levelname)s] [%(name)s] %(message)s')
handler.setFormatter(formatter)
if not logger.handlers:
    logger.addHandler(handler)

class StakingMngr:
    def __init__(self, coin: OMC, account_manager: AccountManager, staked_omc: StakedOMC):
        self.staking_accounts: List[Dict] = []
        self.staking_agreements: List[Dict] = []
        self.coin = coin
        self.account_manager = account_manager
        self.staked_omc = staked_omc

        self.accounts_lock = threading.Lock()
        self.agreements_lock = threading.Lock()

        logger.info("Staking Manager initialized.")

    def stake_coins(self, node_address: str, address: str, amount: float, min_term: int, pub_key: str) -> Dict:
        logger.info(f"Stake on node: {node_address}, address: {address}, amount: {amount}, min_term: {min_term}, pub_key: {pub_key}")
        try:
            if not self.account_manager.get_account_balance(address) >= Decimal(amount):
                raise ValueError("Insufficient balance for staking")
        except Exception as e:
            logger.error(f"Failed to check balance for staking: {e}")
            raise

        contract_id = '0s' + secrets.token_hex(16)
        logger.info(f"Generated contract ID: {contract_id}")

        try:
            self.account_manager.debit_account(address, Decimal(amount))
        except Exception as e:
            logger.error(f"Failed to debit wallet for staked coins: {e}")
            raise

        staking_contract = {
            'contract_id': contract_id,
            'address': address,
            'amount': Decimal(amount),
            'min_term': min_term,
            'node_address': node_address,
            'withdrawals': 0,
            'start_block': 0,  # You could pass the current block height here
            'pub_key': pub_key,
            'start_date': datetime.now(timezone.utc).isoformat()
        }

        with self.agreements_lock:
            self.staking_agreements.append(staking_contract)

        with self.coin.lock:
            self.coin.total_staked += Decimal(amount)
            logger.info(f"Total staked amount updated: {self.coin.total_staked}")

        try:
            self.staked_omc.mint(address, Decimal(amount))
        except Exception as e:
            logger.error(f"Failed to mint staked coins: {e}")
            raise

        logger.info(f"Staked {amount} OMC for {min_term} days successfully. Contract ID: {contract_id}")
        return staking_contract

    def unstake_coins(self, address: str, contract_id: str, current_block_height: int = 0, force: bool = False) -> bool:
        """
        Unstakes coins from a staking contract managed by this staking manager.

        :param address: The address that staked coins.
        :param contract_id: The contract ID of the staking agreement.
        :param current_block_height: The current block height (used to check minimum term).
        :param force: If True, force unstake even if the minimum term is not met.
        :return: True if unstaking was successful, False otherwise.
        """
        with self.agreements_lock:
            # Find the agreement by contract_id
            contract = next((c for c in self.staking_agreements if c.get('contract_id') == contract_id), None)
            if not contract:
                logger.error(f"Staking contract ID {contract_id} not found.")
                return False

            if contract['address'] != address:
                logger.error(f"Address mismatch for contract ID {contract_id}. Expected {contract['address']}, got {address}.")
                return False

            # Check minimum term if not forced
            # Assume min_term is expressed in blocks; you could also compute using start_date if needed
            if not force and current_block_height < contract['start_block'] + contract['min_term']:
                remaining = (contract['start_block'] + contract['min_term']) - current_block_height
                logger.error(f"Cannot unstake contract ID {contract_id}. Remaining term: {remaining} blocks.")
                return False

            unstake_amount = contract['amount']
            # Remove the contract from staking agreements
            self.staking_agreements.remove(contract)
            logger.info(f"Staking contract {contract_id} removed for address {address}.")

        # Credit the account back using the account manager
        if not self.account_manager.credit_account(address, unstake_amount):
            logger.error(f"Failed to credit account {address} after unstaking.")
            return False

        with self.coin.lock:
            self.coin.total_staked -= unstake_amount
            logger.info(f"Updated total staked amount: {self.coin.total_staked}")

        # Emit an event for unstaking if your system supports it (not shown here)
        logger.info(f"Unstaked {unstake_amount} OMC from contract ID {contract_id} for {address}.")
        return True

    def check_balance_for_staking(self, address: str, amount: Union[int, float]) -> bool:
        """
        Check if the address has enough balance for the proposed staking operation.

        Args:
            address (str): The address to check.
            amount (Union[int, float]): The amount to check for staking.

        Returns:
            bool: True if the balance is sufficient, False otherwise.
        """
        try:
            account_balance = self.coin.get_balance(address)
            logger.info(f"Checking balance for staking: address={address}, balance={account_balance}, amount={amount}")
            return account_balance >= amount
        except Exception as e:
            logger.error(f"Error checking balance for staking: {e}")
            return False

    def get_active_staking_agreements(self) -> List[Dict]:
        """
        Retrieves a list of active staking agreements based on their start date and minimum term.

        Returns:
            List[Dict]: A list of active staking agreements.
        """
        active_agreements = []
        current_time = datetime.now(timezone.utc)

        with self.agreements_lock:
            for agreement in self.staking_agreements:
                start_date = datetime.fromisoformat(agreement['start_date'])
                min_term = agreement['min_term']  # Assuming min_term is in days
                staking_duration = timedelta(days=min_term)
                if current_time >= (start_date + staking_duration):
                    active_agreements.append(agreement)

        logger.debug(f"Retrieved {len(active_agreements)} active staking agreements.")
        return active_agreements

    def get_all_staking_agreements(self) -> List[Dict]:
        """
        Retrieves all staking agreements.

        :return: List of staking agreement dictionaries.
        """
        with self.agreements_lock:
            return list(self.staking_agreements)  # Return a shallow copy to prevent external modifications

    def get_total_staked(self) -> Decimal:
        """
        Retrieves the total amount staked across all agreements.

        :return: Total staked amount as Decimal.
        """
        with self.coin.lock:
            total = Decimal(self.coin.total_staked)
            logger.debug(f"[StakingMngr] Total staked: {total} OMC.")
            return total

    def get_staked_omc_distributed(self) -> Decimal:
        """
        Retrieves the total amount of StakedOMC distributed.

        :return: Total sOMC distributed as Decimal.
        """
        with self.staked_omc.lock:
            total = Decimal(self.staked_omc.staked_omc_distributed)
            logger.debug(f"[StakingMngr] Total sOMC distributed: {total} sOMC.")
            return total
