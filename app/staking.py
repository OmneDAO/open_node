# staking.py

import logging
import secrets
from decimal import Decimal
from datetime import datetime, timezone, timedelta
from typing import List, Dict, Optional
import threading

from account_manager import AccountManager
from omc import OMC
from staked_omc import StakedOMC

logger = logging.getLogger('StakingModule')
logger.setLevel(logging.INFO)
handler = logging.StreamHandler()
formatter = logging.Formatter('[%(asctime)s] [%(levelname)s] [%(name)s] %(message)s')
handler.setFormatter(formatter)
if not logger.handlers:
    logger.addHandler(handler)

class StakingMngr:
    """
    Manages who is staked, how much, and how long. 
    Calls staked_omc.mint(...) to give sOMC, and references OMC to debit normal coins.
    """
    def __init__(self, omc: OMC, account_manager: AccountManager, staked_omc: StakedOMC):
        self.logger = logger
        self.omc = omc
        self.account_manager = account_manager
        self.staked_omc = staked_omc

        self.staking_agreements: List[Dict] = []
        self.lock = threading.Lock()

        self.logger.info("[StakingMngr] Staking Manager initialized.")

    def stake_coins(
        self,
        staker_address: str,
        stake_amount: Decimal,
        min_term_days: int,
        node_address: str
    ) -> Optional[Dict]:
        """
        Actually stakes 'stake_amount' OMC from staker_address, 
        mints sOMC via StakedOMC, and appends an agreement so this user 
        can appear in get_active_validators().
        """
        with self.lock:
            self.logger.info(f"Staking {stake_amount} OMC from {staker_address}, term={min_term_days} days.")
            current_balance = self.account_manager.get_account_balance(staker_address)
            if current_balance is None or current_balance < stake_amount:
                self.logger.error("Insufficient OMC balance for staking.")
                return None

            # 1) Debit OMC from user
            success_debit = self.account_manager.debit_account(staker_address, stake_amount)
            if not success_debit:
                self.logger.error("Failed to debit staker's OMC. Aborting stake_coins.")
                return None

            # 2) Mint sOMC 1:1
            minted_ok = self.staked_omc.mint(staker_address, stake_amount)
            if not minted_ok:
                self.logger.error("Minting sOMC failed. Reverting OMC debit.")
                # revert
                self.account_manager.credit_account(staker_address, stake_amount)
                return None

            # 3) Append a new agreement
            contract_id = '0s' + secrets.token_hex(16)
            start_dt = datetime.now(timezone.utc)
            agreement = {
                'contract_id': contract_id,
                'address': staker_address,
                'node_address': node_address,
                'amount_omc': stake_amount,
                'min_term_days': min_term_days,
                'start_date': start_dt.isoformat(),
                'withdrawals': 0,
            }
            self.staking_agreements.append(agreement)

            # Optionally, update omc.total_staked
            with self.omc.lock:
                self.omc.total_staked += stake_amount

            self.logger.info(f"[StakingMngr] Created staking agreement: {agreement}")
            return agreement

    def unstake_coins(
        self,
        staker_address: str,
        contract_id: str,
        force: bool = False
    ) -> bool:
        """
        Unstake logic. Burns sOMC from staker_address and credits OMC back. 
        If not 'force', checks min_term_days.
        """
        with self.lock:
            agreement = next((a for a in self.staking_agreements if a['contract_id'] == contract_id), None)
            if not agreement:
                self.logger.error(f"No staking agreement found for {contract_id}.")
                return False

            if agreement['address'] != staker_address:
                self.logger.error(f"Agreement {contract_id} belongs to {agreement['address']}, not {staker_address}.")
                return False

            min_term_days = agreement['min_term_days']
            start_dt = datetime.fromisoformat(agreement['start_date'])
            if not force:
                if datetime.now(timezone.utc) < (start_dt + timedelta(days=min_term_days)):
                    self.logger.error("Min term not reached. Unstake is blocked.")
                    return False

            # Burn sOMC
            stake_amount = agreement['amount_omc']
            burned = self.staked_omc.burn(staker_address, stake_amount)
            if not burned:
                self.logger.error("Failed to burn sOMC. Unstake aborted.")
                return False

            # Credit OMC back
            credited = self.account_manager.credit_account(staker_address, stake_amount)
            if not credited:
                self.logger.error("Failed to credit OMC back. Attempt re-mint sOMC.")
                self.staked_omc.mint(staker_address, stake_amount)
                return False

            # Remove from local list
            self.staking_agreements.remove(agreement)
            with self.omc.lock:
                self.omc.total_staked -= stake_amount

            self.logger.info(f"Unstake success for {staker_address}, contract {contract_id}.")
            return True

    def get_active_staking_agreements(self) -> List[Dict]:
        """
        Return all staking agreements that are presumably in an "active" state 
        (not unstaked or forcibly removed).
        """
        # Simple approach: everything in self.staking_agreements is "active"
        with self.lock:
            return list(self.staking_agreements)
