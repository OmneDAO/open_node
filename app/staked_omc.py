# staked_omc.py

import logging
import secrets
from decimal import Decimal
from datetime import datetime, timezone
from typing import Dict, Optional
import json
import hashlib
import threading

from account_manager import AccountManager
from crypto_utils import CryptoUtils
from dynamic_fee_calculator import DynamicFeeCalculator

logger = logging.getLogger('StakedOMC')
logger.setLevel(logging.INFO)
handler = logging.StreamHandler()
formatter = logging.Formatter('[%(asctime)s] [%(levelname)s] [%(name)s] %(message)s')
handler.setFormatter(formatter)
if not logger.handlers:
    logger.addHandler(handler)

class DecimalEncoder(json.JSONEncoder):
    def default(self, obj):
        if isinstance(obj, Decimal):
            return format(obj, 'f')
        return super().default(obj)

class StakedOMC:
    """
    Manages minting/burning sOMC. Also can build “staking transactions” 
    to place on the blockchain, but does not itself manage who is an active validator.
    """
    def __init__(
        self,
        account_manager: AccountManager,
        decimals: int = 18
    ):
        self.logger = logger
        self.account_manager = account_manager
        self.decimals = decimals

        self.crypto_utils = CryptoUtils()
        self.balance_lock = threading.Lock()
        self.somc_balances: Dict[str, Decimal] = {}
        self.staked_omc_distributed = Decimal('0')

        self.logger.info("[StakedOMC] Initialized sOMC module.")

    def mint(self, recipient: str, amount_omc: Decimal) -> bool:
        """
        Mints sOMC for 'recipient'. 
        This does not create any “staking agreement” – that’s handled by StakingMngr.
        """
        with self.balance_lock:
            if amount_omc <= 0:
                self.logger.error("Cannot mint a non-positive amount.")
                return False
            raw = (amount_omc * (10 ** self.decimals)).quantize(Decimal('1'))
            self.somc_balances[recipient] = self.somc_balances.get(recipient, Decimal('0')) + raw
            self.staked_omc_distributed += raw

        self.logger.info(f"[StakedOMC] Minted {raw} sOMC for {recipient}. totalDist={self.staked_omc_distributed}")
        return True

    def burn(self, address: str, amount_omc: Decimal) -> bool:
        """
        Burns sOMC from address. Typically used to unstake.
        """
        with self.balance_lock:
            raw = (amount_omc * (10**self.decimals)).quantize(Decimal('1'))
            cur = self.somc_balances.get(address, Decimal('0'))
            if cur < raw:
                self.logger.error(f"Address {address} has insufficient sOMC to burn.")
                return False
            self.somc_balances[address] = cur - raw
            self.staked_omc_distributed -= raw

        self.logger.info(f"[StakedOMC] Burned {raw} sOMC from {address}.")
        return True

    def get_balance(self, address: str) -> Decimal:
        """
        Returns sOMC balance (raw, scaled by decimals) for address.
        """
        return self.somc_balances.get(address, Decimal('0'))

    # ----------------------------------------------------------------
    # Transaction builder for on-chain representation
    # ----------------------------------------------------------------
    def build_staking_transaction(
        self,
        fee_calculator: DynamicFeeCalculator,
        staker_address: str,
        stake_amount: Decimal,
        node_address: str,
        min_term_days: int = 200
    ) -> Dict:
        """
        Returns a base staking transaction structure – not signed, no 'hash' or 'signature'.
        The caller can fill in 'sender' if needed, or just treat 'staker_address' as the 'sender'.
        """
        stake_id = '0s' + secrets.token_hex(16)
        tx = {
            'stake_id': stake_id,
            'type': 'stake_creation',
            'address': staker_address,
            'node_address': node_address,
            'amount': str(stake_amount),
            'min_term_days': min_term_days,
            'timestamp': datetime.now(timezone.utc).isoformat(),
            'sender': staker_address,  # or leave empty if you want the caller to fill it
            'public_key': None,        # let the caller supply
            'fee': "0",
        }

        # (optionally compute fee)
        fee = fee_calculator.get_dynamic_fee(tx, 0, 100)
        tx['fee'] = str(fee)

        return tx
    
    def build_somc_mint_transaction(
        self,
        fee_calculator: DynamicFeeCalculator,
        recipient: str,
        mint_amount: Decimal
    ) -> Dict:
        """
        Build an *unsigned* on-chain transaction to represent minting sOMC
        to 'recipient' in the amount 'mint_amount'.
        This does NOT sign or do final hashing. The caller must sign it.
        """
        tx = {
            'type': 'somc_mint',
            'address': recipient,
            'balance': str(mint_amount),  # The minted sOMC
            'timestamp': datetime.now(timezone.utc).isoformat(),
            'sender': None,          # Let the caller fill in e.g. treasury address
            'public_key': None,      # Also let the caller provide
            'fee': "0"
        }

        fee = fee_calculator.get_dynamic_fee(tx, 0, 100)
        tx['fee'] = str(fee)

        return tx