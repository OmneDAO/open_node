# staked_omc.py

import logging
import secrets
from typing import Dict, List, Optional
from decimal import Decimal
from datetime import datetime, timedelta, timezone

from ledger import Ledger
from verifier import Verifier
from crypto_utils import CryptoUtils
from mempool import Mempool

# Configure logger for StakedOMC
logger = logging.getLogger('StakedOMC')
logger.setLevel(logging.INFO)
handler = logging.StreamHandler()
formatter = logging.Formatter('[%(asctime)s] [%(levelname)s] [%(name)s] %(message)s')
handler.setFormatter(formatter)
if not logger.handlers:
    logger.addHandler(handler)

class StakedOMC:
    """
    Manages staked Omne Coin (sOMC) operations, including minting, burning, and balance tracking.
    Ensures that staked coins are securely managed and prohibits unauthorized transfers.
    """

    def __init__(self, ledger: Ledger, verifier: Verifier, treasury_address: str, treasury_private_key: str, decimals: int = 18):
        """
        :param ledger: Reference to Ledger for accessing and modifying blockchain state.
        :param verifier: Reference to Verifier for validator selection and stake weight calculations.
        :param treasury_address: Address of the treasury.
        :param treasury_private_key: Private key of the treasury for signing.
        :param decimals: Number of decimal places for sOMC.
        """
        self.ledger = ledger
        self.verifier = verifier
        self.crypto_utils = CryptoUtils()
        self.decimals = decimals
        self.treasury_address = treasury_address
        self.treasury_private_key = treasury_private_key
        self.accounts: List[Dict[str, Any]] = []
        self.burn_address = "0z0000000000000000000000000000000000000000"
        self.balance: Dict[str, Decimal] = {}
        self.staked_omc_distributed = Decimal('0')

        self.logger = logging.getLogger('StakedOMC')
        self.logger.info("[StakedOMC] Initialized StakedOMC.")

    def mint(self, recipient: str, amount: Decimal) -> bool:
        """
        Mint staked coins and send them to the specified recipient.

        :param recipient: Address to receive the minted sOMC.
        :param amount: Amount of sOMC to mint.
        :return: True if minting is successful, False otherwise.
        """
        self.logger.info(f"[StakedOMC] Minting sOMC: recipient={recipient}, amount={amount}")
        if amount <= 0:
            self.logger.error("Amount must be a positive value")
            return False

        # Convert the staked amount to a value with the correct number of decimal places
        amount_with_decimals = amount * (10 ** self.decimals)
        self.logger.info(f"[StakedOMC] Amount with decimals: {amount_with_decimals}")

        # Update balance
        self.balance[recipient] = self.balance.get(recipient, Decimal('0')) + amount_with_decimals
        self.staked_omc_distributed += amount_with_decimals

        # Check if the recipient already has an account in the accounts list
        account = next((acc for acc in self.accounts if acc['address'] == recipient), None)
        if account:
            # Update the existing account balance
            account['balance'] += amount_with_decimals
        else:
            # Create a new account object and add it to the accounts list
            new_account = {'address': recipient, 'balance': amount_with_decimals}
            self.accounts.append(new_account)

        self.logger.info(f"[StakedOMC] Minted {amount_with_decimals} sOMC to {recipient}. Total distributed: {self.staked_omc_distributed}")

        # Create and add staking transaction to mempool
        staking_tx = {
            'type': 'stake',
            'sender': self.treasury_address,
            'receiver': recipient,
            'amount': float(amount),
            'fee': '0',  # Assuming staking transactions have no fee
            'nonce': self.ledger.account_manager.get_next_nonce(self.treasury_address),
            'signature': '',  # To be filled after signing
            'public_key': self.crypto_utils.get_public_key(self.treasury_private_key),
            'timestamp': datetime.now(timezone.utc).isoformat()
        }

        # Sign the staking transaction
        staking_tx['signature'] = self.crypto_utils.sign_message(self.treasury_private_key, staking_tx['hash'])

        # Add transaction to mempool
        success = self.ledger.mempool.add_transaction(staking_tx)
        if success:
            self.logger.info(f"[StakedOMC] Staking transaction added to mempool: {staking_tx['hash']}")
        else:
            self.logger.error(f"[StakedOMC] Failed to add staking transaction to mempool: {staking_tx['hash']}")
            return False

        return True

    def burn(self, address: str, amount: Decimal) -> bool:
        """
        Burn staked coins by sending them to the burn address.

        :param address: Address from which to burn sOMC.
        :param amount: Amount of sOMC to burn.
        :return: True if burning is successful, False otherwise.
        """
        self.logger.info(f"[StakedOMC] Burning sOMC: address={address}, amount={amount}")
        if amount <= 0:
            self.logger.error("Amount must be a positive value")
            return False

        if address not in self.balance or self.balance[address] < amount * (10 ** self.decimals):
            self.logger.error("Insufficient balance for burning")
            return False

        # Convert the burn amount to a value with the correct number of decimal places
        amount_with_decimals = amount * (10 ** self.decimals)

        # Send the staked coins to the burn address
        self.balance[address] -= amount_with_decimals
        self.balance[self.burn_address] = self.balance.get(self.burn_address, Decimal('0')) + amount_with_decimals
        self.staked_omc_distributed -= amount_with_decimals

        self.logger.info(f"[StakedOMC] Burned {amount_with_decimals} sOMC from {address} to burn address. Total distributed: {self.staked_omc_distributed}")

        # Create and add burn transaction to mempool
        burn_tx = {
            'type': 'burn',
            'sender': address,
            'receiver': self.burn_address,
            'amount': float(amount),
            'fee': '0',  # Assuming burn transactions have no fee
            'nonce': self.ledger.account_manager.get_next_nonce(address),
            'signature': '',  # To be filled after signing
            'public_key': self.crypto_utils.get_public_key(address),  # Assuming address can provide its public key
            'timestamp': datetime.now(timezone.utc).isoformat()
        }

        # Sign the burn transaction
        burn_tx['signature'] = self.crypto_utils.sign_message(self.treasury_private_key, burn_tx['hash'])

        # Add transaction to mempool
        success = self.ledger.mempool.add_transaction(burn_tx)
        if success:
            self.logger.info(f"[StakedOMC] Burn transaction added to mempool: {burn_tx['hash']}")
        else:
            self.logger.error(f"[StakedOMC] Failed to add burn transaction to mempool: {burn_tx['hash']}")
            return False

        return True

    def get_balance(self, address: str) -> Decimal:
        """
        Get the balance of staked coins for a specific staker.

        :param address: Address to query.
        :return: Balance of sOMC.
        """
        return self.balance.get(address, Decimal('0'))

    def transfer(self, from_address: str, to_address: str, amount: Decimal) -> None:
        """
        Transfer of staked coins between stakers is prohibited.

        :param from_address: Address sending the sOMC.
        :param to_address: Address receiving the sOMC.
        :param amount: Amount of sOMC to transfer.
        :raises ValueError: Always, since transfers are prohibited.
        """
        raise ValueError("StakedCoin transfer between stakers is prohibited")

    def shutdown(self):
        """
        Gracefully shuts down the StakedOMC manager.
        """
        self.logger.info("[StakedOMC] Shutting down StakedOMC manager.")
        # Implement any necessary cleanup here
