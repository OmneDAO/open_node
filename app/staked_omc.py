# staked_omc.py

import logging
from decimal import Decimal
from threading import Lock
from typing import Any, Dict, Optional, List

from crypto_utils import CryptoUtils  # Ensure CryptoUtils is correctly implemented


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
    """
    def __init__(
        self,
        account_manager, 
        ledger=None,  # Optional: Pass ledger if needed
        verifier=None,  # Optional: Pass verifier if needed
        treasury_address: str = "0z0000000000000000000000000000000000000000",
        treasury_private_key: str = "",
        decimals: int = 18
    ):
        """
        :param account_manager: Reference to AccountManager for managing balances.
        :param ledger: (Optional) Reference to Ledger for blockchain interactions.
        :param verifier: (Optional) Reference to Verifier for validating signatures.
        :param treasury_address: Address of the treasury.
        :param treasury_private_key: Private key of the treasury for signing transactions.
        :param decimals: Number of decimal places for sOMC.
        """
        self.account_manager = account_manager
        self.ledger = ledger
        self.verifier = verifier
        self.crypto_utils = CryptoUtils()
        self.decimals = decimals
        self.treasury_address = treasury_address
        self.treasury_private_key = treasury_private_key
        self.balance: Dict[str, Decimal] = {}
        self.staked_omc_distributed = Decimal('0')
        self.burn_address = "0z0000000000000000000000000000000000000000"

        # Initialize a lock for thread-safe operations on balance and accounts
        self.lock = Lock()

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
        if amount <= Decimal('0'):
            self.logger.error("Amount must be a positive value")
            raise ValueError("Amount must be a positive value")

        # Convert the staked amount to a value with the correct number of decimal places
        amount_with_decimals = amount * (10 ** self.decimals)
        self.logger.info(f"[StakedOMC] Amount with decimals: {amount_with_decimals}")

        with self.lock:
            if recipient not in self.balance:
                self.balance[recipient] = Decimal('0')

            self.balance[recipient] += amount_with_decimals
            self.staked_omc_distributed += amount_with_decimals

            # Update the account balance via AccountManager
            self.account_manager.credit_account(recipient, amount_with_decimals)

        self.logger.info(f"[StakedOMC] Minted {amount_with_decimals} sOMC to {recipient}. Total distributed: {self.staked_omc_distributed}")
        return True

    def burn(self, address: str, amount: Decimal) -> bool:
        """
        Burn staked coins by sending them to the burn address.

        :param address: Address from which to burn sOMC.
        :param amount: Amount of sOMC to burn.
        :return: True if burning is successful, False otherwise.
        """
        self.logger.info(f"[StakedOMC] Burning sOMC: address={address}, amount={amount}")
        if amount <= Decimal('0'):
            self.logger.error("Amount must be a positive value")
            raise ValueError("Amount must be a positive value")

        amount_with_decimals = amount * (10 ** self.decimals)

        with self.lock:
            if address not in self.balance or self.balance[address] < amount_with_decimals:
                self.logger.error("Insufficient balance for burning")
                raise ValueError("Insufficient balance for burning")

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
                'nonce': self.account_manager.get_next_nonce(address),
                'signature': '',  # To be filled after signing
                'public_key': self.crypto_utils.get_public_key(address),  # Assuming address can provide its public key
                'timestamp': datetime.now(timezone.utc).isoformat()
            }

            # Sign the burn transaction
            burn_tx['signature'] = self.crypto_utils.sign_message(self.treasury_private_key, burn_tx['hash'])

            # Add transaction to mempool
            if self.ledger and self.ledger.mempool:
                success = self.ledger.mempool.add_transaction(burn_tx)
                if success:
                    self.logger.info(f"[StakedOMC] Burn transaction added to mempool: {burn_tx['hash']}")
                else:
                    self.logger.error(f"[StakedOMC] Failed to add burn transaction to mempool: {burn_tx['hash']}")
                    return False
            else:
                self.logger.error("[StakedOMC] Ledger or Mempool not initialized. Cannot add burn transaction.")
                return False

        return True

    def get_balance(self, address: str) -> Optional[Decimal]:
        """
        Retrieves the sOMC balance of a given account.

        :param address: The address of the account.
        :return: sOMC balance as Decimal or None if account does not exist.
        """
        with self.lock:
            balance = self.balance.get(address)
            if balance is not None:
                logger.debug(f"[StakedOMC] Retrieved sOMC balance for {address}: {balance} sOMC.")
            else:
                logger.debug(f"[StakedOMC] sOMC balance for {address} not found.")
            return balance

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
