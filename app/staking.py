# ~/app/staking.py

import logging
from datetime import datetime, timezone, timedelta
import secrets
from decimal import Decimal
from typing import Union, List, Dict, Optional

import threading  # Import threading for locks

from omc import OMC  # Ensure correct import path
from account_manager import AccountManager  # Ensure correct import path
from staked_omc import StakedOMC  # Assuming you create staked_omc.py

# Configure logging for the staking module
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger('StakingModule')


class StakedOMC:
    def __init__(self, name='Staked OMC', symbol='sOMC', decimals=18):
        self.accounts = []
        self.name = name
        self.id = None
        self.symbol = symbol
        self.decimals = decimals
        self.id = "0z48d76b0690dcdcb32f1893d75c99681f2b595b36"
        self.image = "https://bafybeihbanfylphrqzpzgaibz6pwwl7wyq7kp2n2yt2bq4irrrwirwgcga.ipfs.w3s.link/sOMC-3.png"
        self.balance = {}
        self.burn_address = "0z0000000000000000000000000000000000000000"
        self.staked_omc_distributed = 0.0
        self.treasury_address = None

        # Initialize a lock for thread-safe operations on balance and accounts
        self.lock = threading.Lock()

    def mint(self, recipient: str, amount: float):
        """
        Mint staked coins and send them to the specified recipient.
        """
        logger.info(f"Minting staked coins: recipient={recipient}, amount={amount}")
        if amount <= 0:
            raise ValueError("Amount must be a positive value")

        # Convert the staked amount to a value with the correct number of decimal places
        amount_with_decimals = amount * (10 ** self.decimals)
        logger.info(f"Amount with decimals: {amount_with_decimals}")

        with self.lock:
            if recipient not in self.balance:
                self.balance[recipient] = 0

            self.balance[recipient] += amount_with_decimals
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

        logger.info(f"Minted {amount_with_decimals} staked coins to {recipient}. Total distributed: {self.staked_omc_distributed}")


class StakingMngr:
    def __init__(self, coin: OMC, account_manager: AccountManager, staked_omc: StakedOMC):
        self.staking_accounts: List[Dict] = []
        self.staking_agreements: List[Dict] = []
        self.coin = coin
        self.account_manager = account_manager
        self.staked_omc = staked_omc

        # Initialize locks for thread-safe operations
        self.accounts_lock = threading.Lock()
        self.agreements_lock = threading.Lock()

        logger.info("Staking Manager initialized.")

    def stake_coins(self, node_address: str, address: str, amount: float, min_term: int, pub_key: str) -> Dict:
        """
        Implements the staking logic, allowing users to stake coins on a specific node.
        
        :param node_address: Address of the node to stake on.
        :param address: Address of the user staking the coins.
        :param amount: Amount of coins to stake.
        :param min_term: Minimum staking term (e.g., in days).
        :param pub_key: Public key of the staker.
        :return: The staking contract details.
        """
        logger.info(f"Stake on node: {node_address}, address: {address}, amount: {amount}, min_term: {min_term}, pub_key: {pub_key}")

        try:
            if not self.check_balance_for_staking(address, amount):
                raise ValueError("Insufficient balance for staking")
        except ValueError as e:
            logger.error(f"Failed to check balance for staking: {e}")
            raise

        # Generate a unique hexadecimal contract ID for the staking agreement
        contract_id = '0s' + secrets.token_hex(16)
        logger.info(f"Generated contract ID: {contract_id}")

        # Debit the wallet for the staked amount
        try:
            self.account_manager.debit_account(address, amount)
        except ValueError as e:
            logger.error(f"Failed to debit wallet for staked coins: {e}")
            raise

        # Create the staking contract
        staking_contract = {
            'contract_id': contract_id,
            'address': address,
            'amount': amount,
            'min_term': min_term,
            'node_address': node_address,
            'withdrawals': 0,
            'start_date': datetime.now(timezone.utc).isoformat(),
            'pub_key': pub_key  # Store public key for verification purposes
        }

        # Append the staking contract to the staked_coins list in OMC
        with self.agreements_lock:
            self.coin.staked_coins.append(staking_contract)
            self.staking_agreements.append(staking_contract)

        # Add the staked amount to the total_staked attribute in OMC
        with self.coin.lock:  # Assuming OMC has its own lock for thread safety
            self.coin.total_staked += amount
            logger.info(f"Total staked amount updated: {self.coin.total_staked}")

        # Mint StakedOMC and send them to the wallet
        try:
            self.staked_omc.mint(address, amount)
        except ValueError as e:
            logger.error(f"Failed to mint staked coins: {e}")
            raise

        logger.warning(f"Staked {amount} OMC for {min_term} days successfully. Contract ID: {contract_id}")

        # Return the staking contract to the caller
        return staking_contract

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

        Returns:
            List[Dict]: A list of all staking agreements.
        """
        with self.agreements_lock:
            return list(self.staking_agreements)  # Return a shallow copy to prevent external modifications

    def get_total_staked(self) -> float:
        """
        Retrieves the total amount staked across all agreements.

        Returns:
            float: Total staked amount.
        """
        with self.coin.lock:  # Assuming OMC has its own lock
            return self.coin.total_staked

    def get_staked_omc_distributed(self) -> float:
        """
        Retrieves the total amount of StakedOMC distributed.

        Returns:
            float: Total StakedOMC distributed.
        """
        with self.staked_omc.lock:  # Assuming StakedOMC has its own lock
            return self.staked_omc.staked_omc_distributed
