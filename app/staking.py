# ~/app/staking.py

import logging
from datetime import datetime, timezone
import secrets
from decimal import Decimal
from typing import Union

from omc import OMC  # Ensure correct import path
from account_manager import AccountManager  # Ensure correct import path
from staked_omc import StakedOMC  # Assuming you create staked_omc.py

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

    def mint(self, recipient, amount):
        """
        Mint staked coins and send them to the specified recipient.
        """
        logging.info(f"Minting staked coins: recipient={recipient}, amount={amount}")
        if amount <= 0:
            raise ValueError("Amount must be a positive value")

        # Convert the staked amount to a value with the correct number of decimal places
        amount_with_decimals = amount * (10 ** self.decimals)
        logging.info(f"Amount with decimals: {amount_with_decimals}")

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

        logging.info(f"Minted {amount_with_decimals} staked coins to {recipient}. Total distributed: {self.staked_omc_distributed}")

class StakingMngr:
    def __init__(self, coin: OMC, account_manager: AccountManager, staked_omc: StakedOMC):
        self.staking_accounts = []
        self.staking_agreements = []
        self.coin = coin
        self.account_manager = account_manager
        self.staked_omc = staked_omc

    def stake_coins(self, node_address, address, amount, min_term, pub_key):
        # Implement staking logic
        logging.info(f"Stake on node: {node_address}, address: {address}, amount: {amount}, min_term: {min_term}, pub_key: {pub_key}")
        
        try:
            if not self.check_balance_for_staking(address, amount):
                raise ValueError("Insufficient balance for staking")
        except ValueError as e:
            raise ValueError("Failed to check balance for staking: " + str(e))

        # Generate a unique hexadecimal contract ID for the staking agreement
        contract_id = '0s' + secrets.token_hex(16)
        logging.info(f"Generated contract ID: {contract_id}")

        # Debit the wallet for the staked amount
        try:
            self.account_manager.debit_account(address, amount)
        except ValueError as e:
            raise ValueError("Failed to debit wallet for staked coins: " + str(e))

        # Append the staking contract to the staked_coins list in OMC
        staking_contract = {
            'contract_id': contract_id,
            'address': address,
            'amount': amount,
            'min_term': min_term,
            'node_address': node_address,
            'withdrawals': 0,
            'start_date': str(datetime.now(timezone.utc))
        }
        self.coin.staked_coins.append(staking_contract)

        # Add the staked amount to the total_staked attribute in OMC
        self.coin.total_staked += amount
        logging.info(f"Total staked amount updated: {self.coin.total_staked}")

        # Mint StakedOMC and send them to the wallet
        try:
            self.staked_omc.mint(address, amount)
        except ValueError as e:
            raise ValueError(f"Failed to mint staked coins: {e}")

        # Add staking details to the wallet's staking agreements
        self.staking_agreements.append(staking_contract)
        logging.warning(f"Staked {amount} OMC for {min_term} days successfully. Contract ID: {contract_id}")

        # Return the staking contract to the caller
        return staking_contract

    def check_balance_for_staking(self, address: str, amount: Union[int, float]) -> bool:
        """
        Check if the address has enough balance for the proposed staking operation.

        Args:
            address (str): The address to check.
            amount (Decimal): The amount to check for staking.

        Returns:
            bool: True if the balance is sufficient, False otherwise.
        """
        account_balance = self.coin.get_balance(address)
        logging.info(f"Checking balance for staking: address={address}, balance={account_balance}, amount={amount}")
        return account_balance >= amount
