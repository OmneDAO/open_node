import logging
import secrets
from datetime import datetime, timezone, date
import hashlib
import json
from decimal import Decimal
from threading import Lock
from typing import Any, Dict, Optional

from crypto_utils import CryptoUtils  # Ensure CryptoUtils is correctly implemented
from dynamic_fee_calculator import DynamicFeeCalculator

logger = logging.getLogger('StakedOMC')
logger.setLevel(logging.INFO)
handler = logging.StreamHandler()
formatter = logging.Formatter('[%(asctime)s] [%(levelname)s] [%(name)s] %(message)s')
handler.setFormatter(formatter)
if not logger.handlers:
    logger.addHandler(handler)

# Define a DecimalEncoder if needed for JSON serialization.
class DecimalEncoder(json.JSONEncoder):
    def default(self, obj):
        if isinstance(obj, Decimal):
            return format(obj, 'f')  # Force fixed-point format
        return super().default(obj)

class StakedOMC:
    """
    Manages staked Omne Coin (sOMC) operations, including minting, burning, and balance tracking.
    """
    def __init__(
        self,
        account_manager,
        ledger=None,      # Optional: Pass ledger if needed
        verifier=None,    # Optional: Pass verifier if needed
        treasury_address: str = "0z0ab101730c12632a805bf2dcf0762719ccebfd1b",
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
        self.name = 'Staked Omne Coin'
        self.symbol = 'sOMC'
        self.decimals = decimals
        self.image = "https://w3s.link/ipfs/bafybeiddmhq5tbcm3qxnzgwov5lzoeq4agc4zgjecs3ucvmjv3cqfbs4ii"
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

            # Update the sOMC balance using the provided AccountManager
            self.account_manager.credit_account(recipient, amount_with_decimals, token="sOMC")

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

            # Deduct the staked coins and add them to the burn address.
            self.balance[address] -= amount_with_decimals
            self.balance[self.burn_address] = self.balance.get(self.burn_address, Decimal('0')) + amount_with_decimals
            self.staked_omc_distributed -= amount_with_decimals

            self.logger.info(f"[StakedOMC] Burned {amount_with_decimals} sOMC from {address} to burn address. Total distributed: {self.staked_omc_distributed}")

            # (Optional) Create and add a burn transaction to the mempool if required.
            # ...

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
        """
        raise ValueError("StakedCoin transfer between stakers is prohibited")
    
    def create_staking_transaction(self, treasury_address: str, treasury_public_key: str, treasury_private_key: str, omc_initial_supply: Decimal, fee_calculator: DynamicFeeCalculator) -> Optional[Dict]:
        """
        Creates a staking transaction representing the staking contract.
        This transaction can then be included in a block.
        """
        min_term = 200
        reduced_balance = int(omc_initial_supply * Decimal('0.05'))
        contract_id = '0s' + secrets.token_hex(16)
        
        staking_tx = {
            'stake_id': contract_id,
            'address': treasury_address,
            'amount': reduced_balance,
            'min_term': min_term,
            'node_address': None,  # To be determined; could be set later by the consensus/validator selection
            'withdrawals': 0,
            'start_date': str(datetime.now(timezone.utc)),
            'type': 'c',  # or use a special type for staking transactions
            'public_key': treasury_public_key,
            'timestamp': datetime.now(timezone.utc).isoformat(),
            'sender': treasury_address,
            'fee': "0"  # Will be calculated below
        }
        
        # Determine the node address (fallback to current node)
        staking_tx['node_address'] = self.ledger.node.address
        
        # Calculate fee for the staking transaction
        fee = fee_calculator.get_dynamic_fee(staking_tx, 0, 100)
        staking_tx['fee'] = format(fee, 'f')
        
        # Build canonical payload (exclude 'signature' and 'hash')
        sorted_data = {k: staking_tx[k] for k in sorted(staking_tx) if k not in ['signature', 'hash']}
        payload = json.dumps(sorted_data, sort_keys=True, cls=DecimalEncoder).encode()
        # Compute the transaction hash
        tx_hash = hashlib.sha256(payload).hexdigest()
        staking_tx['hash'] = tx_hash
        
        # Sign the computed hash (rather than the decoded payload dict)
        try:
            # Pass the hash string to sign_message so that it calls bytes.fromhex() internally.
            staking_tx['signature'] = CryptoUtils().sign_message(treasury_private_key, tx_hash)
        except Exception as e:
            logger.error(f"Failed to sign staking transaction: {e}")
            return None
        
        # Validate required fields before returning
        required_fields = ['hash', 'timestamp', 'sender', 'fee', 'signature', 'public_key']
        missing = [field for field in required_fields if field not in staking_tx or staking_tx[field] is None]
        if missing:
            logger.error(f"Staking transaction validation failed. Missing: {missing}")
            return None
        
        return staking_tx


    def create_somc_mint_transaction(self,
                                    recipient: str,
                                    mint_amount: Decimal,
                                    fee_calculator: DynamicFeeCalculator,
                                    treasury_public_key: str,
                                    treasury_private_key: str) -> Optional[Dict]:
        """
        Creates a transaction to record the minting of sOMC tokens to the recipient.
        This transaction will be included on-chain.
        """
        tx = {
            'address': recipient,
            'balance': mint_amount,  # Already adjusted for decimals
            'type': 'somc_mint',
            'timestamp': datetime.now(timezone.utc).isoformat(),
            'withdrawals': 0,
            'fee': "0",  # Fee will be computed below
            'sender': self.treasury_address,
            'public_key': treasury_public_key,
        }
        # Calculate fee for the transaction
        fee = fee_calculator.get_dynamic_fee(tx, 0, 100)
        tx['fee'] = format(fee, 'f')
        
        # Build canonical payload (exclude 'signature' and 'hash')
        sorted_data = {k: tx[k] for k in sorted(tx) if k not in ['signature', 'hash']}
        payload = json.dumps(sorted_data, sort_keys=True, cls=DecimalEncoder).encode()
        # Compute the transaction hash
        tx_hash = hashlib.sha256(payload).hexdigest()
        tx['hash'] = tx_hash
        
        # Sign the computed hash using the treasury private key.
        try:
            tx['signature'] = CryptoUtils().sign_message(treasury_private_key, tx_hash)
        except Exception as e:
            logger.error(f"Failed to sign sOMC mint transaction: {e}")
            return None
        
        # Validate that all required fields are present
        required_fields = ['hash', 'timestamp', 'sender', 'fee', 'signature', 'public_key']
        missing = [field for field in required_fields if field not in tx or tx[field] is None]
        if missing:
            logger.error(f"sOMC mint transaction validation failed. Missing: {missing}")
            return None
        
        logger.info(f"sOMC mint transaction created successfully: {tx}")
        return tx

    def shutdown(self):
        """
        Gracefully shuts down the StakedOMC manager.
        """
        self.logger.info("[StakedOMC] Shutting down StakedOMC manager.")
        # Implement any necessary cleanup here
