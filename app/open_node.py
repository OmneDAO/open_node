# Omne Open Source Node

# Importing the libraries
from datetime import datetime, timezone, date
import statistics
import numpy as np
import pandas as pd
import matplotlib.pyplot as plt
import hashlib
import inspect
import boto3
import json
import bson
from botocore.exceptions import BotoCoreError, ClientError
from typing import List
from uuid import uuid4
from urllib.parse import urlparse
import random
import ecdsa
import base64
from base64 import b64encode
import os
import queue
from mnemonic import Mnemonic
from ecdsa.util import sigencode_der, sigdecode_der
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.asymmetric import ec, padding
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature, encode_dss_signature
from cryptography.hazmat.primitives.serialization import load_pem_private_key
from flask import Flask, jsonify, request, make_response, abort, session
from flask_cors import CORS, cross_origin
import requests
from pydantic import BaseModel
from passlib.hash import sha256_crypt
from typing import Union, Optional, Dict, List
from decimal import *
import time
import socket
import threading
import rsa
import secrets
import logging
logging.basicConfig(level=logging.INFO,
                    format='%(asctime)s - %(levelname)s - %(message)s')
from functools import wraps
import sqlite3
import re
from Crypto.Cipher import AES
import binascii
import math
from pandas_datareader import DataReader
from pymongo.mongo_client import MongoClient
from pymongo.server_api import ServerApi
from bson.objectid import ObjectId

from qiskit import QuantumCircuit, transpile, assemble
from qiskit.visualization import plot_histogram
from qiskit_aer import Aer
from qiskit_aer import AerSimulator

HASH_API_URL = "http://hash-api:3000/hashes"

def fetch_auth_token():
    try:
        response = requests.get("http://hash-api:3000/auth-token")
        if response.status_code != 200:
            raise ValueError("Failed to fetch auth token from public API.")
        data = response.json()
        return data.get("authToken")
    except Exception as e:
        logging.error(f"Error fetching auth token from public API: {e}")
        raise

# Retrieve the auth token
AUTH_TOKEN = fetch_auth_token()

if not AUTH_TOKEN:
    raise ValueError("Auth token could not be retrieved. Check your API setup.")

class CustomEncoder(json.JSONEncoder):
    def default(self, obj):
        if isinstance(obj, (datetime, date)):
            return obj.isoformat()
        elif isinstance(obj, Decimal):
            return float(obj)
        return super().default(obj)

class QuantumUtils:
    @staticmethod
    def quantum_random_bytes(num_bytes):
        try:
            logging.debug("Attempting to generate random bytes using os.urandom.")
            random_bytes = os.urandom(num_bytes)
            if not random_bytes:
                raise ValueError("No random bytes generated using os.urandom")
            logging.debug(f"Generated random bytes using os.urandom: {random_bytes.hex()}")
            return random_bytes
        except Exception as e:
            logging.error(f"Error in quantum_random_bytes using os.urandom: {e}")
            try:
                logging.debug("Falling back to generate random bytes using secrets.token_bytes.")
                random_bytes = secrets.token_bytes(num_bytes)
                if not random_bytes:
                    raise ValueError("No random bytes generated using secrets.token_bytes")
                logging.debug(f"Generated random bytes using secrets.token_bytes: {random_bytes.hex()}")
                return random_bytes
            except Exception as e:
                logging.error(f"Error in quantum_random_bytes using secrets.token_bytes: {e}")
                raise ValueError("Failed to generate random bytes with both os.urandom and secrets.token_bytes")

    @staticmethod
    def quantum_random_int(max_value):
        if max_value < 0:
            raise ValueError("max_value must be non-negative")
        
        try:
            bits_needed = max_value.bit_length()
            num_bytes = (bits_needed + 7) // 8
            logging.debug(f"Number of bytes needed: {num_bytes}")

            while True:
                random_bytes = QuantumUtils.quantum_random_bytes(num_bytes)
                random_int = int.from_bytes(random_bytes, 'big')
                if random_int <= max_value:
                    break

            logging.debug(f"Quantum random int: {random_int} for max value: {max_value}")
            return random_int
        except Exception as e:
            logging.error(f"Error in quantum_random_int: {e}")
            raise

    @staticmethod
    def quantum_resistant_hash(data):
        try:
            data_bin = ''.join(format(ord(i), '08b') for i in data)
            n = len(data_bin)
            qubit_limit = 29  # Adjust based on the simulator's maximum capability
            hash_result = ''

            for i in range(0, n, qubit_limit):
                chunk = data_bin[i:i+qubit_limit]
                chunk_len = len(chunk)
                qc = QuantumCircuit(chunk_len)
                qc.h(range(chunk_len))

                for j in range(chunk_len-1):
                    qc.cx(j, j+1)

                qc.measure_all()

                simulator = AerSimulator()
                transpiled_qc = transpile(qc, simulator)
                result = simulator.run(transpiled_qc, shots=1).result()
                counts = result.get_counts()
                measured_data = max(counts, key=counts.get)
                hash_result += measured_data

            quantum_hash = hashlib.sha256(hash_result.encode()).hexdigest()
            logging.debug(f"Quantum resistant hash: {quantum_hash}")
            return quantum_hash

        except Exception as e:
            logging.error(f"Error in quantum_resistant_hash: {e}")
            raise

class DynamicFeeCalculator:
    def __init__(self):
        # Define different rates for different transaction types
        self.rate_per_kilobyte = {
            'e': 0.000000000000085137,
            'o': 0.000000000000034259,
            'c': 0.000000000000000000
        }

    def get_base_dynamic_fee(self, transaction_data, transaction_type):
        # Convert the transaction data to string
        transaction_string = json.dumps(transaction_data, sort_keys=True)
        transaction_length = len(transaction_string)
        bytes_per_kilobyte = 1000

        # Get the rate for the given transaction type
        rate = self.rate_per_kilobyte.get(transaction_type, 0.000010004070000000)  # Default rate if type not found

        # Calculate the cost based on transaction length and rate
        kilobytes = transaction_length / bytes_per_kilobyte
        cost = kilobytes * rate

        # Generate a transaction hash
        transaction_hash = hashlib.sha256(transaction_string.encode()).hexdigest()

        # Return the cost and the hash
        return cost, transaction_hash
        
class Verifier:
    def __init__(self):
        self.nodes = []
        self.staking_agreements = []

    def update_staking_agreements(self, staking_agreements):
        self.staking_agreements = staking_agreements

    def calculate_stake_weight_for_node(self, node):
        # Combine and clarify the stake weight calculation
        # Assuming you have a method to calculate these amounts
        amount = self.get_staked_amount_for_node(node)
        contracts = self.get_contracts_count_for_node(node)
        withdrawals = self.get_withdrawals_count_for_node(node)

        # Apply your normalization and weight factors
        stake_weight = (self.normalize_amount(amount) * 0.7 +
                        self.normalize_contracts(contracts) * 0.2 -
                        self.normalize_withdrawals(withdrawals) * 0.1)

        return max(stake_weight, 0)  # Ensure non-negative

    def get_staked_amount_for_node(self, node_address, staking_agreements=None):
        if staking_agreements is None:
            staking_agreements = self.staking_agreements

        total_staked = 0
        for agreement in staking_agreements:
            if agreement['node_address'] == node_address:
                total_staked += agreement['amount']
        return total_staked

    def get_contracts_count_for_node(self, node_address, staking_agreements=None):
        if staking_agreements is None:
            staking_agreements = self.staking_agreements

        contracts_count = 0
        for agreement in staking_agreements:
            if agreement['node_address'] == node_address:
                contracts_count += 1
        return contracts_count

    def get_withdrawals_count_for_node(self, node_address, staking_agreements=None):
        if staking_agreements is None:
            staking_agreements = self.staking_agreements

        total_withdrawals = 0
        for agreement in staking_agreements:
            if agreement['node_address'] == node_address:
                total_withdrawals += agreement['withdrawals']
        return total_withdrawals

    def calculate_stake_weights(self):
        for node in self.nodes:
            stake_weight = self.calculate_stake_weight_for_node(node)
            if isinstance(node, Node):
                node.stake_weight = stake_weight
            elif isinstance(node, dict):
                node['stake_weight'] = stake_weight

    def normalize_amount(self, total_staked_amount):
        """
        Normalizes the total staked amount using a logarithmic scale.
        Adjusts the scale to ensure positive values.
        """
        # Ensure the minimum value is 1 to avoid log(0)
        adjusted_amount = max(1, total_staked_amount)
        # Use log to normalize and scale +1 to ensure a minimum value of 1
        return math.log(adjusted_amount) + 1

    def normalize_contracts(self, total_contracts):
        """
        Normalizes the number of contracts using a logarithmic scale.
        Adjusts the scale to ensure positive values.
        """
        # Ensure the minimum value is 1 to avoid log(0)
        adjusted_contracts = max(1, total_contracts)
        # Use log to normalize and scale +1 to ensure a minimum value of 1
        return math.log(adjusted_contracts) + 1

    def normalize_withdrawals(self, total_withdrawals):
        """
        Normalizes the number of withdrawals using a logarithmic scale.
        This method inversely scales withdrawals to penalize higher numbers.
        """
        # Ensure the minimum value is 1 to avoid log(0) and negative values
        adjusted_withdrawals = max(1, total_withdrawals)
        # Use inverse log to normalize, ensuring higher withdrawals result in lower values
        # +1 to ensure a minimum value of 1
        return 1 / (math.log(adjusted_withdrawals) + 1)

    def validate_stake(self, block):
        self.calculate_stake_weights()

        total_stake_weight = sum(node.stake_weight for node in self.nodes)
        random_number = random.uniform(0, total_stake_weight)
        cumulative_stake_weight = 0

        for current_node in self.nodes:
            cumulative_stake_weight += current_node.stake_weight
            if cumulative_stake_weight > random_number and current_node not in verifier.verified_nodes:
                return False  # Do not select unverified nodes

        return True

    def select_validator(self, block):
        self.calculate_stake_weights()  # Make sure this updates the stake weights in self.nodes

        # Corrected the sum to properly handle both dict and Node instances
        total_stake_weight = sum(node['stake_weight'] if isinstance(node, dict) else node.stake_weight for node in self.nodes)
        
        # Use quantum random integer instead of uniform
        max_value = int(total_stake_weight * 1000)  # Scale up to ensure sufficient granularity
        quantum_random_number = QuantumUtils.quantum_random_int(max_value) / 1000  # Scale down to original range

        cumulative_stake_weight = 0

        for node in self.nodes:
            node_stake_weight = node['stake_weight'] if isinstance(node, dict) else node.stake_weight
            cumulative_stake_weight += node_stake_weight

            if cumulative_stake_weight > quantum_random_number:
                return node

        logging.warning("No validator was selected, returning None.")
        return None

class CUtils:
    def __init__(self):
        pass

    @staticmethod
    def generate_mnemonic():
        entropy = quantum_utils.quantum_random_bytes(16)  # Using 16 bytes for 128 bits of entropy
        mnemonic = Mnemonic('english').to_mnemonic(entropy)
        return mnemonic

    @staticmethod
    def generate_seed(mnemonic):
        seed_bytes = Mnemonic('english').to_seed(mnemonic)
        return seed_bytes

    @staticmethod
    def generate_keys_from_mnemonic(mnemonic):
        seed_bytes = CUtils.generate_seed(mnemonic)
        hash_object = hashlib.sha256(seed_bytes)
        private_key_bytes = hash_object.digest()
        return private_key_bytes, ecdsa.SigningKey.from_string(private_key_bytes, curve=ecdsa.SECP256k1).get_verifying_key().to_string().hex()

    @staticmethod
    def sign_transaction(private_key_bytes: bytes, transaction: dict) -> str:
        private_key = ecdsa.SigningKey.from_string(private_key_bytes, curve=ecdsa.SECP256k1)
        transaction_data_str = json.dumps(transaction, sort_keys=True, cls=CustomEncoder)
        transaction_data_hash = hashlib.sha256(transaction_data_str.encode('utf-8')).digest()
        signature = private_key.sign(transaction_data_hash, sigencode=ecdsa.util.sigencode_der)
        return signature.hex()

    @staticmethod
    def verify_transaction(public_key_str, transaction, signature_base64):
        try:
            public_key_bytes = bytes.fromhex(public_key_str)
            verifying_key = ecdsa.VerifyingKey.from_string(public_key_bytes, curve=ecdsa.SECP256k1)
            transaction_data_str = json.dumps(transaction, sort_keys=True)
            transaction_data_hash = hashlib.sha256(transaction_data_str.encode('utf-8')).digest()
            signature_bytes = base64.b64decode(signature_base64)
            if verifying_key.verify(signature_bytes, transaction_data_hash, hashfunc=hashlib.sha256, sigdecode=ecdsa.util.sigdecode_der):
                return True, "Signature verified"
            else:
                return False, "Signature does not match"
        except ecdsa.BadSignatureError:
            return False, "Bad signature"
        except Exception as e:
            return False, f"Verification failed with error: {e}"

    @staticmethod
    def decrypt_val(cipher_text, hex_key):
        key = bytes.fromhex(hex_key)
        if len(key) not in [16, 24, 32]:
            raise ValueError("Incorrect AES key length (%d bytes)" % len(key))
        decipher = AES.new(key, AES.MODE_ECB)
        decrypted_text = decipher.decrypt(base64.b64decode(cipher_text))
        return decrypted_text.strip().decode('utf-8')

    @staticmethod
    def calculate_sha256_hash(transaction: dict) -> str:
        transaction_string = json.dumps(transaction, sort_keys=True)
        hash_object = hashlib.sha256(transaction_string.encode())
        return hash_object.hexdigest()

class PermissionMngr:
    def __init__(self):
        self.permissions = []

    def add_permission(self, address, url, permission, last_visit):
        """
        Add a new permission object to the list or update an existing one.
        """
        existing_permission = next(
            (perm for perm in self.permissions if perm['address'] == address), None)

        if existing_permission:
            # Update the existing permission object
            url_permissions = existing_permission['url_permissions']
            existing_url_permission = next(
                (up for up in url_permissions if up['url'] == url), None)

            if existing_url_permission:
                # Update the existing URL permission
                if time.time() - existing_url_permission['last_visit'] > 120 * 60:
                    # If last visit time is older than 120 minutes, revoke permission
                    existing_url_permission['permission'] = False
                else:
                    # Update the last visit time
                    existing_url_permission['last_visit'] = last_visit
                    # Update the existing URL permission
                    existing_url_permission['permission'] = permission
            else:
                # Add a new URL permission
                new_url_permission = {'url': url, 'permission': permission, 'last_visit': last_visit}
                url_permissions.append(new_url_permission)
        else:
            # Add a new permission object
            new_permission = {'address': address, 'url_permissions': [{'url': url, 'permission': permission, 'last_visit': last_visit}]}
            self.permissions.append(new_permission)

    def check_permission_for_url(self, address, url):
        """
        Check if the given address has permission for the specified URL.

        Args:
            address (str): The address to check.
            url (str): The URL to check for permission.

        Returns:
            bool: True if permission is granted, False otherwise.
        """
        permission_object = next((perm for perm in self.permissions if perm['address'] == address), None)

        if permission_object:
            url_permissions = permission_object['url_permissions']
            url_permission = next((up for up in url_permissions if up['url'] == url), None)

            if url_permission:
                return url_permission['permission']

        return False

class Transactions:
    def __init__(self):
        self.cleaned_transactions = []
        self.selected_transactions = []
        self.transactions = []

    def batch_pending_transactions(self):
        """
        Get and remove the first 24 pending transactions for processing.

        Returns:
            list: List of pending transactions to be processed.
        """
        pending_batch = self.transactions[:24]
        self.transactions = self.transactions[24:]
        self.selected_transactions = pending_batch
        return self.selected_transactions

    def clear_pending_transactions(self):
        """Clear the list of pending transactions."""
        self.transactions = []

    def clear_cleaned_transactions(self):
        """Clear the list of cleaned transactions."""
        self.cleaned_transactions = []

    def clear_selecteded_transactions(self):
        """Clear the list of selected transactions."""
        self.selecteded_transactions = []

    def remove_transaction(self, hash):
        """
        Remove a transaction from the list of pending transactions and cleaned transactions.

        Args:
            hash (str): The hash of the transaction to remove.
        """
        # Remove from self.transactions
        transaction_to_remove = None
        for transaction in self.transactions:
            if transaction['hash'] == hash:
                transaction_to_remove = transaction
                break
        if transaction_to_remove:
            self.transactions.remove(transaction_to_remove)

        # Remove from self.cleaned_transactions
        cleaned_transaction_to_remove = None
        for cleaned_transaction in self.cleaned_transactions:
            if cleaned_transaction['hash'] == hash:
                cleaned_transaction_to_remove = cleaned_transaction
                break
        if cleaned_transaction_to_remove:
            self.cleaned_transactions.remove(cleaned_transaction_to_remove)

    def get_transaction_count(self):
        """
        Get the count of pending transactions and cleaned transactions.

        Returns:
            tuple: A tuple containing the number of pending transactions and cleaned transactions.
        """
        pending_count = len(self.transactions)
        cleaned_count = len(self.cleaned_transactions)
        return pending_count

    def get_cleaned_transactions(self):
        """
        Get the list of pending transactions.

        Returns:
            list: List of pending transactions.
        """
        return self.cleaned_transactions

    def get_current_transaction_volume(self):
        """
        Get the current transaction volume by counting the number of pending transactions.

        Returns:
            int: Number of pending transactions.
        """
        return len(self.transactions)

class MerkleTree:
    def __init__(self):
        self.transactions = []
        self.tree = []

    def add_transaction(self, transaction):
        """Adds a new transaction to the transactions list."""
        self.transactions.append(transaction)

    def create_tree(self):
        """Generates the Merkle tree from the transactions."""
        if not self.transactions:
            return

        self.tree = [self.hash_data(tx) for tx in self.transactions]
        # Generate upper levels of the tree
        while len(self.tree) > 1:
            self.tree = self.create_upper_level(self.tree)

    def create_upper_level(self, lower_level):
        """Generates the upper level of the tree from the provided lower level."""
        upper_level = []
        for i in range(0, len(lower_level), 2):
            left = lower_level[i]
            right = lower_level[i + 1] if i + 1 < len(lower_level) else left
            upper_level.append(self.hash_pair(left, right))
        return upper_level

    def hash_data(self, data):
        """Returns the hash of the given data."""
        return hashlib.sha256(data.encode()).hexdigest()

    def hash_pair(self, left, right):
        """Hashes a pair of nodes and returns the resulting hash."""
        return self.hash_data(left + right)

    def get_merkle_root(self):
        """Returns the Merkle root of the tree."""
        if not self.tree:
            return None
        return self.tree[0]

    def get_merkle_proof(self, transaction):
        """Generates a Merkle proof for a transaction."""
        if transaction not in self.transactions:
            return []

        index = self.transactions.index(transaction)
        proof = []
        for level in self.tree:
            if index % 2 == 0:
                if index + 1 < len(level):
                    proof.append((level[index + 1], 'right'))
            else:
                proof.append((level[index - 1], 'left'))
            index = index // 2
        return proof

    def verify_proof(self, proof, transaction, root):
        """Verifies a Merkle proof for a transaction."""
        current_hash = self.hash_data(transaction)
        for sibling_hash, direction in proof:
            if direction == 'left':
                current_hash = self.hash_pair(sibling_hash, current_hash)
            else:
                current_hash = self.hash_pair(current_hash, sibling_hash)
        return current_hash == root

class TransferRequest:
    def __init__(self, from_address, to_address, amount, permission, sender_pub=None, permission_sig=None):
        self.from_address = from_address
        self.to_address = to_address
        self.amount = amount
        self.permission = permission
        self.sender_pub = sender_pub
        self.permission_sig = permission_sig

class OMC:
    def __init__(self, initial_supply=0.0):
        getcontext().prec = 18
        self.init_date = datetime.now(timezone.utc)
        self.name = 'Omne Coin'
        self.symbol = 'OMC'
        self.decimals = 18
        self.soft_max = 2200000
        self.coin_max = 22000000000000000000000000
        self.initial_supply = self.soft_max * (10 ** self.decimals)
        self.balance = {}
        self.id = "0z3ffd5d95e8b870eb1812caf03833b9ea8eadaeb7"
        self.circulating_supply = 0.0
        self.total_staked = 0.0
        self.total_minted = 0
        self.total_burned = 0
        self.staked_coins = []
        self.balance_lock = threading.Lock()
        self.reserves = 0
        self.treasury_address = None

    def transfer(self, from_address, to_address, amount):
        with self.balance_lock:
            if from_address not in self.balance:
                raise ValueError("Sender address does not exist")

            if self.balance[from_address] >= amount:
                self.balance[from_address] -= amount

                if to_address not in self.balance:
                    self.balance[to_address] = Decimal(0)

                self.balance[to_address] += Decimal(amount)

                timestamp = datetime.now(timezone.utc).isoformat()
                cursor = self.db_connection.cursor()
                cursor.execute("INSERT INTO transfer_history (timestamp, from_address, to_address, amount) VALUES (?, ?, ?, ?)",
                            (timestamp, from_address, to_address, amount))
                self.db_connection.commit()

                return True
            else:
                raise ValueError("Insufficient balance for transfer")

    @staticmethod
    def generate_request_id():
        random_number = secrets.randbelow(10**40)
        cryptographic_number = f'0r{random_number:040d}'
        return cryptographic_number

    def get_balance(self, address):
        with self.balance_lock:
            return self.balance.get(address, Decimal(0))

    def background_monitoring(self):
        while True:
            current_time = time.time()
            time.sleep(60)

    def get_transfer_history(self):
        cursor = self.db_connection.cursor()
        cursor.execute("SELECT * FROM transfer_history ORDER BY timestamp")
        rows = cursor.fetchall()
        transfer_history = [{
            'timestamp': row[0],
            'from_address': row[1],
            'to_address': row[2],
            'amount': row[3]
        } for row in rows]

        return transfer_history

    def report_coin_status(self):
        with self.balance_lock:
            return {
                'circulating_supply': str(self.circulating_supply),
                'number_of_addresses': len(self.balance)
            }

    def credit(self, address: str, amount: int):
        if address not in self.balance:
            self.balance[address] = 0
        self.balance[address] += amount

    def debit(self, address: str, amount: int):
        if address not in self.balance:
            raise ValueError("Account not found")
        if self.balance[address] < amount:
            raise ValueError("Insufficient balance for debit")
        self.balance[address] -= amount

    def mint_coins_and_send(self, to_address, amount):
        if amount <= 0:
            raise ValueError("Amount must be a positive value")

        with self.balance_lock:
            if self.circulating_supply >= self.coin_max:
                raise ValueError("Peak supply has been reached. No more minting allowed.")

            if self.coin_max - self.circulating_supply < amount:
                raise ValueError("Not enough supply for minting")

            if to_address not in self.balance:
                self.balance[to_address] = 0

            self.balance[to_address] += amount
            self.circulating_supply += amount
            self.total_minted += amount
            
            return True

    def mint_for_block_fee(self, transaction_fee):
        base_amount = 48
        adjustment_factor = 0.08
        base_fee = 26

        # Calculate the number of years since initialization
        current_date = datetime.now(timezone.utc)
        years_since_init = (current_date - self.init_date).days // 365

        # Calculate the number of halvings
        num_halvings = years_since_init // 4

        # Adjust the base amount according to the number of halvings
        base_amount /= (2 ** num_halvings)

        if transaction_fee > base_fee:
            percent_increase = ((transaction_fee - base_fee) / base_fee) * 100
            number_of_adjustments = percent_increase // 5
            for _ in range(int(number_of_adjustments)):
                base_amount *= (1 - adjustment_factor)

        with self.balance_lock:
            if self.circulating_supply >= self.coin_max:
                raise ValueError("Peak supply has been reached. No more minting allowed.")

            if self.treasury_address not in self.balance:
                self.balance[self.treasury_address] = 0

            self.balance[self.treasury_address] += base_amount
            self.circulating_supply += base_amount
            self.total_minted += base_amount
            logging.info(f"Minted {base_amount} to treasury for block fee purposes.")

        return base_amount

    @staticmethod
    def is_valid_address(address):
        if not re.match(r'^0b[0-9a-fA-F]{40}$', address):
            return False
        return True

class pOMC:
    def __init__(self, max_supply=0, name='Precursor OMC', symbol='pOMC', decimals=18):
        self.name = name
        self.symbol = symbol
        self.decimals = decimals
        self.id = "0z945e3cbb01dd784e96f0b53e18bef3af38c2f039"
        self.max_supply = max_supply
        self.whitelisted_addresses = set()
        self.minted_addresses = set()
        self.balance = {}
        self.burn_address = "0z0000000000000000000000000000000000000000"
        self.burned_pomc = 0  # Track the amount of pOMC burned
        self.balance_lock = threading.Lock()
        self.initial_mint_done = False  # Kill switch to prevent additional minting after initial mint

    def mint(self, recipient, amount):
        if self.initial_mint_done:
            raise ValueError("Minting additional coins is not allowed after the initial mint")

        if amount <= 0:
            raise ValueError("Amount must be a positive value")

        if recipient not in self.whitelisted_addresses:
            raise ValueError("Recipient is not whitelisted")

        if recipient in self.minted_addresses:
            raise ValueError("Address has already received coins")

        if recipient not in self.balance:
            self.balance[recipient] = 0

        self.balance[recipient] += amount
        self.minted_addresses.add(recipient)
        self.initial_mint_done = True

    def whitelist_address(self, address, pub_key, signature):
        if address in self.whitelisted_addresses:
            raise ValueError("Address is already whitelisted")

        self.whitelisted_addresses.add(address)
        
        transaction = {
            'pub_key': pub_key,
            'sender': address,
            'signature': signature,
            'sub_type': 'w',
            'type': 'c',
            'when': str(datetime.now(timezone.utc))
        }
        
        transaction_fee, transaction_hash = dynamic_fee_calculator.get_base_dynamic_fee(transaction, 'c')
        
        result = {
            'fee': transaction_fee,
            'hash': transaction_hash,
            'pub_key': pub_key,
            'sender': address,
            'signature': signature,
            'sub_type': 'w',
            'type': 'c',
            'when': str(datetime.now(timezone.utc))
        }
        
        transactions.transactions.append(result)

    def transfer(self, from_address, to_address, amount):
        raise ValueError("Coin transfer between whitelisted addresses is prohibited")

    def burn(self, address, amount):
        if amount <= 0:
            raise ValueError("Amount must be a positive value")

        if address not in self.balance or self.balance[address] < amount:
            raise ValueError("Insufficient balance for burning")

        with self.balance_lock:
            self.balance[address] -= amount
            self.burned_pomc += amount
            self.max_supply -= amount
            if self.burn_address not in self.balance:
                self.balance[self.burn_address] = 0
            self.balance[self.burn_address] += amount

    def get_balance(self, address):
        return self.balance.get(address, 0)

    def omc_redemption(self, address, amount):
        if address not in self.whitelisted_addresses:
            raise ValueError("Address is not whitelisted")

        if address not in self.balance:
            raise ValueError("Address does not have any pOMC balance")

        if self.balance[address] < amount:
            raise ValueError("Insufficient pOMC balance for redemption")

        # Deduct pOMC from the address and send to the burn address
        self.burn(address, amount)

        # Transfer OMC from OMC instance to the address
        coin.mint_coins_and_send(address, amount)

    def __init__(self, coin):
        self.coin = coin
        self.lockup_period_months = 28
        self.distribution_interval_months = 3
        self.locked_balance = 0
        self.lockup_end_time = None
        self.kill_switch = False
        self.lock = threading.Lock()

    def initialize_lockup(self, amount, address1, address2):
        with self.lock:
            if self.kill_switch:
                logging.error("The lockup method has already been executed once. Cannot run again.")
                return False

            # Mint coins to the Vault address
            vault_address = "0xVaultAddress"  # Replace with the actual Vault address
            if not self.coin.mint_coins(vault_address, amount):
                logging.error("Failed to mint coins to the Vault address.")
                return False

            self.locked_balance = amount
            self.lockup_end_time = datetime.now() + timedelta(days=self.lockup_period_months * 30)
            self.kill_switch = True
            logging.info(f"Successfully initialized lockup with {amount} coins for 28 months.")

            # Start the distribution thread
            distribution_thread = threading.Thread(target=self.distribute_coins_quarterly, args=(vault_address, address1, address2))
            distribution_thread.daemon = True
            distribution_thread.start()

            return True

    def distribute_coins_quarterly(self, vault_address, address1, address2):
        quarters = self.lockup_period_months // self.distribution_interval_months
        quarterly_distribution_amount = self.locked_balance / quarters / 2

        for _ in range(quarters):
            time.sleep(self.distribution_interval_months * 30 * 24 * 60 * 60)  # Sleep for 3 months
            with self.lock:
                if self.locked_balance > 0:
                    if not self.coin.transfer(vault_address, address1, quarterly_distribution_amount):
                        logging.error(f"Failed to transfer {quarterly_distribution_amount} to {address1}.")
                    if not self.coin.transfer(vault_address, address2, quarterly_distribution_amount):
                        logging.error(f"Failed to transfer {quarterly_distribution_amount} to {address2}.")
                    self.locked_balance -= quarterly_distribution_amount * 2
                    logging.info(f"Distributed {quarterly_distribution_amount} coins to {address1} and {address2}.")

class AccMngr:
    def __init__(self):
        self.accounts = []
        self.precursor_accounts = []
        self.staking_accounts = []

    def generate_account_from_mnemonic(self, mnemonic: str) -> dict:
        private_key, public_key = crypto_utils.generate_keys_from_mnemonic(mnemonic)
        return {'address': '0z' + public_key[-40:], 'pub_key': public_key, 'private_key': private_key, 'mnemonic': mnemonic}

    def get_account_balance(self, address: str) -> dict:
        try:
            balance = coin.balance.get(address, 0)
            return {
                'balance_scientific': format(balance, 'e'),
                'balance_float': balance / (10 ** coin.decimals)
            }
        except Exception as e:
            raise Exception("Get account balance error: " + str(e))

    def update_account_balance(self, address: str, new_balance: int, account_type: str = 'regular') -> bool:
        """
        Update the balance of an account.
        """
        try:
            if account_type == 'precursor':
                account_list = self.precursor_accounts
            else:
                account_list = self.accounts

            account = next((acc for acc in account_list if acc['address'] == address), None)
            if account:
                account['balance'] = new_balance
                return True
            else:
                # Optionally handle the case where the account does not exist
                # For now, just returning False
                return False
        except Exception as e:
            # Handle or log the exception
            logging.error(f"Error updating account balance: {e}")
            return False

    def credit_account(self, address: str, amount: int) -> None:
        """
        Credit an account with a specified amount.
        """
        account = next((acc for acc in self.accounts if acc['address'] == address), None)
        if account:
            account['balance'] += amount
            coin.balance[address] += amount
        else:
            # If account doesn't exist, create a new account with the credited amount
            self.accounts.append({'address': address, 'balance': amount})
            coin.balance[address] += amount

    def debit_account(self, address: str, amount: int) -> None:
        """
        Debit an account by a specified amount.
        """
        account = next((acc for acc in self.accounts if acc['address'] == address), None)
        if account and account['balance'] >= amount:
            account['balance'] -= amount
            coin.balance[address] -= amount
        else:
            raise ValueError("Insufficient balance for debit or account not found")

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

    def transfer(self, from_address, to_address, amount):
        """
        Transfer of staked coins between stakers (prohibited).
        """
        raise ValueError("StakedCoin transfer between stakers is prohibited")

    def burn(self, address, amount):
        """
        Burn staked coins by sending them to the burn address.
        """
        if amount <= 0:
            raise ValueError("Amount must be a positive value")

        if address not in self.balance or self.balance[address] < amount:
            raise ValueError("Insufficient balance for burning")

        # Convert the burn amount to a value with the correct number of decimal places
        amount_with_decimals = amount * (10 ** self.decimals)

        # Send the staked coins to the burn address
        self.balance[address] -= amount_with_decimals
        if self.burn_address not in self.balance:
            self.balance[self.burn_address] = 0
        self.balance[self.burn_address] += amount_with_decimals
        self.staked_omc_distributed -= amount_with_decimals

    def get_balance(self, address):
        """
        Get the balance of staked coins for a specific staker.
        """
        return self.balance.get(address, 0)

class StakingMngr:
    def __init__(self):
        self.staking_accounts = []
        self.staking_agreements = []

    def stake_coins(self, node_address, address, amount, min_term, pub_key):
        # Check if the address has enough balance for the proposed staking operation
        logging.info(f"Stake on node: {node_address}, address: {address}, amount: {amount}, min_term: {min_term}, pub_key: {pub_key}")
        
        try:
            if not self.check_balance_for_staking(address, amount):
                raise ValueError("Insufficient balance for staking")
        except ValueError as e:
            raise ValueError("Failed to check balance for staking: " + str(e))

        # Generate a unique hexadecimal contract ID for the staking agreement
        contract_id = '0s' + str(secrets.token_hex(16))
        logging.info(f"Generated contract ID: {contract_id}")

        # Debit the wallet for the staked amount
        try:
            account_manager.debit_account(address, amount)
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
        coin.staked_coins.append(staking_contract)

        # Add the staked amount to the total_staked attribute in OMC
        coin.total_staked += amount
        logging.info(f"Total staked amount updated: {coin.total_staked}")

        # Mint StakedOMC and send them to the wallet
        try:
            staked_coin.mint(address, amount)
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
        account_balance = coin.get_balance(address)
        logging.info(f"Checking balance for staking: address={address}, balance={account_balance}, amount={amount}")
        return account_balance >= amount

class Wallet:
    def __init__(self):
        self.account_manager = account_manager
        self.permission_manager = permission_manager

    # Add a new method to add account using AccMngr
    def add_account(self, account_data):
        account_manager.accounts.append(account_data)

    def _find_index(self, pub_key):
        for index, item in enumerate(self.accounts):
            if item["pub_key"] == pub_key:
                return index
        return -1

    @staticmethod
    def generate_key_from_passphrase(self, private_key):
        try:
            with open("pk.json") as file:
                data = json.load(file)
            password = data["pw"]

            passphrase_bytes = password.encode('utf-8')  # Encode the passphrase to bytes
            salt = os.urandom(16)  # Generate a random salt
            key = hashlib.pbkdf2_hmac(
                'sha256', passphrase_bytes, salt, iterations=100000, dklen=32)  # Derive the key
            f = Fernet(base64.urlsafe_b64encode(key))  # Use the derived key for Fernet
            return f.encrypt(base64.b64encode(private_key)), salt
        except Exception as e:
            raise Exception("Key generation error: " + str(e))

    def get(self, pub_key):
        try:
            for item in self.accounts:
                if item["pub_key"] == pub_key:
                    return item
            raise KeyError("Key not found or passphrase mismatch")
        except Exception as e:
            raise Exception("Get error: " + str(e))

    def send_coins(self, sender: str, receiver: str, amount: int, type: str) -> bool:
        try:
            amount_with_decimals = amount * (10 ** coin.decimals)
            return coin.transfer(sender, receiver, amount_with_decimals)
        except Exception as e:
            raise Exception("Send coins error: " + str(e))

    def pay_fee(self, address: str, amount: Union[int, float]) -> bool:
        account_balance = coin.get_balance(address)

        # Ensure amount is a Decimal for precise arithmetic
        amount = amount

        if account_balance >= amount:
            # Deduct the fee from the sender's account
            new_sender_balance = account_balance - amount

            # Update the sender's account balance
            update_success = account_manager.update_account_balance(address, new_sender_balance)
            if not update_success:
                logging.error("Failed to update sender's account balance.")
                return False

            # Assuming there's a receiver account designated for fees
            receiver_address = account_manager.accounts[0]['address']
            receiver_balance = coin.get_balance(receiver_address)

            # Ensure receiver's balance is treated as Decimal
            receiver_balance = receiver_balance
            new_receiver_balance = receiver_balance + amount

            # Update the receiver's account balance
            update_success = account_manager.update_account_balance(receiver_address, new_receiver_balance)
            if not update_success:
                logging.error("Failed to update receiver's account balance.")
                return False

            return True
        else:
            logging.warning("Insufficient balance for transaction")
            return False

    def get_account_balance(self, address: str) -> Decimal:
        """
        Get the balance of the specified address in the OMC coin.

        Args:
            address (str): The address to check.

        Returns:
            Decimal: The balance of the address.
        """
        return coin.get_balance(address)

    def recover_wallet(self, mnemonic):
        try:
            account = account_manager.generate_account_from_mnemonic(mnemonic)
            return {"address": account['address'], "pub_key": account['pub_key'], "private_key": base64.b64encode(account['private_key']).decode('utf-8'), "mnemonic": mnemonic}
        except Exception as e:
            raise Exception("Wallet recovery error: " + str(e))

    def add_accounts(self, accounts_data):
        """
        Add or update accounts with new data.

        Args:
            accounts_data (list): List of account data to add or update.
        """
        for account_data in accounts_data:
            # Check if account already exists
            existing_account = next((acc for acc in account_manager.accounts if acc['address'] == account_data['address']), None)
            if existing_account:
                # Update existing account data
                existing_account.update(account_data)
            else:
                # Add new account
                account_manager.accounts.append(account_data)

    def update_permissions(self, permissions_data):
        """
        Update permissions data.

        Args:
            permissions_data (list): List of permissions data to update.
        """
        # Implement the logic to update permissions
        pass

class OMCTreasury:
    def __init__(self):
        self.treasury_account = None
        self.balance = 0.0
        self.dao = None

    def set_dao(self, dao):
        self.dao = dao

    def get_treasury_balance(self):
        if self.treasury_account is None:
            raise ValueError("Treasury account not created yet.")

        return {
            'balance_scientific': format(self.treasury_account['balance'], 'e'),
            'balance_float': self.treasury_account['balance'] / (10 ** wallet.coin.decimals)
        }

    def update_treasury_data(self, treasury_data):
        """
        Update the treasury data with new information.

        Args:
            treasury_data (dict): New treasury account data to update.
        """
        if not isinstance(treasury_data, dict):
            raise ValueError("Invalid treasury data format.")

        # Update existing treasury account data or set it if it doesn't exist
        if self.treasury_account:
            self.treasury_account.update(treasury_data)
        else:
            self.treasury_account = treasury_data

        # Update treasury balance if available
        if 'balance' in treasury_data:
            self.balance = treasury_data['balance']

class Node:
    def __init__(self, address=None, stake_weight=0, url="http://node.omne:3400",
                 version="0.0.1", private_key=None, public_key=None, signature=None, steward=None):
        self.address = address
        self.stake_weight = stake_weight
        self.url = url
        self.version = version
        self.private_key = private_key
        self.public_key = public_key
        self.signature = signature
        self.steward = steward

        # If address and keys are not provided, generate new ones
        if not self.address or not self.private_key or not self.public_key:
            mnemonic = crypto_utils.generate_mnemonic()
            account = account_manager.generate_account_from_mnemonic(mnemonic)

            # Extract key data
            self.address = account['address']
            # Assuming private_key is also a byte-like object that needs conversion
            # Adjust this line if private_key is already correctly formatted
            self.private_key = binascii.hexlify(account['private_key']).decode('utf-8')
            self.public_key = account['pub_key']

            wallet_creation_transaction = {
                'address': account['address'],
                'balance': 0.0,
                'withdrawals': 0,
                'type': 'c'
            }

            # Use the add_account method from Wallet class
            # wallet.add_account(wallet_creation_transaction)

    def sign_node_data(self, data):
        # Sign data using the private key
        sk = ecdsa.SigningKey.from_string(bytes.fromhex(self.private_key), curve=ecdsa.SECP256k1)
        data_str = json.dumps(data, sort_keys=True)
        data_hash = hashlib.sha256(data_str.encode('utf-8')).digest()
        signature = sk.sign(data_hash)
        return base64.b64encode(signature).decode('utf-8')

    def verify_node(self, node_data, signature):
        # Verify signature using the public key
        vk = ecdsa.VerifyingKey.from_string(bytes.fromhex(self.public_key), curve=ecdsa.SECP256k1)
        data_str = json.dumps(node_data, sort_keys=True)
        data_hash = hashlib.sha256(data_str.encode('utf-8')).digest()
        signature_bytes = base64.b64decode(signature)
        try:
            return vk.verify(signature_bytes, data_hash)
        except ecdsa.BadSignatureError:
            return False

    def to_dict(self):
        return {
            'address': self.address,
            'stake_weight': self.stake_weight,
            'url': self.url,
            'version': self.version,
            'public_key': self.public_key,
            'signature': self.signature,
            'steward': self.steward
        }

class Block:
    def __init__(self, index: int, fee: int, previous_hash: str, timestamp: str, transactions: list, validator: str, validator_share: int):
        self.index = index
        self.previous_hash = previous_hash
        self.timestamp = timestamp
        self.transactions = transactions
        self.nonce = 0
        self.fee = fee
        self.hash = self.calculate_hash()
        self.validator = validator
        self.validator_share = validator_share

    def calculate_hash(self) -> str:
        """
        Calculate the hash value of the block.
        """
        block_string = str(self.previous_hash) + str(self.transactions) + \
            str(self.nonce) + str(self.timestamp)
        return hashlib.sha256(block_string.encode()).hexdigest()

    def is_valid(self, previous_block: 'Block') -> bool:
        """
        Check if the block is valid by verifying its hash and transactions.
        """
        # Check if the hash is correct
        if self.calculate_hash() != self.hash:
            return False

        # Check if the previous hash matches the hash of the previous block
        if previous_block.hash != self.previous_hash:
            return False

        # Verify each transaction in the block
        for transaction in self.transactions:
            if not transaction.is_valid():
                return False

        return True

    def proof_of_stake(self, threshold):
        while True:
            # Calculate the hash of the block
            block_hash = self.calculate_hash()

            # Check if the hash meets the proof-of-stake condition
            if int(block_hash, 16) < threshold:
                break

            # Increment the nonce and try again
            self.nonce += 1


    def __init__(self, message="Double spending detected"):
        self.message = message
        super().__init__(self.message)


    def __init__(self, coin, node, wallet, transactions, verifier):
        self.coin = coin
        self.node = node
        self.wallet = wallet
        self.transactions = transactions
        self.verifier = verifier

        self.chain = []
        self.block_hashes = set()
        self.lock = threading.Lock()
        logging.basicConfig(level=logging.DEBUG)
        
        self.validators = []
        
        mining_thread = threading.Thread(target=self.mine_new_block_periodically)
        mining_thread.daemon = True
        mining_thread.start()

    @staticmethod
    def serialize_and_create_single_hash(cls):
        if not isinstance(cls, type):
            raise TypeError(f"Expected class type, got {type(cls)}")

        try:
            class_dict = {
                'attributes': {key: value for key, value in cls.__dict__.items() if not callable(value) and not key.startswith('__')},
                'methods': {
                    key: (value.__func__.__code__.co_code if isinstance(value, staticmethod) else value.__code__.co_code)
                    for key, value in cls.__dict__.items() if callable(value)
                }
            }
            class_serialized = json.dumps(class_dict, sort_keys=True, default=str)
            logging.debug(f"Serialized class {cls.__name__}: {class_serialized}")
            class_hash = hashlib.sha256(class_serialized.encode()).hexdigest()
            return class_hash
        except Exception as e:
            logging.error(f"Error serializing class {cls.__name__}: {e}")
            raise

    @staticmethod
    def verify_class_hashes():
        """
        This function retrieves the stored hashes of classes from the public API and compares them
        with the hashes of the current local classes to ensure integrity.
        """
        try:
            response = requests.get(HASH_API_URL)
            if response.status_code != 200:
                raise ValueError("Failed to fetch class hashes from public API.")

            stored_hashes = response.json()
        except Exception as e:
            logging.error(f"Error fetching class hashes from public API: {e}")
            raise

        classes_to_verify = {
            'coin': OMC,
            'quantum_utils': QuantumUtils,
            'transactions': Transactions,
            'permission_manager': PermissionMngr,
            'precursor_coin': pOMC,
            'verifier': Verifier,
            'crypto_utils': CUtils,
            'fee_calculator': DynamicFeeCalculator,
            'ledger': Ledger
        }

        for class_name, cls in classes_to_verify.items():
            stored_hash = stored_hashes.get(class_name)
            if not stored_hash:
                logging.error(f"Stored hash for class {class_name} not found in the public API response.")
                raise ValueError(f"Stored hash for class {class_name} not found.")

            local_hash = Ledger.serialize_and_create_single_hash(cls)
            if stored_hash != local_hash:
                logging.error(f"Hash mismatch for class {class_name}. Possible tampering detected.")
                raise ValueError(f"Hash mismatch for class {class_name}. Possible tampering detected.")

        logging.info("All class hashes verified successfully. No tampering detected.")
        return True

    def initialize_node(self):
        service_prefix = "node"
        services = self.discover_services(service_prefix)
        if services:
            self.ping_services(services, "check_nodes", self.node.url)

        self.node.steward = os.getenv('STEWARD_ADDRESS')
        if not self.node.steward:
            raise ValueError("Steward address not provided. Set the STEWARD_ADDRESS environment variable.")

        self.update_node_state(self.node)
        self.check_chain_length_and_sync(services)
        self.update_validators()
        self.broadcast_node_data(self.node)

    def discover_services(self, prefix):
        discovered_services = []
        max_range = 10

        for i in range(1, max_range):
            service_name = f"{prefix}{i}.omne"
            try:
                service_address = socket.gethostbyname(service_name)

                if service_address != self.node.url:
                    discovered_services.append(service_name)
                    logging.debug(f"Discovered service: {service_name}")

            except socket.gaierror:
                continue

        if not discovered_services:
            logging.warning("No services were discovered.")

        return discovered_services

    def ping_services(self, services, endpoint, current_node_url):
        headers = {"Authorization": f"Bearer {AUTH_TOKEN}"}

        for service in services:
            service_base_url = f"http://{service}:3400"
            service_url = f"{service_base_url}/{endpoint}"

            if service_base_url == current_node_url:
                logging.debug(f"Skipping self ping: {service_base_url}")
                continue

            logging.debug(f"Attempting to ping {service_url}")
            try:
                response = requests.get(service_url, headers=headers)
                if response.status_code == 200:
                    logging.debug(f"Successfully pinged {service_url}")
                    received_nodes = response.json().get('nodes', [])
                    for received_node in received_nodes:
                        if not any(node['address'] == received_node['address'] for node in self.verifier.nodes):
                            verifier.nodes.append(received_node)
                            verifier.nodes.append(received_node)
                            self.validators.append(received_node['address'])
                            logging.debug(f"Added new node: {received_node['address']}")
                else:
                    logging.debug(f"Failed to ping {service_url}, status code: {response.status_code}")

            except requests.exceptions.RequestException as e:
                logging.error(f"Error pinging {service_url}: {e}")

    def post_data_to_services(self, services, endpoint, data):
        headers = {"Authorization": f"Bearer {AUTH_TOKEN}"}

        for service in services:
            service_base_url = f"http://{service}:3400"
            service_url = f"{service_base_url}/{endpoint}"

            if service_base_url == self.node.url:
                logging.debug(f"Skipping self post: {service_url}")
                continue

            logging.debug(f"Attempting to post data to {service_url}")
            try:
                response = requests.post(service_url, json=data, headers=headers)
                if response.status_code == 200:
                    logging.debug(f"Successfully posted data to {service_url}")
                else:
                    logging.debug(f"Failed to post data to {service_url}, status code: {response.status_code}")

            except requests.exceptions.RequestException as e:
                logging.error(f"Error posting data to {service_url}: {e}")

    def broadcast_self_info(self):
        if not self.node or not self.node.address or not self.node.url:
            logging.error("Node information is incomplete or incorrect. Cannot broadcast.")
            return

        node_info = self.node.to_dict()
        logging.info(f"Broadcasting self node information: {node_info}")

        services = self.discover_services("node")
        if not services:
            logging.warning("No other services discovered for broadcasting. Broadcast aborted.")
            return

        services = [service for service in services if service != self.node.url]
        if not services:
            logging.warning("No external services discovered for broadcasting. Broadcast aborted.")
            return

        self.post_data_to_services(services, "receive_node_info", node_info)
        logging.info("Successfully broadcasted self node information to other services.")

    def update_validators(self):
        services = self.discover_services("node")
        for service in services:
            service_base_url = f"http://{service}:3400"
            service_url = f"{service_base_url}/node_info"

            if service_base_url == self.node.url:
                continue

            try:
                response = requests.get(service_url)
                if response.status_code == 200:
                    node_data = response.json()
                    if node_data['address'] not in self.validators:
                        self.validators.append(node_data['address'])
            except requests.exceptions.RequestException as e:
                logging.error(f"Failed to retrieve node information from {service}: {e}")

    def sync_with_other_nodes(self, services):
        my_chain_length = len(self.chain)
        synchronized_chain = None
        authoritative_node_url = None

        for service in services:
            service_base_url = f"http://{service}:3400"
            service_url = f"{service_base_url}/get_chain"

            if service_base_url == self.node.url:
                continue

            try:
                response = requests.get(service_url)
                if response.status_code == 200:
                    other_chain = response.json()["chain"]
                    if len(other_chain) > my_chain_length:
                        my_chain_length = len(other_chain)
                        synchronized_chain = other_chain
                        authoritative_node_url = service_base_url
            except requests.exceptions.RequestException as e:
                logging.error(f"Error while trying to sync with {service_url}: {e}")

        if synchronized_chain:
            self.chain = synchronized_chain

        return authoritative_node_url, synchronized_chain

    def broadcast_node_data(self, node):
        headers = {"Authorization": f"Bearer {AUTH_TOKEN}"}
        node_data_complete = {
            'address': node.address,
            'public_key': node.public_key,
            'url': node.url,
            'stake_weight': node.stake_weight,
            'version': node.version,
            'steward': node.steward
        }

        services = self.discover_services("node")

        for service in services:
            service_base_url = f"http://{service}:3400"
            service_url = f"{service_base_url}/receive_node_data"

            if service_base_url == self.node.url:
                continue

            logging.debug(f"Broadcasting node data to {service_url}")
            try:
                response = requests.post(service_url, json=node_data_complete, headers=headers)
                if response.status_code == 200:
                    logging.debug(f"Successfully broadcasted node data to {service_url}")
                else:
                    logging.warning(f"Failed to broadcast node data to {service_url}, status code: {response.status_code}")
            except requests.exceptions.RequestException as e:
                logging.error(f"Error broadcasting node data to {service_url}: {e}")

    def update_accounts(self, address, balance):
        new_account = {
            'address': address,
            'balance': balance
        }

        service_prefix = "node"
        services = self.discover_services(service_prefix)

        filtered_services = [s for s in services if f"http://{s}:3400" != self.node.url]
        self.post_data_to_services(filtered_services, "propagate_account", new_account)

    def update_node_state(self, new_node):
        if new_node not in self.verifier.nodes:
            verifier.nodes.append(new_node)
            self.node.verifier.verified_nodes.append(new_node)
            self.validators.append(new_node.address)
            logging.info(f"Node {new_node.address} added to local state.")

    def mine_new_block_periodically(self, interval=9):
        while True:
            self.check_for_mining_opportunity()
            time.sleep(interval * 60)

    def check_for_mining_opportunity(self):
        num_transactions = len(self.transactions.transactions)
        if num_transactions >= 1:
            self.check_pending_transactions()
        elif 4 <= num_transactions < 15 and self.is_time_to_mine():
            self.check_pending_transactions()

    def is_time_to_mine(self):
        latest_block = self.chain[-1]
        block_timestamp = datetime.strptime(latest_block['timestamp'], "%Y-%m-%d %H:%M:%S.%f%z")
        current_timestamp = datetime.now(timezone.utc)
        
        mining_interval = 9 * 60  # Fixed interval of 9 minutes
        return (current_timestamp - block_timestamp).total_seconds() >= mining_interval

    def create_new_wallet(self):
        mnemonic = crypto_utils.generate_mnemonic()
        account = self.wallet.account_manager.generate_account_from_mnemonic(mnemonic)
        
        # Add the new address with a balance of zero to the self.balance dictionary
        with coin.balance_lock:
            coin.balance[account['address']] = 0.0

        wallet_creation_transaction = {
            'address': account['address'],
            'balance': 0.0,
            'withdrawals': 0,
            'type': 'c'
        }

        cleaned_transaction = {
            'address': wallet_creation_transaction['address'],
            'balance': wallet_creation_transaction['balance'],
            'pub_key': account['pub_key'],
            'sub_type': 'c',
            'type': wallet_creation_transaction['type'],
            'withdrawals': wallet_creation_transaction['withdrawals']
        }

        initial_balance = 0.0

        account_dict = {
            'address': wallet_creation_transaction['address'],
            'balance': initial_balance,
        }

        sendable_transaction = {
            'mnemonic': mnemonic,
            'private_key': base64.b64encode(account['private_key']).decode('utf-8'),
            'pub_key': account['pub_key'],
            'address': account['address'],
        }

        return sendable_transaction

    def create_new_wallet_from_seed(self, seed):
        account = self.wallet.account_manager.generate_account_from_mnemonic(seed)

        wallet_creation_transaction = {
            'address': account['address'],
            'balance': 0.0,
            'withdrawals': 0,
            'type': 'c'
        }

        cleaned_transaction = {
            'address': wallet_creation_transaction['address'],
            'balance': wallet_creation_transaction['balance'],
            'pub_key': account['pub_key'],
            'type': wallet_creation_transaction['type'],
            'withdrawals': wallet_creation_transaction['withdrawals']
        }

        sendable_transaction = {
            'mnemonic': account['mnemonic'],
            'private_key': base64.b64encode(account['private_key']).decode('utf-8'),
            'pub_key': account['pub_key'],
            'address': account['address'],
        }

        private_key_bytes = base64.b64decode(sendable_transaction['private_key'])
        signature = crypto_utils.sign_transaction(private_key_bytes, wallet_creation_transaction)

        cleaned_transaction['signature'] = signature

        self.transactions.transactions.append(cleaned_transaction)
        self.update_accounts(wallet_creation_transaction['address'], wallet_creation_transaction['balance'])

        return sendable_transaction

    def get_chain_length(self):
        return len(self.chain) if hasattr(self, "blockchain") else 0

    def check_chain_length_and_sync(self, services):
        service_prefix = "node"
        services = self.discover_services(service_prefix)

        authoritative_node_url, synchronized_chain = self.sync_with_other_nodes(services)

        self.sync_account_list_data(authoritative_node_url, account_manager, coin, staked_coin)
        self.sync_treasury_data(authoritative_node_url)

        self.ping_services(services, "check_nodes", self.node.url)

        if synchronized_chain is not None:
            return {
                "chain": synchronized_chain,
                "message": "Chain synchronized successfully"
            }
        else:
            return {
                "chain": self.chain,
                "message": "Chain synchronization failed"
            }

    def sync_account_list_data(self, authoritative_node_url, account_manager, coin, staked_coin):
        if not authoritative_node_url:
            logging.error("No authoritative node URL provided for account list data synchronization.")
            return

        service_url = f"{authoritative_node_url}/retrieve_accounts"

        try:
            response = requests.get(service_url)
            if response.status_code == 200:
                data = response.json()

                main_accounts = data.get('data', [])
                for new_acc in main_accounts:
                    if 'address' in new_acc and 'balance' in new_acc:
                        account = next((acc for acc in account_manager.accounts if acc['address'] == new_acc['address']), None)
                        if account:
                            account['balance'] = new_acc['balance']
                            coin.balance[new_acc['address']] = new_acc['balance']
                            logging.info(f"Updated main account {new_acc['address']} for {coin.name}.")
                        else:
                            account_manager.accounts.append(new_acc)
                            coin.balance[new_acc['address']] = new_acc['balance']
                            logging.info(f"Added new main account {new_acc['address']} for {coin.name}.")

                precursor_accounts = data.get('precursor_accounts', [])
                for new_acc in precursor_accounts:
                    if 'address' in new_acc and 'balance' in new_acc:
                        account = next((acc for acc in account_manager.precursor_accounts if acc['address'] == new_acc['address']), None)
                        if account:
                            account['balance'] = new_acc['balance']
                            coin.balance[new_acc['address']] = new_acc['balance']
                            logging.info(f"Updated precursor account {new_acc['address']} for {coin.name}.")
                        else:
                            account_manager.precursor_accounts.append(new_acc)
                            coin.balance[new_acc['address']] = new_acc['balance']
                            logging.info(f"Added new precursor account {new_acc['address']} for {coin.name}.")

                staking_accounts = data.get('staking_accounts', [])
                for new_acc in staking_accounts:
                    if 'address' in new_acc and 'min_term' in new_acc:
                        account = next((acc for acc in staking_manager.staking_agreements if acc['address'] == new_acc['address']), None)
                        if account:
                            account['amount'] = new_acc['amount']
                            account['withdrawals'] = new_acc['withdrawals']
                            staked_coin.balance[new_acc['address']] = new_acc['amount']
                            logging.info(f"Updated staking account {new_acc['address']} for {staked_coin.name}.")
                        else:
                            staked_coin.accounts.append(new_acc)
                            staking_manager.staking_agreements.append(new_acc)
                            staked_coin.balance[new_acc['address']] = new_acc['amount']
                            logging.info(f"Added new staking account {new_acc['address']} for {staked_coin.name}.")

                self.validators = data.get('validators', [])
                if self.node.address not in self.validators:
                    self.validators.append(self.node.address)

                notification_data = {"message": "Data updated from authoritative node"}
                self.post_data_to_services(self.discover_services("node"), "notify_data_update", notification_data)

                logging.warning(f"Synchronized account list data with the authoritative node: {authoritative_node_url}")
            else:
                logging.error(f"Failed to retrieve account data from {service_url}, status code: {response.status_code}")
        except requests.RequestException as e:
            logging.error(f"Error retrieving account data from {service_url}: {e}")
            
    def sync_treasury_data(self, authoritative_node_url):
        if not authoritative_node_url:
            logging.error("No authoritative node URL provided for treasury data synchronization.")
            return False

        service_url = f"{authoritative_node_url}/retrieve_treasury_data"

        try:
            response = requests.get(service_url)
            if response.status_code == 200:
                response_data = response.json()
                if 'treasury_account' in response_data:
                    self.treasury.update_treasury_data(response_data['treasury_account'])
                    logging.warning("Synchronized treasury data with the authoritative node: %s", authoritative_node_url)
                    return True
                else:
                    logging.error(f"No treasury account data found in the response from {service_url}")
                    return False
            else:
                logging.error(f"Failed to retrieve treasury data from {service_url}, status code: {response.status_code}")
                return False
        except requests.RequestException as e:
            logging.error(f"Error retrieving treasury data from {service_url}: {e}")
            return False

    def add_account(self, account_data):
        address = account_data.get('address')
        balance_float = account_data.get('balance_float', 0)
        new_account = {}
        new_account['address'] = address
        new_account['balance'] = balance_float

        account_manager.accounts.append(new_account)
        coin.balance[address] = balance_float

        logging.info(f"Added/Updated account: {address} with balance {balance_float}")

    def add_staking_account(self, data):
        account_manager.staking_accounts.append(data)
        staked_coin.accounts.append(data)
        staking_manager.staking_accounts.append(data)

    def get_init_date(self):
        return coin.init_date

    def validate_chain(self, chain):
        previous_block = chain[0]
        for block in chain[1:]:
            if block['previous_hash'] != previous_block['hash']:
                return False

            block_data = block.copy()
            block_data.pop('hash')
            calculated_hash = self.calculate_block_hash(block_data)

            if block['hash'] != calculated_hash:
                return False

            if not self.validate_stake(block):
                return False

            previous_block = block

        return True

    def add_block(self, block):
        logging.info(f"Attempting to add block with index {block['index']}")
        if self.validate_received_block(block):
            with self.lock:
                if block['index'] == len(self.chain) + 1 and \
                   block['previous_hash'] == self.chain[-1]['hash']:
                    self.chain.append(block)
                    self.block_hashes.add(block['hash'])
                    logging.info(f"Block with index {block['index']} successfully added to the chain.")
                    self.broadcast_block(block)
                    return True
                else:
                    logging.warning(f"Block with index {block['index']} failed to match chain continuity.")
        else:
            logging.warning(f"Block with index {block['index']} failed validation.")
        return False
    
    def broadcast_block(self, new_block):
        block_data = json.dumps(new_block)

        service_prefix = "node"
        services = self.discover_services(service_prefix)

        self.post_data_to_services(services, "blocks/receive_block", block_data)
        
    def validate_foreign_tx(self, address, hash, pub_key, tx, signature):
        logging.debug(f"Validating tx from {address}")

        tx_hash = quantum_utils.quantum_resistant_hash(json.dumps(tx, sort_keys=True))
        if tx_hash != hash:
            logging.error(f"Hash mismatch for transaction with hash: {hash}")
            return None

        if not CUtils.verify_transaction(pub_key, tx, signature):
            logging.error(f"Invalid signature in foreign transaction with hash: {hash} from address: {address}")
            return None

        return True

    def vote_on_local_tx(self, address, hash, pub_key, tx, signature):
        valid_votes = []
        services = ledger.discover_services("node")

        if len(services) == 1 and services[0] == self.node.url:
            logging.info("Only one validator in the network, bypassing the voting process.")
            valid_votes.append(self.node.url)

        filtered_services = [s for s in services if f"http://{s}:3400" != self.node.url]
        for service in filtered_services:
            service_url = f"http://{service}:3400/vote_on_tx"

            try:
                data = {
                    'address': address,
                    'hash': hash,
                    'pub_key': pub_key,
                    'new_tx': tx,
                    'signature': signature
                }
                response = requests.post(service_url, json=data)
                if response.status_code == 200 and response.json().get('message') == 'Tx is valid':
                    valid_votes.append(service)
                    logging.info(f"Validator {service} approved the tx.")
                else:
                    logging.info(f"Validator {service} did not approve the tx.")
            except requests.exceptions.RequestException as e:
                logging.error(f"Error voting on block with {service}: {e}")

        return valid_votes

    def reach_tx_consensus(self, address, hash, pub_key, tx, signature):
        if len(self.validators) == 1:
            logging.info("Automatically reaching consensus with single validator")
            return True

        consensus_reached = self.vote_on_local_tx(address, hash, pub_key, tx, signature)

        if consensus_reached:
            logging.info("Tx consensus reached")
            return True
        else:
            logging.info("Tx consensus not reached")
            return False

    def receive_tx(self, address, hash, pub_key, tx, signature):
        try:
            if not self.validate_foreign_tx(address, hash, pub_key, tx, signature):
                logging.error(f"Received transaction, with hash {hash} from wallet {address}, did not pass verification")
                return False

            return True
        except Exception as e:
            logging.error(f"Error processing received transaction: {str(e)}")
            return False

    def receive_block(self, block):
        try:
            services = ledger.discover_services("node")
            authoritative_node_url, _ = ledger.sync_with_other_nodes(services)

            if authoritative_node_url:
                ledger.sync_account_list_data(authoritative_node_url, account_manager, coin, staked_coin)
                ledger.sync_treasury_data(authoritative_node_url)

            return True
        except Exception as e:
            logging.error(f"Error processing received block: {str(e)}")
            return False

    def broadcast_tx(self, address, hash, pub_key, new_tx, signature):
        data = {
            'address': address,
            'hash': hash,
            'pub_key': pub_key,
            'new_tx': new_tx,
            'signature': signature
        }

        services = ledger.discover_services("node")

        ledger.post_data_to_services(services, "transaction/receive_tx", data)

        return True
    
    def randomly_select_validator(self):
        if not self.validators:
            logging.warning("No validators available.")
            return None

        try:
            if len(self.validators) == 1:
                validator_address = self.validators[0]
                logging.info(f"Only one validator available. Selected validator address: {validator_address}")
                return validator_address

            max_value = len(self.validators) - 1
            random_bytes = QuantumUtils.quantum_random_bytes((max_value.bit_length() + 7) // 8)
            random_int = int.from_bytes(random_bytes, 'big') % (max_value + 1)
            validator_address = self.validators[random_int]
            logging.info(f"Randomly selected validator address: {validator_address}")
            return validator_address
        except Exception as e:
            logging.error(f"Error generating random index: {e}")
            return None

    def trigger_sync_on_all_nodes(self):
        services = ledger.discover_services("node")

        data = {}

        for service in services:
            service_base_url = f"http://{service}:3400"

            if service_base_url == self.node.url:
                logging.debug(f"Skipping self sync trigger: {service_base_url}")
                continue

            service_url = f"{service_base_url}/trigger_sync"
            logging.debug(f"Attempting to trigger sync on {service_url}")
            try:
                response = requests.post(service_url, json=data)
                if response.status_code == 200:
                    logging.debug(f"Successfully triggered sync on {service_url}")
                else:
                    logging.debug(f"Failed to trigger sync on {service_url}, status code: {response.status_code}")
            except requests.exceptions.RequestException as e:
                logging.error(f"Error triggering sync on {service_url}: {e}")

    def validate_received_block(self, block):
        logging.debug(f"Validating received block with index {block['index']}")
        if not self.validate_block_structure(block):
            logging.error("Block structure validation failed.")
            return False

        if not self.validate_block(block):
            logging.error("Block content validation failed.")
            return False

        if block['index'] != len(self.chain) + 1:
            logging.error(f"Block index {block['index']} does not follow the current chain length.")
            return False

        return True

    def validate_block_structure(self, block):
        logging.debug(f"Checking block structure for block with index {block['index']}")
        required_fields = [
            'index', 'previous_hash', 'timestamp', 'transactions',
            'merkle_root', 'stake_threshold', 'hash', 'miner', 'miner_share',
            'validator', 'validator_share', 'fee'
        ]

        missing_fields = [field for field in required_fields if field not in block]
        if missing_fields:
            logging.error(f"Block missing required fields: {missing_fields}")
            return False

        field_type_issues = False
        for field in required_fields:
            if field in block:
                expected_type = (int if field in ['index', 'timestamp'] else
                                 str if field in ['previous_hash', 'hash', 'miner', 'validator', 'merkle_root'] else
                                 list if field == 'transactions' else
                                 (int, float) if field in ['stake_threshold', 'fee', 'miner_share', 'validator_share'] else
                                 None)
                actual_type = type(block[field])
                if not isinstance(block[field], expected_type):
                    logging.error(f"Field '{field}' type mismatch: expected {expected_type}, got {actual_type}")
                    field_type_issues = True
            else:
                logging.error(f"Field '{field}' is missing from the block.")
                field_type_issues = True

        if field_type_issues:
            logging.error("One or more block field types are incorrect.")
            return False

        logging.debug("Block structure validated successfully.")
        return True
    
    def reach_consensus(self, proposed_block):
        if len(self.validators) == 1:
            logging.info("Automatically reaching consensus with single validator")
            return True

        consensus_reached = self.vote_on_local_block(proposed_block)

        if consensus_reached:
            logging.info("Consensus reached")
            return True
        else:
            logging.info("Consensus not reached")
            return False

    def vote_on_local_block(self, block):
        valid_votes = []
        services = self.discover_services("node")

        if len(services) == 1 and services[0] == self.node.url:
            logging.info("Only one validator in the network, bypassing the voting process.")
            valid_votes.append(self.node.url)

        filtered_services = [s for s in services if f"http://{s}:3400" != self.node.url]
        for service in filtered_services:
            service_url = f"http://{service}:3400/vote_on_block"

            try:
                response = requests.post(service_url, json=block)
                if response.status_code == 200 and response.json().get('message') == 'Block is valid':
                    valid_votes.append(service)
                    logging.info(f"Validator {service} approved the block.")
                else:
                    logging.info(f"Validator {service} did not approve the block.")
            except requests.exceptions.RequestException as e:
                logging.error(f"Error voting on block with {service}: {e}")

        return valid_votes

    def validate_block(self, block):
        logging.debug(f"Validating block with index {block['index']}")
        if block['validator'] not in self.validators:
            logging.error("Block validator is not recognized.")
            return False

        if not self.proof_of_stake(block):
            return False

        unique_addresses = set()
        double_spent_addresses = set()
        for transaction in block['transactions']:
            sender_address = transaction.get('address')
            if sender_address in unique_addresses:
                double_spent_addresses.add(sender_address)
            unique_addresses.add(sender_address)

        if double_spent_addresses:
            logging.error(f"Double spending detected for addresses: {', '.join(double_spent_addresses)}")
            raise DoubleSpendingError("Double spending detected for addresses: " + ', '.join(double_spent_addresses))

        block_string = str(block['index']) + str(block['timestamp']) + str(block['previous_hash']) + str(
            block['transactions']) + str(block['fee']) + str(block['validator']) + str(block['validator_share'])

        generated_hash = hashlib.sha256(block_string.encode()).hexdigest()
        if block['hash'] != generated_hash:
            logging.error("Block hash does not match the generated hash.")
            return False

        if not self.reach_consensus(block):
            logging.error("Failed to reach consensus.")
            return False

        logging.info(f"Block with index {block['index']} passed all validations.")
        return True

    def validate_foreign_block(self, block):
        logging.debug(f"Validating block with index {block['index']}")
        if block['validator'] not in self.validators:
            logging.error("Block validator is not recognized.")
            return False

        if not self.proof_of_stake(block):
            return False

        unique_addresses = set()
        double_spent_addresses = set()
        for transaction in block['transactions']:
            sender_address = transaction.get('address')
            if sender_address in unique_addresses:
                double_spent_addresses.add(sender_address)
            unique_addresses.add(sender_address)

        if double_spent_addresses:
            logging.error(f"Double spending detected for addresses: {', '.join(double_spent_addresses)}")
            raise DoubleSpendingError("Double spending detected for addresses: " + ', '.join(double_spent_addresses))

        block_string = str(block['index']) + str(block['timestamp']) + str(block['previous_hash']) + str(
            block['transactions']) + str(block['fee']) + str(block['validator']) + str(block['validator_share'])

        generated_hash = hashlib.sha256(block_string.encode()).hexdigest()
        if block['hash'] != generated_hash:
            logging.error("Block hash does not match the generated hash.")
            return False

        return True

    def generate_block_hash(self, block):
        transactions_string = json.dumps(block['transactions'], sort_keys=True)

        block_contents = (
            str(block['index']) +
            str(block['timestamp']) +
            str(block['previous_hash']) +
            transactions_string +
            str(block['fee']) +
            str(block['miner']) +
            str(block['miner_share']) +
            str(block['validator']) +
            str(block['validator_share'])
        )

        block_hash = hashlib.sha256(block_contents.encode()).hexdigest()
        return block_hash
    
    def proof_of_stake(self, block):
        logging.info("Starting proof of stake validation.")

        total_stake_weight = sum(node['stake_weight'] if isinstance(node, dict) else node.stake_weight for node in self.verifier.nodes)
        random_number = random.uniform(0, total_stake_weight)
        cumulative_stake_weight = 0

        logging.info(f"Total stake weight: {total_stake_weight}, Random number for validator selection: {random_number}")

        for current_node in self.verifier.nodes:
            node_stake_weight = current_node['stake_weight'] if isinstance(current_node, dict) else current_node.stake_weight
            cumulative_stake_weight += node_stake_weight

            if cumulative_stake_weight > random_number:
                selected_validator_address = current_node['address'] if isinstance(current_node, dict) else current_node.address
                logging.info(f"Selected validator address: {selected_validator_address}, Stake weight: {node_stake_weight}")

                if selected_validator_address == block['validator']:
                    logging.info(f"Validator {selected_validator_address} matches the block's validator.")
                    if node_stake_weight >= block['stake_threshold']:
                        logging.info(f"Validator {selected_validator_address} meets the stake threshold.")
                        return node_stake_weight
                    else:
                        logging.error(f"Validator {selected_validator_address} does not meet the stake threshold.")
                        return 0

        logging.error("No suitable validator found or the selected validator does not meet the stake threshold.")
        return 0

    def add_coin_transaction(self, address: str, amount: int, converted_amount: Union[int, float], fee: Union[int, float], hash: str, pub_key: str, signature: str, sub_type: str, type: str) -> Union[bool, str]:

        cleaned_transaction = {
            'address': address,
            'amount': amount,
            'converted_amount': converted_amount,
            'fee': fee,
            'hash': hash,
            'pub_key': pub_key,
            'signature': signature,
            'sub_type': sub_type,
            'type': type
        }

        if cleaned_transaction['signature']:
            return cleaned_transaction
        
    def select_miner(self) -> dict:
        accounts = staking_manager.staking_agreements

        # If no accounts are available, return None
        if not accounts:
            logging.warning("No staking accounts available for miner selection.")
            return None

        # Calculate the number of withdrawals for each account
        for account in accounts:
            account['withdrawals'] = sum(1 for block in self.chain for transaction in block['transactions']
                                        if 'address' in transaction and transaction.get('address') == account['address'])

        # Select the miner based on weighted selection
        miner = self.weighted_selection(accounts)
        return miner

    def weighted_selection(self, accounts: List[dict]) -> dict:
        # Calculate weights based on the number of withdrawals for each account
        weights = [1 / (acc['withdrawals'] + 1) for acc in accounts]
        total_weight = sum(weights)

        # Normalize the weights to ensure their sum is 1
        normalized_weights = [weight / total_weight for weight in weights]

        # Select an account using the normalized weights
        chosen_account = random.choices(
            accounts, weights=normalized_weights, k=1)[0]
        return chosen_account

    def calculate_fee_distribution(self, total_fee):
        fee_distribution = {}

        validator_percentage = 0.45
        miner_percentage = 0.315
        treasury_percentage = 0.235  # Updated to include the burn percentage

        fee_distribution['validator_share'] = total_fee * validator_percentage
        fee_distribution['miner_share'] = total_fee * miner_percentage
        fee_distribution['treasury_share'] = total_fee * treasury_percentage

        return fee_distribution
    
    def select_validator(self, block):
        selected_validator = self.verifier.select_validator(block)
        return selected_validator if selected_validator else None

    def validate_selected_validator(self, selected_validator, block):
        if selected_validator.malicious or selected_validator not in verifier.verified_nodes:
            return False

        if selected_validator.address == block['validator'] and \
                selected_validator.stake_weight >= block['stake_threshold']:
            return True

        return False

    def add_malicious_validator(self, validator_address):
        for node in self.nodes:
            if node.address == validator_address:
                node.malicious = True
                break

    def create_new_block(self, transactions):
        latest_block = self.chain[-1]
        block_index = latest_block['index'] + 1
        timestamp = int(datetime.now(timezone.utc).timestamp())
        previous_hash = latest_block['hash']
        stake_threshold = self.node.stake_weight

        processed_transactions, total_fee = self.process_transactions(transactions)
        block_fee = self.coin.mint_for_block_fee(total_fee)
        fee_distribution = self.calculate_fee_distribution(block_fee)
        miner = self.select_miner()

        if miner is None:
            logging.error("Failed to select a miner. Aborting block creation.")
            return

        miner_address = miner['address']

        block = {
            'index': block_index,
            'timestamp': timestamp,
            'previous_hash': previous_hash,
            'transactions': processed_transactions,
            'stake_threshold': stake_threshold,
            'fee': block_fee
        }

        validator_node = self.select_validator(block)
        validator_address = validator_node.address if validator_node else self.node.address

        for transaction in transactions:
            merkle_tree.add_transaction(str(transaction))

        merkle_tree.create_tree()
        merkle_root = merkle_tree.get_merkle_root()

        self.coin.credit(validator_address, fee_distribution['validator_share'])
        self.coin.credit(miner_address, fee_distribution['miner_share'])
        self.coin.credit(self.coin.treasury_address, fee_distribution['treasury_share'])

        new_block = {
            'index': block_index,
            'timestamp': timestamp,
            'previous_hash': previous_hash,
            'transactions': processed_transactions,
            'merkle_root': merkle_root,
            'stake_threshold': stake_threshold,
            'fee': block_fee,
            'miner': miner_address,
            'miner_share': fee_distribution['miner_share'],
            'validator': validator_address,
            'validator_share': fee_distribution['validator_share'],
            'treasury_share': fee_distribution['treasury_share']
        }

        logging.info(f"constructed block: {new_block}")

        block_string = str(new_block['index']) + str(new_block['timestamp']) + str(new_block['previous_hash']) + str(
            new_block['transactions']) + str(new_block['fee']) + str(new_block['validator']) + str(new_block['validator_share'])

        # Generate block hash
        block_hash = hashlib.sha256(block_string.encode()).hexdigest()

        new_block['hash'] = block_hash

        if self.add_block(new_block):
            self.transactions.cleaned_transactions = []
            logging.info(f"Successfully mined new block: {new_block}")
            return new_block
        else:
            logging.debug(f"Issue mining block: {new_block}")

    def process_transactions(self, transactions):
        processed_transactions = []
        total_fee = 0.0

        for transaction in transactions:
            transaction_type = transaction.get('sub_type')

            if transaction_type == 'r':
                processed_transaction = self.handle_staking_transaction(transaction)
            elif transaction_type == 'o':
                processed_transaction = self.handle_unstaking_transaction(transaction)
            elif transaction_type == 'k':
                processed_transaction = self.handle_transfer_transaction(transaction)
            elif transaction_type == 'w':
                processed_transaction = self.handle_pomc_whitelist_transaction(transaction)
            elif transaction_type in ['h', 'x', 'm', 'pr']:
                processed_transaction = self.handle_fee_payment_transaction(transaction)
            else:
                processed_transaction = self.handle_default_transaction(transaction)

            if processed_transaction:
                processed_transactions.append(processed_transaction)
                total_fee += processed_transaction.get('fee', 0.0)

        return processed_transactions, total_fee

    def handle_staking_transaction(self, transaction):
        try:
            fee_calculator = DynamicFeeCalculator()
            sender_address = transaction['address']
            staking_amount = transaction['amount']
            min_term = transaction['min_term']
            pub_key = transaction['pub_key']
            signature = transaction.get('signature')

            transaction_data = {
                'address': sender_address,
                'amount': staking_amount,
                'min_term': min_term,
                'pub_key': pub_key,
                'type': transaction['type']
            }

            transaction_fee, transaction_hash = dynamic_fee_calculator.get_base_dynamic_fee(transaction_data, transaction['type'])

            if not all([sender_address, staking_amount, min_term, pub_key, signature]):
                logging.error("Missing fields in staking transaction")
                return None

            sender_balance_info = self.wallet.get_account_balance(sender_address)
            if not sender_balance_info or sender_balance_info['balance_float'] < staking_amount + transaction_fee:
                logging.error("Insufficient balance for staking")
                return None

            transaction_for_verification = {
                'address': sender_address,
                'amount': staking_amount,
                'fee': transaction_fee,
                'hash': transaction_hash,
                'min_term': min_term,
                'pub_key': pub_key,
                'type': transaction['type']
            }

            if not crypto_utils.verify_transaction(transaction['pub_key'], transaction_for_verification, transaction['signature']):
                logging.error("Invalid signature in staking transaction")
                return None

            self.wallet.stake_coins(sender_address, staking_amount, min_term)

            processed_transaction = {
                'address': sender_address,
                'amount': staking_amount,
                'fee': transaction_fee,
                'hash': transaction_hash,
                'min_term': min_term,
                'stake_threshold': 3,
                'type': transaction['type'],
                'when': str(datetime.now(timezone.utc))
            }

            logging.info(f"Processed staking transaction for {sender_address}")
            return processed_transaction

        except Exception as e:
            logging.error(f"Error processing staking transaction: {e}")
            return None

    def handle_unstaking_transaction(self, transaction):
        try:
            fee_calculator = DynamicFeeCalculator()
            sender_address = transaction['address']
            contract_id = transaction['contract_id']
            pub_key = transaction['pub_key']
            signature = transaction.get('signature')

            transaction_data = {
                'address': sender_address,
                'contract_id': contract_id,
                'pub_key': pub_key,
                'type': transaction['type']
            }

            transaction_fee, transaction_hash = dynamic_fee_calculator.get_base_dynamic_fee(transaction_data, transaction['type'])

            if not all([sender_address, contract_id, pub_key, signature]):
                logging.error("Missing fields in unstaking transaction")
                return None

            sender_balance_info = self.wallet.get_account_balance(sender_address)
            if not sender_balance_info or sender_balance_info['balance_float'] < transaction_fee:
                logging.error("Insufficient balance for unstaking")
                return None

            transaction_for_verification = {
                'address': sender_address,
                'contract_id': contract_id,
                'fee': transaction_fee,
                'hash': transaction_hash,
                'pub_key': pub_key,
                'type': transaction['type']
            }

            if not crypto_utils.verify_transaction(transaction['pub_key'], transaction_for_verification, transaction['signature']):
                logging.error("Invalid signature in unstaking transaction")
                return None

            self.wallet.unstake_coins(sender_address, contract_id)

            processed_transaction = {
                'address': sender_address,
                'contract_id': contract_id,
                'fee': transaction_fee,
                'hash': transaction_hash,
                'stake_threshold': 2,
                'type': transaction['type'],
                'when': str(datetime.now(timezone.utc))
            }

            logging.info(f"Processed unstaking transaction for {sender_address}")
            return processed_transaction

        except Exception as e:
            logging.error(f"Error processing unstaking transaction: {e}")
            return None

    def handle_transfer_transaction(self, transaction):
        try:
            fee_calculator = DynamicFeeCalculator()
            sender_address = transaction['sender']
            recipient_address = transaction['recipient']
            transfer_amount = transaction['amount']
            pub_key = transaction['pub_key']
            signature = transaction.get('signature')

            transaction_data = {
                'sender': sender_address,
                'recipient': recipient_address,
                'amount': transfer_amount,
                'pub_key': pub_key,
                'type': transaction['type']
            }

            transaction_fee, transaction_hash = dynamic_fee_calculator.get_base_dynamic_fee(transaction_data, transaction['type'])

            if not all([sender_address, recipient_address, transfer_amount, pub_key, signature]):
                logging.error("Missing fields in transfer transaction")
                return None

            sender_balance_info = self.wallet.get_account_balance(sender_address)
            if not sender_balance_info or sender_balance_info['balance_float'] < transfer_amount + transaction_fee:
                logging.error("Insufficient balance for transfer")
                return None

            transaction_for_verification = {
                'sender': sender_address,
                'recipient': recipient_address,
                'amount': transfer_amount,
                'fee': transaction_fee,
                'hash': transaction_hash,
                'pub_key': pub_key,
                'type': transaction['type']
            }

            if not crypto_utils.verify_transaction(transaction['pub_key'], transaction_for_verification, transaction['signature']):
                logging.error("Invalid signature in transfer transaction")
                return None

            self.wallet.transfer(sender_address, recipient_address, transfer_amount)

            processed_transaction = {
                'sender': sender_address,
                'recipient': recipient_address,
                'amount': transfer_amount,
                'fee': transaction_fee,
                'hash': transaction_hash,
                'stake_threshold': 2,
                'type': transaction['type'],
                'when': str(datetime.now(timezone.utc))
            }

            logging.info(f"Processed transfer transaction from {sender_address} to {recipient_address}")
            return processed_transaction

        except Exception as e:
            logging.error(f"Error processing transfer transaction: {e}")
            return None
    
    def handle_pomc_whitelist_transaction(self, transaction):
        try:
            
            sender_address = transaction['sender']
            pub_key = transaction['pub_key']
            signature = transaction.get('signature')

            processed_transaction = {
                'fee': transaction['fee'],
                'hash': transaction['hash'],
                'sender': transaction['sender'],
                'sub_type': transaction['sub_type'],
                'stake_threshold': 2,
                'type': transaction['type'],
                'when': transaction['when']
            }

            logging.info(f"Processed transfer transaction from {sender_address} to join pOMC whitelist")
            return processed_transaction

        except Exception as e:
            logging.error(f"Error processing transfer transaction: {e}")
            return None

    def handle_fee_payment_transaction(self, transaction):
        try:
            fee_calculator = DynamicFeeCalculator()
            payer_address = transaction['from']
            fee_amount = transaction['fee']
            pub_key = transaction['pub_key']
            signature = transaction.get('signature')

            transaction_data = {
                'from': payer_address,
                'fee': fee_amount,
                'pub_key': pub_key,
                'type': transaction['type']
            }

            calculated_fee, transaction_hash = dynamic_fee_calculator.get_base_dynamic_fee(transaction_data, transaction['type'])

            if not all([payer_address, fee_amount, pub_key, signature]):
                logging.error("Missing fields in fee payment transaction")
                return None

            payer_balance_info = self.wallet.get_account_balance(payer_address)
            if not payer_balance_info or payer_balance_info['balance_float'] < fee_amount + calculated_fee:
                logging.error("Insufficient balance for fee payment")
                return None

            transaction_for_verification = {
                'from': payer_address,
                'fee': calculated_fee,
                'hash': transaction_hash,
                'pub_key': pub_key,
                'type': transaction['type']
            }

            if not crypto_utils.verify_transaction(transaction['pub_key'], transaction_for_verification, transaction['signature']):
                logging.error("Invalid signature in fee payment transaction")
                return None

            self.wallet.pay_fee(payer_address, fee_amount)

            processed_transaction = {
                'from': payer_address,
                'fee': calculated_fee,
                'hash': transaction_hash,
                'stake_threshold': 2,
                'type': transaction['type'],
                'when': str(datetime.now(timezone.utc))
            }

            logging.info(f"Processed fee payment transaction from {payer_address}")
            return processed_transaction

        except Exception as e:
            logging.error(f"Error processing fee payment transaction A1: {e}")
            return None

    def handle_default_transaction(self, transaction):
        try:
            fee_calculator = DynamicFeeCalculator()
            payer_address = transaction['address']

            transaction_data = {
                'from': payer_address,
                'type': 'e'
            }

            calculated_fee, transaction_hash = dynamic_fee_calculator.get_base_dynamic_fee(transaction_data, transaction['type'])

            processed_transaction = {
                'from': payer_address,
                'fee': 0.0,
                'hash': transaction_hash,
                'stake_threshold': 1,
                'type': 'e',
                'when': str(datetime.now(timezone.utc))
            }

            logging.info(f"Processed fee payment transaction from {payer_address}")
            return processed_transaction

        except Exception as e:
            logging.error(f"Error processing fee payment transaction A2: {e}")
            return None

    def clean_and_verify_transactions(self):
        new_transactions = self.transactions.batch_pending_transactions()
        cleaned_transactions = []

        for transaction in new_transactions:
            try:
                if transaction['type'] == 'c' and transaction['sub_type'] == 'c':
                    self.process_account_creation_transaction(transaction)
                elif transaction['type'] == 'c' and transaction['sub_type'] == 'w':
                    self.process_add_account_to_whitelist_transaction(transaction)
                elif transaction['type'] == 'o':
                    self.process_non_f_transaction(transaction)
                elif transaction['type'] == 'e':
                    self.process_f_transaction(transaction)
            except Exception as e:
                logging.error(f"Error processing transaction {transaction['type']}: {e}")

        return cleaned_transactions
    
    def process_account_creation_transaction(self, transaction):
        # Verify that the transaction is of the correct type
        if transaction['type'] != 'c':
            logging.error(f"Invalid transaction type for account creation: {transaction['type']}")
            return

        try:
            # Extract necessary fields from the transaction
            address = transaction['address']
            balance = transaction['balance']
            type = transaction['type']
            timestamp = ['timestamp']
            withdrawals = transaction['withdrawals']

            # Validate the transaction data
            if not all([address, type]):
                logging.error("Incomplete account creation transaction data")
                return

            # Check if the address already exists in the blockchain wallet
            # if any(acc['address'] == address for acc in account_manager.accounts):
            #     logging.info(f"Account already exists: {address}")
            #     return

            # # Create and append the new account to the wallet
            # new_account = {
            #     'address': address,
            #     'balance': balance,
            #     'withdrawals': withdrawals
            # }
            # account_manager.accounts.append(new_account)

            # Create a cleaned version of the transaction for the blockchain
            cleaned_transaction = {
                'address': address,
                'hash': transaction.get('hash'),
                'pub_key': transaction['pub_key'],
                'signature': transaction['signature'],
                'sub_type': 'c',
                'type': transaction['type'],
                'withdrawals': withdrawals
            }

            # Append the cleaned transaction to the list of processed transactions
            self.transactions.cleaned_transactions.append(cleaned_transaction)
            logging.info(f"Processed account creation transaction for {address}")

        except Exception as e:
            logging.error(f"Error processing account creation transaction A2: {e}")
            
    def process_add_account_to_whitelist_transaction(self, transaction):
        # Verify that the transaction is of the correct type
        if transaction['type'] != 'c':
            logging.error(f"Invalid transaction type to add account to whitelist: {transaction['type']}")
            return

        try:
            result = {
                'fee': transaction['fee'],
                'hash': transaction['hash'],
                'pub_key': transaction['pub_key'],
                'sender': transaction['sender'],
                'signature': transaction['signature'],
                'sub_type': transaction['sub_type'],
                'type': transaction['type'],
                'when': transaction['when']
            }
            # Extract necessary fields from the transaction
            address = transaction['sender']
            hash = transaction['hash']
            type = transaction['type']

            # Validate the transaction data
            if not all([address, hash, type]):
                logging.error("Incomplete account creation transaction data")
                return

            # Create a cleaned version of the transaction for the blockchain
            cleaned_transaction = {
                'fee': transaction['fee'],
                'hash': transaction['hash'],
                'pub_key': transaction['pub_key'],
                'sender': transaction['sender'],
                'signature': transaction['signature'],
                'sub_type': transaction['sub_type'],
                'type': transaction['type'],
                'when': transaction['when']
            }

            # Append the cleaned transaction to the list of processed transactions
            self.transactions.cleaned_transactions.append(cleaned_transaction)
            logging.info(f"Processed join whitelist transaction for {address}")

        except Exception as e:
            logging.error(f"Error processing join whiteist transaction A2: {e}")

    def process_f_transaction(self, transaction):
        try:
            transaction_type = transaction.get('type')
            sender_address = transaction.get('address')
            transaction_fee = transaction.get('fee', 0.0)

            if not sender_address or transaction_fee is None:
                logging.error("Invalid transaction format.")
                return None

            cleaned_transaction = None

            if transaction_type == 'e':
                sub_tx_type = transaction.get('sub_type')

                if sub_tx_type == 'p':
                    amount = transaction.get('amount')
                    recipient_address = transaction.get('recipient')

                    if crypto_utils.verify_transaction(sender_address, recipient_address, amount):
                        self.wallet.transfer(sender_address, recipient_address, amount)

                elif sub_tx_type == 'r':
                    amount = transaction.get('amount')
                    min_term = transaction.get('min_term')

                    self.wallet.stake_coins(sender_address, amount, min_term)

                elif sub_tx_type == 'z':
                    contract_id = transaction.get('contract_id')

                    self.wallet.unstake_coins(sender_address, contract_id)

            if cleaned_transaction:
                self.transactions.cleaned_transactions.append(cleaned_transaction)
                logging.info(f"Processed transaction of type {transaction_type} for {sender_address}")
                return cleaned_transaction
            else:
                logging.warning(f"Unhandled or failed transaction type/subtype: {transaction_type}/{sub_tx_type}")
                return None

        except Exception as e:
            logging.error(f"Error processing account creation transaction A2: {e}")

    def process_non_f_transaction(self, transaction):
        try:
            transaction_type = transaction.get('type')
            sender_address = transaction.get('address')
            transaction_fee = transaction.get('fee', 0.0)

            if not sender_address or transaction_fee is None:
                logging.error("Invalid transaction format.")
                return None

            cleaned_transaction = None

            if transaction_type == 'o':
                sub_tx_type = transaction.get('sub_type')

                if sub_tx_type == 's':
                    self.handle_post_transaction(transaction)

                elif sub_tx_type == 'j':
                    refined_transaction = self.handle_add_profile_transaction(transaction)
                    if refined_transaction:
                        cleaned_transaction = {
                            'address': transaction['address'],
                            'avi': transaction['avi'],
                            'clubs': transaction['clubs'],
                            'fee': transaction['fee'],
                            'handle': transaction['handle'],
                            'hash': transaction['hash'],
                            'intro': transaction['intro'],
                            'joined': transaction['joined'],
                            'name': transaction['name'],
                            'profile_id': transaction['profile_id'],
                            'profile_type': transaction['profile_type'],
                            'pt': transaction['pt'],
                            'pt_id': transaction['pt_id'],
                            'pub_key': transaction['pub_key'],
                            'signature': transaction['signature'],
                            'sub_type': transaction['sub_type'],
                            'tags': transaction['tags'],
                            'type': transaction['type'],
                            'version': transaction['version']
                        }

            if cleaned_transaction:
                transactions.cleaned_transactions.append(cleaned_transaction)
                logging.info(f"Processed transaction of type {transaction_type} for {sender_address}")
                return cleaned_transaction
            else:
                logging.warning(f"Unhandled or failed transaction type/subtype: {transaction_type}/{sub_tx_type}")
                return None

        except Exception as e:
            logging.error(f"Error processing transaction: {e}")
            return None

    def start_mining(self):
        self.create_new_block(self.transactions.cleaned_transactions)

    def check_pending_transactions(self):
        self.clean_and_verify_transactions()
        self.start_mining()

    def get_latest_block(self):
        return self.chain[-1]

    def main_loop(self):
        while True:
            self.start_mining()
            self.consume_blocks()

    def consume_blocks(self):
        for message in self.consumer:
            block_data = message.value.decode('utf-8')
            block = json.loads(block_data)
            self.receive_block(block)

    def __init__(self, coin, node, wallet, transactions, verifier):
        self.coin = coin
        self.node = node
        self.wallet = wallet
        self.transactions = transactions
        self.verifier = verifier

        self.chain = []
        self.block_hashes = set()
        self.lock = threading.Lock()
        logging.basicConfig(level=logging.DEBUG)
        
        self.validators = []
        
        mining_thread = threading.Thread(target=self.mine_new_block_periodically)
        mining_thread.daemon = True
        mining_thread.start()

    @staticmethod
    def serialize_and_create_single_hash(cls):
        if not isinstance(cls, type):
            raise TypeError(f"Expected class type, got {type(cls)}")

        try:
            class_dict = {
                'attributes': {key: value for key, value in cls.__dict__.items() if not callable(value) and not key.startswith('__')},
                'methods': {
                    key: (value.__func__.__code__.co_code if isinstance(value, staticmethod) else value.__code__.co_code)
                    for key, value in cls.__dict__.items() if callable(value)
                }
            }
            class_serialized = json.dumps(class_dict, sort_keys=True, default=str)
            logging.debug(f"Serialized class {cls.__name__}: {class_serialized}")
            class_hash = hashlib.sha256(class_serialized.encode()).hexdigest()
            return class_hash
        except Exception as e:
            logging.error(f"Error serializing class {cls.__name__}: {e}")
            raise

    @staticmethod
    def verify_class_hashes():
        """
        This function retrieves the stored hashes of classes from the public API and compares them
        with the hashes of the current local classes to ensure integrity.
        """
        try:
            response = requests.get(HASH_API_URL)
            if response.status_code != 200:
                raise ValueError("Failed to fetch class hashes from public API.")

            stored_hashes = response.json()
        except Exception as e:
            logging.error(f"Error fetching class hashes from public API: {e}")
            raise

        classes_to_verify = {
            'coin': OMC,
            'precursor_coin': pOMC,
            'verifier': Verifier,
            'crypto_utils': CUtils,
            'fee_calculator': DynamicFeeCalculator,
            'ledger': Ledger
        }

        for class_name, cls in classes_to_verify.items():
            stored_hash = stored_hashes.get(class_name)
            if not stored_hash:
                logging.error(f"Stored hash for class {class_name} not found in the public API response.")
                raise ValueError(f"Stored hash for class {class_name} not found.")

            local_hash = Ledger.serialize_and_create_single_hash(cls)
            if stored_hash != local_hash:
                logging.error(f"Hash mismatch for class {class_name}. Possible tampering detected.")
                raise ValueError(f"Hash mismatch for class {class_name}. Possible tampering detected.")

        logging.info("All class hashes verified successfully. No tampering detected.")
        return True

    def initialize_node(self):
        service_prefix = "node"
        services = self.discover_services(service_prefix)
        if services:
            self.ping_services(services, "check_nodes", self.node.url)

        self.node.steward = os.getenv('STEWARD_ADDRESS')
        if not self.node.steward:
            raise ValueError("Steward address not provided. Set the STEWARD_ADDRESS environment variable.")

        self.update_node_state(self.node)
        self.check_chain_length_and_sync(services)
        self.update_validators()
        self.broadcast_node_data(self.node)

    def discover_services(self, prefix):
        discovered_services = []
        max_range = 10

        for i in range(1, max_range):
            service_name = f"{prefix}{i}.omne"
            try:
                service_address = socket.gethostbyname(service_name)

                if service_address != self.node.url:
                    discovered_services.append(service_name)
                    logging.debug(f"Discovered service: {service_name}")

            except socket.gaierror:
                continue

        if not discovered_services:
            logging.warning("No services were discovered.")

        return discovered_services

    def ping_services(self, services, endpoint, current_node_url):
        headers = {"Authorization": f"Bearer {AUTH_TOKEN}"}

        for service in services:
            service_base_url = f"http://{service}:3400"
            service_url = f"{service_base_url}/{endpoint}"

            if service_base_url == current_node_url:
                logging.debug(f"Skipping self ping: {service_base_url}")
                continue

            logging.debug(f"Attempting to ping {service_url}")
            try:
                response = requests.get(service_url, headers=headers)
                if response.status_code == 200:
                    logging.debug(f"Successfully pinged {service_url}")
                    received_nodes = response.json().get('nodes', [])
                    for received_node in received_nodes:
                        if not any(node['address'] == received_node['address'] for node in self.verifier.nodes):
                            verifier.nodes.append(received_node)
                            verifier.nodes.append(received_node)
                            self.validators.append(received_node['address'])
                            logging.debug(f"Added new node: {received_node['address']}")
                else:
                    logging.debug(f"Failed to ping {service_url}, status code: {response.status_code}")

            except requests.exceptions.RequestException as e:
                logging.error(f"Error pinging {service_url}: {e}")

    def post_data_to_services(self, services, endpoint, data):
        headers = {"Authorization": f"Bearer {AUTH_TOKEN}"}

        for service in services:
            service_base_url = f"http://{service}:3400"
            service_url = f"{service_base_url}/{endpoint}"

            if service_base_url == self.node.url:
                logging.debug(f"Skipping self post: {service_url}")
                continue

            logging.debug(f"Attempting to post data to {service_url}")
            try:
                response = requests.post(service_url, json=data, headers=headers)
                if response.status_code == 200:
                    logging.debug(f"Successfully posted data to {service_url}")
                else:
                    logging.debug(f"Failed to post data to {service_url}, status code: {response.status_code}")

            except requests.exceptions.RequestException as e:
                logging.error(f"Error posting data to {service_url}: {e}")

    def broadcast_self_info(self):
        if not self.node or not self.node.address or not self.node.url:
            logging.error("Node information is incomplete or incorrect. Cannot broadcast.")
            return

        node_info = self.node.to_dict()
        logging.info(f"Broadcasting self node information: {node_info}")

        services = self.discover_services("node")
        if not services:
            logging.warning("No other services discovered for broadcasting. Broadcast aborted.")
            return

        services = [service for service in services if service != self.node.url]
        if not services:
            logging.warning("No external services discovered for broadcasting. Broadcast aborted.")
            return

        self.post_data_to_services(services, "receive_node_info", node_info)
        logging.info("Successfully broadcasted self node information to other services.")

    def update_validators(self):
        services = self.discover_services("node")
        for service in services:
            service_base_url = f"http://{service}:3400"
            service_url = f"{service_base_url}/node_info"

            if service_base_url == self.node.url:
                continue

            try:
                response = requests.get(service_url)
                if response.status_code == 200:
                    node_data = response.json()
                    if node_data['address'] not in self.validators:
                        self.validators.append(node_data['address'])
            except requests.exceptions.RequestException as e:
                logging.error(f"Failed to retrieve node information from {service}: {e}")

    def sync_with_other_nodes(self, services):
        my_chain_length = len(self.chain)
        synchronized_chain = None
        authoritative_node_url = None

        for service in services:
            service_base_url = f"http://{service}:3400"
            service_url = f"{service_base_url}/get_chain"

            if service_base_url == self.node.url:
                continue

            try:
                response = requests.get(service_url)
                if response.status_code == 200:
                    other_chain = response.json()["chain"]
                    if len(other_chain) > my_chain_length:
                        my_chain_length = len(other_chain)
                        synchronized_chain = other_chain
                        authoritative_node_url = service_base_url
            except requests.exceptions.RequestException as e:
                logging.error(f"Error while trying to sync with {service_url}: {e}")

        if synchronized_chain:
            self.chain = synchronized_chain

        return authoritative_node_url, synchronized_chain

    def broadcast_node_data(self, node):
        headers = {"Authorization": f"Bearer {AUTH_TOKEN}"}
        node_data_complete = {
            'address': node.address,
            'public_key': node.public_key,
            'url': node.url,
            'stake_weight': node.stake_weight,
            'version': node.version,
            'steward': node.steward
        }

        services = self.discover_services("node")

        for service in services:
            service_base_url = f"http://{service}:3400"
            service_url = f"{service_base_url}/receive_node_data"

            if service_base_url == self.node.url:
                continue

            logging.debug(f"Broadcasting node data to {service_url}")
            try:
                response = requests.post(service_url, json=node_data_complete, headers=headers)
                if response.status_code == 200:
                    logging.debug(f"Successfully broadcasted node data to {service_url}")
                else:
                    logging.warning(f"Failed to broadcast node data to {service_url}, status code: {response.status_code}")
            except requests.exceptions.RequestException as e:
                logging.error(f"Error broadcasting node data to {service_url}: {e}")

    def update_accounts(self, address, balance):
        new_account = {
            'address': address,
            'balance': balance
        }

        service_prefix = "node"
        services = self.discover_services(service_prefix)

        filtered_services = [s for s in services if f"http://{s}:3400" != self.node.url]
        self.post_data_to_services(filtered_services, "propagate_account", new_account)

    def update_node_state(self, new_node):
        if new_node not in self.verifier.nodes:
            verifier.nodes.append(new_node)
            self.node.verifier.verified_nodes.append(new_node)
            self.validators.append(new_node.address)
            logging.info(f"Node {new_node.address} added to local state.")

    def mine_new_block_periodically(self, interval=9):
        while True:
            self.check_for_mining_opportunity()
            time.sleep(interval * 60)

    def check_for_mining_opportunity(self):
        num_transactions = len(self.transactions.transactions)
        if num_transactions >= 1:
            self.check_pending_transactions()
        elif 4 <= num_transactions < 15 and self.is_time_to_mine():
            self.check_pending_transactions()

    def is_time_to_mine(self):
        latest_block = self.chain[-1]
        block_timestamp = datetime.strptime(latest_block['timestamp'], "%Y-%m-%d %H:%M:%S.%f%z")
        current_timestamp = datetime.now(timezone.utc)
        return (current_timestamp - block_timestamp).total_seconds() >= 8 * 60

    def create_new_wallet(self):
        mnemonic = crypto_utils.generate_mnemonic()
        account = self.wallet.account_manager.generate_account_from_mnemonic(mnemonic)
        account_manager.accounts.append(account_dict)
        # Add the new address with a balance of zero to the self.balance dictionary
        with coin.balance_lock:
            coin.balance[account['address']] = 0.0

        wallet_creation_transaction = {
            'address': account['address'],
            'balance': 0.0,
            'withdrawals': 0,
            'type': 'c'
        }

        cleaned_transaction = {
            'address': wallet_creation_transaction['address'],
            'balance': wallet_creation_transaction['balance'],
            'pub_key': account['pub_key'],
            'sub_type': 'c',
            'type': wallet_creation_transaction['type'],
            'withdrawals': wallet_creation_transaction['withdrawals']
        }

        initial_balance = 0.0

        account_dict = {
            'address': wallet_creation_transaction['address'],
            'balance': initial_balance,
        }

        sendable_transaction = {
            'mnemonic': mnemonic,
            'private_key': base64.b64encode(account['private_key']).decode('utf-8'),
            'pub_key': account['pub_key'],
            'address': account['address'],
        }

        return sendable_transaction

    def create_new_wallet_from_seed(self, seed):
        account = self.wallet.account_manager.generate_account_from_mnemonic(seed)

        wallet_creation_transaction = {
            'address': account['address'],
            'balance': 0.0,
            'withdrawals': 0,
            'type': 'c'
        }

        cleaned_transaction = {
            'address': wallet_creation_transaction['address'],
            'balance': wallet_creation_transaction['balance'],
            'pub_key': account['pub_key'],
            'type': wallet_creation_transaction['type'],
            'withdrawals': wallet_creation_transaction['withdrawals']
        }

        sendable_transaction = {
            'mnemonic': account['mnemonic'],
            'private_key': base64.b64encode(account['private_key']).decode('utf-8'),
            'pub_key': account['pub_key'],
            'address': account['address'],
        }

        private_key_bytes = base64.b64decode(sendable_transaction['private_key'])
        signature = crypto_utils.sign_transaction(private_key_bytes, wallet_creation_transaction)

        cleaned_transaction['signature'] = signature

        self.transactions.transactions.append(cleaned_transaction)
        self.update_accounts(wallet_creation_transaction['address'], wallet_creation_transaction['balance'])

        return sendable_transaction

    def get_chain_length(self):
        return len(self.chain) if hasattr(self, "blockchain") else 0

    def check_chain_length_and_sync(self, services):
        service_prefix = "node"
        services = self.discover_services(service_prefix)

        authoritative_node_url, synchronized_chain = self.sync_with_other_nodes(services)

        self.sync_account_list_data(authoritative_node_url, account_manager, coin, staked_coin)
        self.sync_treasury_data(authoritative_node_url)

        self.ping_services(services, "check_nodes", self.node.url)

        if synchronized_chain is not None:
            return {
                "chain": synchronized_chain,
                "message": "Chain synchronized successfully"
            }
        else:
            return {
                "chain": self.chain,
                "message": "Chain synchronization failed"
            }

    def sync_account_list_data(self, authoritative_node_url, account_manager, coin, staked_coin):
        if not authoritative_node_url:
            logging.error("No authoritative node URL provided for account list data synchronization.")
            return

        service_url = f"{authoritative_node_url}/retrieve_accounts"

        try:
            response = requests.get(service_url)
            if response.status_code == 200:
                data = response.json()

                main_accounts = data.get('data', [])
                for new_acc in main_accounts:
                    if 'address' in new_acc and 'balance' in new_acc:
                        account = next((acc for acc in account_manager.accounts if acc['address'] == new_acc['address']), None)
                        if account:
                            account['balance'] = new_acc['balance']
                            coin.balance[new_acc['address']] = new_acc['balance']
                            logging.info(f"Updated main account {new_acc['address']} for {coin.name}.")
                        else:
                            account_manager.accounts.append(new_acc)
                            coin.balance[new_acc['address']] = new_acc['balance']
                            logging.info(f"Added new main account {new_acc['address']} for {coin.name}.")

                precursor_accounts = data.get('precursor_accounts', [])
                for new_acc in precursor_accounts:
                    if 'address' in new_acc and 'balance' in new_acc:
                        account = next((acc for acc in account_manager.precursor_accounts if acc['address'] == new_acc['address']), None)
                        if account:
                            account['balance'] = new_acc['balance']
                            coin.balance[new_acc['address']] = new_acc['balance']
                            logging.info(f"Updated precursor account {new_acc['address']} for {coin.name}.")
                        else:
                            account_manager.precursor_accounts.append(new_acc)
                            coin.balance[new_acc['address']] = new_acc['balance']
                            logging.info(f"Added new precursor account {new_acc['address']} for {coin.name}.")

                staking_accounts = data.get('staking_accounts', [])
                for new_acc in staking_accounts:
                    if 'address' in new_acc and 'min_term' in new_acc:
                        account = next((acc for acc in staking_manager.staking_agreements if acc['address'] == new_acc['address']), None)
                        if account:
                            account['amount'] = new_acc['amount']
                            account['withdrawals'] = new_acc['withdrawals']
                            staked_coin.balance[new_acc['address']] = new_acc['amount']
                            logging.info(f"Updated staking account {new_acc['address']} for {staked_coin.name}.")
                        else:
                            staked_coin.accounts.append(new_acc)
                            staking_manager.staking_agreements.append(new_acc)
                            staked_coin.balance[new_acc['address']] = new_acc['amount']
                            logging.info(f"Added new staking account {new_acc['address']} for {staked_coin.name}.")

                self.validators = data.get('validators', [])
                if self.node.address not in self.validators:
                    self.validators.append(self.node.address)

                notification_data = {"message": "Data updated from authoritative node"}
                self.post_data_to_services(self.discover_services("node"), "notify_data_update", notification_data)

                logging.warning(f"Synchronized account list data with the authoritative node: {authoritative_node_url}")
            else:
                logging.error(f"Failed to retrieve account data from {service_url}, status code: {response.status_code}")
        except requests.RequestException as e:
            logging.error(f"Error retrieving account data from {service_url}: {e}")
            
    def sync_treasury_data(self, authoritative_node_url):
        if not authoritative_node_url:
            logging.error("No authoritative node URL provided for treasury data synchronization.")
            return False

        service_url = f"{authoritative_node_url}/retrieve_treasury_data"

        try:
            response = requests.get(service_url)
            if response.status_code == 200:
                response_data = response.json()
                if 'treasury_account' in response_data:
                    self.treasury.update_treasury_data(response_data['treasury_account'])
                    logging.warning("Synchronized treasury data with the authoritative node: %s", authoritative_node_url)
                    return True
                else:
                    logging.error(f"No treasury account data found in the response from {service_url}")
                    return False
            else:
                logging.error(f"Failed to retrieve treasury data from {service_url}, status code: {response.status_code}")
                return False
        except requests.RequestException as e:
            logging.error(f"Error retrieving treasury data from {service_url}: {e}")
            return False

    def add_account(self, account_data):
        address = account_data.get('address')
        balance_float = account_data.get('balance_float', 0)
        new_account = {}
        new_account['address'] = address
        new_account['balance'] = balance_float

        account_manager.accounts.append(new_account)
        coin.balance[address] = balance_float

        logging.info(f"Added/Updated account: {address} with balance {balance_float}")

    def add_staking_account(self, data):
        account_manager.staking_accounts.append(data)
        staked_coin.accounts.append(data)
        staking_manager.staking_accounts.append(data)

    def get_init_date(self):
        return coin.init_date

    def validate_chain(self, chain):
        previous_block = chain[0]
        for block in chain[1:]:
            if block['previous_hash'] != previous_block['hash']:
                return False

            block_data = block.copy()
            block_data.pop('hash')
            calculated_hash = self.calculate_block_hash(block_data)

            if block['hash'] != calculated_hash:
                return False

            if not self.validate_stake(block):
                return False

            previous_block = block

        return True

    def add_block(self, block):
        logging.info(f"Attempting to add block with index {block['index']}")
        if self.validate_received_block(block):
            with self.lock:
                if block['index'] == len(self.chain) + 1 and \
                   block['previous_hash'] == self.chain[-1]['hash']:
                    self.chain.append(block)
                    self.block_hashes.add(block['hash'])
                    logging.info(f"Block with index {block['index']} successfully added to the chain.")
                    self.broadcast_block(block)
                    return True
                else:
                    logging.warning(f"Block with index {block['index']} failed to match chain continuity.")
        else:
            logging.warning(f"Block with index {block['index']} failed validation.")
        return False
    
    def broadcast_block(self, new_block):
        block_data = json.dumps(new_block)

        service_prefix = "node"
        services = self.discover_services(service_prefix)

        self.post_data_to_services(services, "blocks/receive_block", block_data)
        
    def validate_foreign_tx(self, address, hash, pub_key, tx, signature):
        logging.debug(f"Validating tx from {address}")

        if not crypto_utils.verify_transaction(pub_key, tx, signature):
            logging.error(f"Invalid signature in foreign transaction with hash: {hash} from address: {address}")
            return None

        return True

    def vote_on_local_tx(self, address, hash, pub_key, tx, signature):
        valid_votes = []
        services = ledger.discover_services("node")

        if len(services) == 1 and services[0] == self.node.url:
            logging.info("Only one validator in the network, bypassing the voting process.")
            valid_votes.append(self.node.url)

        filtered_services = [s for s in services if f"http://{s}:3400" != self.node.url]
        for service in filtered_services:
            service_url = f"http://{service}:3400/vote_on_tx"

            try:
                data = {
                    'address': address,
                    'hash': hash,
                    'pub_key': pub_key,
                    'new_tx': tx,
                    'signature': signature
                }
                response = requests.post(service_url, json=data)
                if response.status_code == 200 and response.json().get('message') == 'Tx is valid':
                    valid_votes.append(service)
                    logging.info(f"Validator {service} approved the tx.")
                else:
                    logging.info(f"Validator {service} did not approve the tx.")
            except requests.exceptions.RequestException as e:
                logging.error(f"Error voting on block with {service}: {e}")

        return valid_votes

    def reach_tx_consensus(self, address, hash, pub_key, tx, signature):
        if len(self.validators) == 1:
            logging.info("Automatically reaching consensus with single validator")
            return True

        consensus_reached = self.vote_on_local_tx(address, hash, pub_key, tx, signature)

        if consensus_reached:
            logging.info("Tx consensus reached")
            return True
        else:
            logging.info("Tx consensus not reached")
            return False

    def receive_tx(self, address, hash, pub_key, tx, signature):
        try:
            if not self.validate_foreign_tx(address, hash, pub_key, tx, signature):
                logging.error(f"Received transaction, with hash {hash} from wallet {address}, did not pass verification")
                return False

            return True
        except Exception as e:
            logging.error(f"Error processing received transaction: {str(e)}")
            return False

    def receive_block(self, block):
        try:
            services = ledger.discover_services("node")
            authoritative_node_url, _ = ledger.sync_with_other_nodes(services)

            if authoritative_node_url:
                ledger.sync_account_list_data(authoritative_node_url, account_manager, coin, staked_coin)
                ledger.sync_treasury_data(authoritative_node_url)

            return True
        except Exception as e:
            logging.error(f"Error processing received block: {str(e)}")
            return False

    def broadcast_tx(self, address, hash, pub_key, new_tx, signature):
        data = {
            'address': address,
            'hash': hash,
            'pub_key': pub_key,
            'new_tx': new_tx,
            'signature': signature
        }

        services = ledger.discover_services("node")

        ledger.post_data_to_services(services, "transaction/receive_tx", data)

        return True
    
    def randomly_select_validator(self):
        if not self.validators:
            logging.warning("No validators available.")
            return None

        validator_address = random.choice(self.validators)
        logging.info(f"Randomly selected validator address: {validator_address}")
        return validator_address

    def trigger_sync_on_all_nodes(self):
        services = ledger.discover_services("node")

        data = {}

        for service in services:
            service_base_url = f"http://{service}:3400"

            if service_base_url == self.node.url:
                logging.debug(f"Skipping self sync trigger: {service_base_url}")
                continue

            service_url = f"{service_base_url}/trigger_sync"
            logging.debug(f"Attempting to trigger sync on {service_url}")
            try:
                response = requests.post(service_url, json=data)
                if response.status_code == 200:
                    logging.debug(f"Successfully triggered sync on {service_url}")
                else:
                    logging.debug(f"Failed to trigger sync on {service_url}, status code: {response.status_code}")
            except requests.exceptions.RequestException as e:
                logging.error(f"Error triggering sync on {service_url}: {e}")

    def validate_received_block(self, block):
        logging.debug(f"Validating received block with index {block['index']}")
        if not self.validate_block_structure(block):
            logging.error("Block structure validation failed.")
            return False

        if not self.validate_block(block):
            logging.error("Block content validation failed.")
            return False

        if block['index'] != len(self.chain) + 1:
            logging.error(f"Block index {block['index']} does not follow the current chain length.")
            return False

        return True

    def validate_block_structure(self, block):
        logging.debug(f"Checking block structure for block with index {block['index']}")
        required_fields = [
            'index', 'previous_hash', 'timestamp', 'transactions',
            'merkle_root', 'stake_threshold', 'hash', 'miner', 'miner_share',
            'validator', 'validator_share', 'fee'
        ]

        missing_fields = [field for field in required_fields if field not in block]
        if missing_fields:
            logging.error(f"Block missing required fields: {missing_fields}")
            return False

        field_type_issues = False
        for field in required_fields:
            if field in block:
                expected_type = (int if field in ['index', 'timestamp'] else
                                 str if field in ['previous_hash', 'hash', 'miner', 'validator', 'merkle_root'] else
                                 list if field == 'transactions' else
                                 (int, float) if field in ['stake_threshold', 'fee', 'miner_share', 'validator_share'] else
                                 None)
                actual_type = type(block[field])
                if not isinstance(block[field], expected_type):
                    logging.error(f"Field '{field}' type mismatch: expected {expected_type}, got {actual_type}")
                    field_type_issues = True
            else:
                logging.error(f"Field '{field}' is missing from the block.")
                field_type_issues = True

        if field_type_issues:
            logging.error("One or more block field types are incorrect.")
            return False

        logging.debug("Block structure validated successfully.")
        return True
    
    def reach_consensus(self, proposed_block):
        if len(self.validators) == 1:
            logging.info("Automatically reaching consensus with single validator")
            return True

        consensus_reached = self.vote_on_local_block(proposed_block)

        if consensus_reached:
            logging.info("Consensus reached")
            return True
        else:
            logging.info("Consensus not reached")
            return False

    def vote_on_local_block(self, block):
        valid_votes = []
        services = self.discover_services("node")

        if len(services) == 1 and services[0] == self.node.url:
            logging.info("Only one validator in the network, bypassing the voting process.")
            valid_votes.append(self.node.url)

        filtered_services = [s for s in services if f"http://{s}:3400" != self.node.url]
        for service in filtered_services:
            service_url = f"http://{service}:3400/vote_on_block"

            try:
                response = requests.post(service_url, json=block)
                if response.status_code == 200 and response.json().get('message') == 'Block is valid':
                    valid_votes.append(service)
                    logging.info(f"Validator {service} approved the block.")
                else:
                    logging.info(f"Validator {service} did not approve the block.")
            except requests.exceptions.RequestException as e:
                logging.error(f"Error voting on block with {service}: {e}")

        return valid_votes

    def validate_block(self, block):
        logging.debug(f"Validating block with index {block['index']}")
        if block['validator'] not in self.validators:
            logging.error("Block validator is not recognized.")
            return False

        if not self.proof_of_stake(block):
            return False

        unique_addresses = set()
        double_spent_addresses = set()
        for transaction in block['transactions']:
            sender_address = transaction.get('address')
            if sender_address in unique_addresses:
                double_spent_addresses.add(sender_address)
            unique_addresses.add(sender_address)

        if double_spent_addresses:
            logging.error(f"Double spending detected for addresses: {', '.join(double_spent_addresses)}")
            raise DoubleSpendingError("Double spending detected for addresses: " + ', '.join(double_spent_addresses))

        block_string = str(block['index']) + str(block['timestamp']) + str(block['previous_hash']) + str(
            block['transactions']) + str(block['fee']) + str(block['validator']) + str(block['validator_share'])

        generated_hash = hashlib.sha256(block_string.encode()).hexdigest()
        if block['hash'] != generated_hash:
            logging.error("Block hash does not match the generated hash.")
            return False

        if not self.reach_consensus(block):
            logging.error("Failed to reach consensus.")
            return False

        logging.info(f"Block with index {block['index']} passed all validations.")
        return True

    def validate_foreign_block(self, block):
        logging.debug(f"Validating block with index {block['index']}")
        if block['validator'] not in self.validators:
            logging.error("Block validator is not recognized.")
            return False

        if not self.proof_of_stake(block):
            return False

        unique_addresses = set()
        double_spent_addresses = set()
        for transaction in block['transactions']:
            sender_address = transaction.get('address')
            if sender_address in unique_addresses:
                double_spent_addresses.add(sender_address)
            unique_addresses.add(sender_address)

        if double_spent_addresses:
            logging.error(f"Double spending detected for addresses: {', '.join(double_spent_addresses)}")
            raise DoubleSpendingError("Double spending detected for addresses: " + ', '.join(double_spent_addresses))

        block_string = str(block['index']) + str(block['timestamp']) + str(block['previous_hash']) + str(
            block['transactions']) + str(block['fee']) + str(block['validator']) + str(block['validator_share'])

        generated_hash = hashlib.sha256(block_string.encode()).hexdigest()
        if block['hash'] != generated_hash:
            logging.error("Block hash does not match the generated hash.")
            return False

        return True

    def generate_block_hash(self, block):
        transactions_string = json.dumps(block['transactions'], sort_keys=True)

        block_contents = (
            str(block['index']) +
            str(block['timestamp']) +
            str(block['previous_hash']) +
            transactions_string +
            str(block['fee']) +
            str(block['miner']) +
            str(block['miner_share']) +
            str(block['validator']) +
            str(block['validator_share'])
        )

        block_hash = hashlib.sha256(block_contents.encode()).hexdigest()
        return block_hash
    
    def proof_of_stake(self, block):
        logging.info("Starting proof of stake validation.")

        total_stake_weight = sum(node['stake_weight'] if isinstance(node, dict) else node.stake_weight for node in self.verifier.nodes)
        random_number = random.uniform(0, total_stake_weight)
        cumulative_stake_weight = 0

        logging.info(f"Total stake weight: {total_stake_weight}, Random number for validator selection: {random_number}")

        for current_node in self.verifier.nodes:
            node_stake_weight = current_node['stake_weight'] if isinstance(current_node, dict) else current_node.stake_weight
            cumulative_stake_weight += node_stake_weight

            if cumulative_stake_weight > random_number:
                selected_validator_address = current_node['address'] if isinstance(current_node, dict) else current_node.address
                logging.info(f"Selected validator address: {selected_validator_address}, Stake weight: {node_stake_weight}")

                if selected_validator_address == block['validator']:
                    logging.info(f"Validator {selected_validator_address} matches the block's validator.")
                    if node_stake_weight >= block['stake_threshold']:
                        logging.info(f"Validator {selected_validator_address} meets the stake threshold.")
                        return node_stake_weight
                    else:
                        logging.error(f"Validator {selected_validator_address} does not meet the stake threshold.")
                        return 0

        logging.error("No suitable validator found or the selected validator does not meet the stake threshold.")
        return 0

    def add_coin_transaction(self, address: str, amount: int, converted_amount: Union[int, float], fee: Union[int, float], hash: str, pub_key: str, signature: str, sub_type: str, type: str) -> Union[bool, str]:

        cleaned_transaction = {
            'address': address,
            'amount': amount,
            'converted_amount': converted_amount,
            'fee': fee,
            'hash': hash,
            'pub_key': pub_key,
            'signature': signature,
            'sub_type': sub_type,
            'type': type
        }

        if cleaned_transaction['signature']:
            return cleaned_transaction
        
    def select_miner(self) -> dict:
        accounts = staking_manager.staking_agreements

        # Calculate the number of withdrawals for each account
        for account in accounts:
            account['withdrawals'] = sum(1 for block in self.chain for transaction in block['transactions']
                             if 'address' in transaction and transaction.get('address') == account['address'])

            # Select the miner based on weighted selection
            miner = self.weighted_selection(accounts)

            return miner

    def weighted_selection(self, accounts: List[dict]) -> dict:
        # Calculate weights based on the number of withdrawals for each account
        weights = [1 / (acc['withdrawals'] + 1) for acc in accounts]
        total_weight = sum(weights)

        # Normalize the weights to ensure their sum is 1
        normalized_weights = [weight / total_weight for weight in weights]

        # Select an account using the normalized weights
        chosen_account = random.choices(
            accounts, weights=normalized_weights, k=1)[0]
        return chosen_account

    def calculate_fee_distribution(self, total_fee):
        fee_distribution = {}

        validator_percentage = 0.45
        miner_percentage = 0.315
        treasury_percentage = 0.235  # Updated to include the burn percentage

        fee_distribution['validator_share'] = total_fee * validator_percentage
        fee_distribution['miner_share'] = total_fee * miner_percentage
        fee_distribution['treasury_share'] = total_fee * treasury_percentage

        return fee_distribution
    
    def select_validator(self, block):
        selected_validator = self.verifier.select_validator(block)
        return selected_validator if selected_validator else None

    def validate_selected_validator(self, selected_validator, block):
        if selected_validator.malicious or selected_validator not in verifier.verified_nodes:
            return False

        if selected_validator.address == block['validator'] and \
                selected_validator.stake_weight >= block['stake_threshold']:
            return True

        return False

    def add_malicious_validator(self, validator_address):
        for node in self.nodes:
            if node.address == validator_address:
                node.malicious = True
                break

    def create_new_block(self, transactions):
        latest_block = self.chain[-1]
        block_index = latest_block['index'] + 1
        timestamp = int(datetime.now(timezone.utc).timestamp())
        previous_hash = latest_block['hash']
        stake_threshold = node.stake_weight

        processed_transactions, total_fee = self.process_transactions(transactions)

        block_fee = coin.mint_for_block_fee(total_fee)

        fee_distribution = self.calculate_fee_distribution(block_fee)

        miner = self.select_miner()
        miner_address = miner['address']

        block = {
            'index': block_index,
            'timestamp': timestamp,
            'previous_hash': previous_hash,
            'transactions': processed_transactions,
            'stake_threshold': stake_threshold,
            'fee': block_fee
        }

        validator_node = self.select_validator(block)

        if not validator_node:
            logging.warning("No validator selected, assigning default validator.")
            validator_address = self.node.address
        else:
            validator_address = validator_node.address if isinstance(validator_node, Node) else validator_node['address']

        for transaction in transactions:
            merkle_tree.add_transaction(str(transaction))

        merkle_tree.create_tree()
        merkle_root = merkle_tree.get_merkle_root()
        
        coin.credit(validator_address, fee_distribution['validator_share'])
        
        coin.credit(miner_address, fee_distribution['miner_share'])

        coin.credit(coin.treasury_address, fee_distribution['treasury_share'])

        new_block = {
            'index': block_index,
            'timestamp': timestamp,
            'previous_hash': previous_hash,
            'transactions': processed_transactions,
            'merkle_root': merkle_root,
            'stake_threshold': stake_threshold,
            'fee': block_fee,
            'miner': miner_address,
            'miner_share': fee_distribution['miner_share'],
            'validator': validator_address,
            'validator_share': fee_distribution['validator_share'],
            'treasury_share': fee_distribution['treasury_share']
        }

        logging.info(f"constructed block: {new_block}")

        block_string = str(new_block['index']) + str(new_block['timestamp']) + str(new_block['previous_hash']) + str(
            new_block['transactions']) + str(new_block['fee']) + str(new_block['validator']) + str(new_block['validator_share'])

        block_hash = hashlib.sha256(block_string.encode()).hexdigest()

        new_block['hash'] = block_hash

        if self.add_block(new_block):
            self.transactions.cleaned_transactions = []
            logging.info(f"Successfully mined new block: {new_block}")
            return new_block
        else:
            logging.debug(f"Issue mining block: {new_block}")

    def process_transactions(self, transactions):
        processed_transactions = []
        total_fee = 0.0

        for transaction in transactions:
            transaction_type = transaction.get('sub_type')

            if transaction_type == 'r':
                processed_transaction = self.handle_staking_transaction(transaction)
            elif transaction_type == 'o':
                processed_transaction = self.handle_unstaking_transaction(transaction)
            elif transaction_type == 'k':
                processed_transaction = self.handle_transfer_transaction(transaction)
            elif transaction_type == 'w':
                processed_transaction = self.handle_pomc_whitelist_transaction(transaction)
            elif transaction_type in ['h', 'x', 'm', 'pr']:
                processed_transaction = self.handle_fee_payment_transaction(transaction)
            else:
                processed_transaction = self.handle_default_transaction(transaction)

            if processed_transaction:
                processed_transactions.append(processed_transaction)
                total_fee += processed_transaction.get('fee', 0.0)

        return processed_transactions, total_fee

    def handle_staking_transaction(self, transaction):
        try:
            fee_calculator = DynamicFeeCalculator()
            sender_address = transaction['address']
            staking_amount = transaction['amount']
            min_term = transaction['min_term']
            pub_key = transaction['pub_key']
            signature = transaction.get('signature')

            transaction_data = {
                'address': sender_address,
                'amount': staking_amount,
                'min_term': min_term,
                'pub_key': pub_key,
                'type': transaction['type']
            }

            transaction_fee, transaction_hash = dynamic_fee_calculator.get_base_dynamic_fee(transaction_data, transaction['type'])

            if not all([sender_address, staking_amount, min_term, pub_key, signature]):
                logging.error("Missing fields in staking transaction")
                return None

            sender_balance_info = self.wallet.get_account_balance(sender_address)
            if not sender_balance_info or sender_balance_info['balance_float'] < staking_amount + transaction_fee:
                logging.error("Insufficient balance for staking")
                return None

            transaction_for_verification = {
                'address': sender_address,
                'amount': staking_amount,
                'fee': transaction_fee,
                'hash': transaction_hash,
                'min_term': min_term,
                'pub_key': pub_key,
                'type': transaction['type']
            }

            if not crypto_utils.verify_transaction(transaction['pub_key'], transaction_for_verification, transaction['signature']):
                logging.error("Invalid signature in staking transaction")
                return None

            self.wallet.stake_coins(sender_address, staking_amount, min_term)

            processed_transaction = {
                'address': sender_address,
                'amount': staking_amount,
                'fee': transaction_fee,
                'hash': transaction_hash,
                'min_term': min_term,
                'stake_threshold': 3,
                'type': transaction['type'],
                'when': str(datetime.now(timezone.utc))
            }

            logging.info(f"Processed staking transaction for {sender_address}")
            return processed_transaction

        except Exception as e:
            logging.error(f"Error processing staking transaction: {e}")
            return None

    def handle_unstaking_transaction(self, transaction):
        try:
            fee_calculator = DynamicFeeCalculator()
            sender_address = transaction['address']
            contract_id = transaction['contract_id']
            pub_key = transaction['pub_key']
            signature = transaction.get('signature')

            transaction_data = {
                'address': sender_address,
                'contract_id': contract_id,
                'pub_key': pub_key,
                'type': transaction['type']
            }

            transaction_fee, transaction_hash = dynamic_fee_calculator.get_base_dynamic_fee(transaction_data, transaction['type'])

            if not all([sender_address, contract_id, pub_key, signature]):
                logging.error("Missing fields in unstaking transaction")
                return None

            sender_balance_info = self.wallet.get_account_balance(sender_address)
            if not sender_balance_info or sender_balance_info['balance_float'] < transaction_fee:
                logging.error("Insufficient balance for unstaking")
                return None

            transaction_for_verification = {
                'address': sender_address,
                'contract_id': contract_id,
                'fee': transaction_fee,
                'hash': transaction_hash,
                'pub_key': pub_key,
                'type': transaction['type']
            }

            if not crypto_utils.verify_transaction(transaction['pub_key'], transaction_for_verification, transaction['signature']):
                logging.error("Invalid signature in unstaking transaction")
                return None

            self.wallet.unstake_coins(sender_address, contract_id)

            processed_transaction = {
                'address': sender_address,
                'contract_id': contract_id,
                'fee': transaction_fee,
                'hash': transaction_hash,
                'stake_threshold': 2,
                'type': transaction['type'],
                'when': str(datetime.now(timezone.utc))
            }

            logging.info(f"Processed unstaking transaction for {sender_address}")
            return processed_transaction

        except Exception as e:
            logging.error(f"Error processing unstaking transaction: {e}")
            return None

    def handle_transfer_transaction(self, transaction):
        try:
            fee_calculator = DynamicFeeCalculator()
            sender_address = transaction['sender']
            recipient_address = transaction['recipient']
            transfer_amount = transaction['amount']
            pub_key = transaction['pub_key']
            signature = transaction.get('signature')

            transaction_data = {
                'sender': sender_address,
                'recipient': recipient_address,
                'amount': transfer_amount,
                'pub_key': pub_key,
                'type': transaction['type']
            }

            transaction_fee, transaction_hash = dynamic_fee_calculator.get_base_dynamic_fee(transaction_data, transaction['type'])

            if not all([sender_address, recipient_address, transfer_amount, pub_key, signature]):
                logging.error("Missing fields in transfer transaction")
                return None

            sender_balance_info = self.wallet.get_account_balance(sender_address)
            if not sender_balance_info or sender_balance_info['balance_float'] < transfer_amount + transaction_fee:
                logging.error("Insufficient balance for transfer")
                return None

            transaction_for_verification = {
                'sender': sender_address,
                'recipient': recipient_address,
                'amount': transfer_amount,
                'fee': transaction_fee,
                'hash': transaction_hash,
                'pub_key': pub_key,
                'type': transaction['type']
            }

            if not crypto_utils.verify_transaction(transaction['pub_key'], transaction_for_verification, transaction['signature']):
                logging.error("Invalid signature in transfer transaction")
                return None

            self.wallet.transfer(sender_address, recipient_address, transfer_amount)

            processed_transaction = {
                'sender': sender_address,
                'recipient': recipient_address,
                'amount': transfer_amount,
                'fee': transaction_fee,
                'hash': transaction_hash,
                'stake_threshold': 2,
                'type': transaction['type'],
                'when': str(datetime.now(timezone.utc))
            }

            logging.info(f"Processed transfer transaction from {sender_address} to {recipient_address}")
            return processed_transaction

        except Exception as e:
            logging.error(f"Error processing transfer transaction: {e}")
            return None
    
    def handle_pomc_whitelist_transaction(self, transaction):
        try:
            
            sender_address = transaction['sender']
            pub_key = transaction['pub_key']
            signature = transaction.get('signature')

            processed_transaction = {
                'fee': transaction['fee'],
                'hash': transaction['hash'],
                'sender': transaction['sender'],
                'sub_type': transaction['sub_type'],
                'stake_threshold': 2,
                'type': transaction['type'],
                'when': transaction['when']
            }

            logging.info(f"Processed transfer transaction from {sender_address} to join pOMC whitelist")
            return processed_transaction

        except Exception as e:
            logging.error(f"Error processing transfer transaction: {e}")
            return None

    def handle_fee_payment_transaction(self, transaction):
        try:
            fee_calculator = DynamicFeeCalculator()
            payer_address = transaction['from']
            fee_amount = transaction['fee']
            pub_key = transaction['pub_key']
            signature = transaction.get('signature')

            transaction_data = {
                'from': payer_address,
                'fee': fee_amount,
                'pub_key': pub_key,
                'type': transaction['type']
            }

            calculated_fee, transaction_hash = dynamic_fee_calculator.get_base_dynamic_fee(transaction_data, transaction['type'])

            if not all([payer_address, fee_amount, pub_key, signature]):
                logging.error("Missing fields in fee payment transaction")
                return None

            payer_balance_info = self.wallet.get_account_balance(payer_address)
            if not payer_balance_info or payer_balance_info['balance_float'] < fee_amount + calculated_fee:
                logging.error("Insufficient balance for fee payment")
                return None

            transaction_for_verification = {
                'from': payer_address,
                'fee': calculated_fee,
                'hash': transaction_hash,
                'pub_key': pub_key,
                'type': transaction['type']
            }

            if not crypto_utils.verify_transaction(transaction['pub_key'], transaction_for_verification, transaction['signature']):
                logging.error("Invalid signature in fee payment transaction")
                return None

            self.wallet.pay_fee(payer_address, fee_amount)

            processed_transaction = {
                'from': payer_address,
                'fee': calculated_fee,
                'hash': transaction_hash,
                'stake_threshold': 2,
                'type': transaction['type'],
                'when': str(datetime.now(timezone.utc))
            }

            logging.info(f"Processed fee payment transaction from {payer_address}")
            return processed_transaction

        except Exception as e:
            logging.error(f"Error processing fee payment transaction A1: {e}")
            return None

    def handle_default_transaction(self, transaction):
        try:
            fee_calculator = DynamicFeeCalculator()
            payer_address = transaction['address']

            transaction_data = {
                'from': payer_address,
                'type': 'e'
            }

            calculated_fee, transaction_hash = dynamic_fee_calculator.get_base_dynamic_fee(transaction_data, transaction['type'])

            processed_transaction = {
                'from': payer_address,
                'fee': 0.0,
                'hash': transaction_hash,
                'stake_threshold': 1,
                'type': 'e',
                'when': str(datetime.now(timezone.utc))
            }

            logging.info(f"Processed fee payment transaction from {payer_address}")
            return processed_transaction

        except Exception as e:
            logging.error(f"Error processing fee payment transaction A2: {e}")
            return None

    def clean_and_verify_transactions(self):
        new_transactions = self.transactions.batch_pending_transactions()
        cleaned_transactions = []

        for transaction in new_transactions:
            try:
                if transaction['type'] == 'c' and transaction['sub_type'] == 'c':
                    self.process_account_creation_transaction(transaction)
                elif transaction['type'] == 'c' and transaction['sub_type'] == 'w':
                    self.process_add_account_to_whitelist_transaction(transaction)
                elif transaction['type'] == 'o':
                    self.process_non_f_transaction(transaction)
                elif transaction['type'] == 'e':
                    self.process_f_transaction(transaction)
            except Exception as e:
                logging.error(f"Error processing transaction {transaction['type']}: {e}")

        return cleaned_transactions
    
    def process_account_creation_transaction(self, transaction):
        # Verify that the transaction is of the correct type
        if transaction['type'] != 'c':
            logging.error(f"Invalid transaction type for account creation: {transaction['type']}")
            return

        try:
            # Extract necessary fields from the transaction
            address = transaction['address']
            balance = transaction['balance']
            type = transaction['type']
            timestamp = ['timestamp']
            withdrawals = transaction['withdrawals']

            # Validate the transaction data
            if not all([address, type]):
                logging.error("Incomplete account creation transaction data")
                return

            # Check if the address already exists in the blockchain wallet
            # if any(acc['address'] == address for acc in account_manager.accounts):
            #     logging.info(f"Account already exists: {address}")
            #     return

            # # Create and append the new account to the wallet
            # new_account = {
            #     'address': address,
            #     'balance': balance,
            #     'withdrawals': withdrawals
            # }
            # account_manager.accounts.append(new_account)

            # Create a cleaned version of the transaction for the blockchain
            cleaned_transaction = {
                'address': address,
                'hash': transaction.get('hash'),
                'pub_key': transaction['pub_key'],
                'signature': transaction['signature'],
                'sub_type': 'c',
                'type': transaction['type'],
                'withdrawals': withdrawals
            }

            # Append the cleaned transaction to the list of processed transactions
            self.transactions.cleaned_transactions.append(cleaned_transaction)
            logging.info(f"Processed account creation transaction for {address}")

        except Exception as e:
            logging.error(f"Error processing account creation transaction A2: {e}")
            
    def process_add_account_to_whitelist_transaction(self, transaction):
        # Verify that the transaction is of the correct type
        if transaction['type'] != 'c':
            logging.error(f"Invalid transaction type to add account to whitelist: {transaction['type']}")
            return

        try:
            result = {
                'fee': transaction['fee'],
                'hash': transaction['hash'],
                'pub_key': transaction['pub_key'],
                'sender': transaction['sender'],
                'signature': transaction['signature'],
                'sub_type': transaction['sub_type'],
                'type': transaction['type'],
                'when': transaction['when']
            }
            # Extract necessary fields from the transaction
            address = transaction['sender']
            hash = transaction['hash']
            type = transaction['type']

            # Validate the transaction data
            if not all([address, hash, type]):
                logging.error("Incomplete account creation transaction data")
                return

            # Create a cleaned version of the transaction for the blockchain
            cleaned_transaction = {
                'fee': transaction['fee'],
                'hash': transaction['hash'],
                'pub_key': transaction['pub_key'],
                'sender': transaction['sender'],
                'signature': transaction['signature'],
                'sub_type': transaction['sub_type'],
                'type': transaction['type'],
                'when': transaction['when']
            }

            # Append the cleaned transaction to the list of processed transactions
            self.transactions.cleaned_transactions.append(cleaned_transaction)
            logging.info(f"Processed join whitelist transaction for {address}")

        except Exception as e:
            logging.error(f"Error processing join whiteist transaction A2: {e}")

    def process_f_transaction(self, transaction):
        try:
            transaction_type = transaction.get('type')
            sender_address = transaction.get('address')
            transaction_fee = transaction.get('fee', 0.0)

            if not sender_address or transaction_fee is None:
                logging.error("Invalid transaction format.")
                return None

            cleaned_transaction = None

            if transaction_type == 'e':
                sub_tx_type = transaction.get('sub_type')

                if sub_tx_type == 'p':
                    amount = transaction.get('amount')
                    recipient_address = transaction.get('recipient')

                    if crypto_utils.verify_transaction(sender_address, recipient_address, amount):
                        self.wallet.transfer(sender_address, recipient_address, amount)

                elif sub_tx_type == 'r':
                    amount = transaction.get('amount')
                    min_term = transaction.get('min_term')

                    self.wallet.stake_coins(sender_address, amount, min_term)

                elif sub_tx_type == 'z':
                    contract_id = transaction.get('contract_id')

                    self.wallet.unstake_coins(sender_address, contract_id)

            if cleaned_transaction:
                self.transactions.cleaned_transactions.append(cleaned_transaction)
                logging.info(f"Processed transaction of type {transaction_type} for {sender_address}")
                return cleaned_transaction
            else:
                logging.warning(f"Unhandled or failed transaction type/subtype: {transaction_type}/{sub_tx_type}")
                return None

        except Exception as e:
            logging.error(f"Error processing account creation transaction A2: {e}")

    def process_non_f_transaction(self, transaction):
        try:
            transaction_type = transaction.get('type')
            sender_address = transaction.get('address')
            transaction_fee = transaction.get('fee', 0.0)

            if not sender_address or transaction_fee is None:
                logging.error("Invalid transaction format.")
                return None

            cleaned_transaction = None

            if transaction_type == 'o':
                sub_tx_type = transaction.get('sub_type')

                if sub_tx_type == 's':
                    self.handle_post_transaction(transaction)

                elif sub_tx_type == 'j':
                    refined_transaction = self.handle_add_profile_transaction(transaction)
                    if refined_transaction:
                        cleaned_transaction = {
                            'address': transaction['address'],
                            'avi': transaction['avi'],
                            'clubs': transaction['clubs'],
                            'fee': transaction['fee'],
                            'handle': transaction['handle'],
                            'hash': transaction['hash'],
                            'intro': transaction['intro'],
                            'joined': transaction['joined'],
                            'name': transaction['name'],
                            'profile_id': transaction['profile_id'],
                            'profile_type': transaction['profile_type'],
                            'pt': transaction['pt'],
                            'pt_id': transaction['pt_id'],
                            'pub_key': transaction['pub_key'],
                            'signature': transaction['signature'],
                            'sub_type': transaction['sub_type'],
                            'tags': transaction['tags'],
                            'type': transaction['type'],
                            'version': transaction['version']
                        }

            if cleaned_transaction:
                transactions.cleaned_transactions.append(cleaned_transaction)
                logging.info(f"Processed transaction of type {transaction_type} for {sender_address}")
                return cleaned_transaction
            else:
                logging.warning(f"Unhandled or failed transaction type/subtype: {transaction_type}/{sub_tx_type}")
                return None

        except Exception as e:
            logging.error(f"Error processing transaction: {e}")
            return None

    def start_mining(self):
        self.create_new_block(self.transactions.cleaned_transactions)

    def check_pending_transactions(self):
        self.clean_and_verify_transactions()
        self.start_mining()

    def get_latest_block(self):
        return self.chain[-1]

    def main_loop(self):
        while True:
            self.start_mining()
            self.consume_blocks()

    def consume_blocks(self):
        for message in self.consumer:
            block_data = message.value.decode('utf-8')
            block = json.loads(block_data)
            self.receive_block(block)
    @staticmethod
    def list_endpoints(app: Flask):
        """
        List all the endpoints in a Flask application.

        :param app: Flask application instance
        :return: List of endpoint rules
        """
        endpoints = []
        for rule in app.url_map.iter_rules():
            endpoints.append(rule.rule)
        return endpoints

    @staticmethod
    def register_endpoints(app: Flask, registry_url: str, node_address: str):
        """
        Register all endpoints with the central registry.

        :param app: Flask application instance
        :param registry_url: URL of the registry service
        :param node_address: Address of the current node
        :return: None
        """
        endpoints = EndpointManager.list_endpoints(app)
        registration_data = {
            "node_address": node_address,
            "endpoints": endpoints
        }
        response = requests.post(f"{registry_url}/register", json=registration_data)
        if response.status_code == 200:
            print("Successfully registered endpoints")
        else:
            print("Failed to register endpoints")


    def __init__(self, coin, wallet, transactions, verifier):
        self.coin = coin
        self.wallet = wallet
        self.transactions = transactions
        self.verifier = verifier

        self.chain = []
        self.block_hashes = set()
        self.lock = threading.Lock()
        logging.basicConfig(level=logging.DEBUG)
        
        self.validators = []
        
        mining_thread = threading.Thread(target=self.mine_new_block_periodically)
        mining_thread.daemon = True
        mining_thread.start()

    @staticmethod
    def serialize_and_create_single_hash(cls):
        if not isinstance(cls, type):
            raise TypeError(f"Expected class type, got {type(cls)}")

        try:
            class_dict = {
                'attributes': {key: value for key, value in cls.__dict__.items() if not callable(value) and not key.startswith('__')},
                'methods': {
                    key: (value.__func__.__code__.co_code if isinstance(value, staticmethod) else value.__code__.co_code)
                    for key, value in cls.__dict__.items() if callable(value)
                }
            }
            class_serialized = json.dumps(class_dict, sort_keys=True, default=str)
            logging.debug(f"Serialized class {cls.__name__}: {class_serialized}")
            class_hash = hashlib.sha256(class_serialized.encode()).hexdigest()
            return class_hash
        except Exception as e:
            logging.error(f"Error serializing class {cls.__name__}: {e}")
            raise

    @staticmethod
    def verify_class_hashes():
        """
        This function retrieves the stored hashes of classes from the public API and compares them
        with the hashes of the current local classes to ensure integrity.
        """
        try:
            response = requests.get(HASH_API_URL)
            if response.status_code != 200:
                raise ValueError("Failed to fetch class hashes from public API.")

            stored_hashes = response.json()
        except Exception as e:
            logging.error(f"Error fetching class hashes from public API: {e}")
            raise

        classes_to_verify = {
            'coin': OMC,
            'quantum_utils': QuantumUtils,
            'transactions': Transactions,
            'permission_manager': PermissionMngr,
            'precursor_coin': pOMC,
            'verifier': Verifier,
            'crypto_utils': CUtils,
            'fee_calculator': DynamicFeeCalculator,
            'ledger': Ledger,
            'treasury': OMCTreasury,
            'endpoint_manager': EndpointManager
        }

        for class_name, cls in classes_to_verify.items():
            stored_hash = stored_hashes.get(class_name)
            if not stored_hash:
                logging.error(f"Stored hash for class {class_name} not found in the public API response.")
                raise ValueError(f"Stored hash for class {class_name} not found.")

            local_hash = Ledger.serialize_and_create_single_hash(cls)
            if stored_hash != local_hash:
                logging.error(f"Hash mismatch for class {class_name}. Possible tampering detected.")
                raise ValueError(f"Hash mismatch for class {class_name}. Possible tampering detected.")

        logging.info("All class hashes verified successfully. No tampering detected.")
        return True

    def initialize_node(self):
        service_prefix = "node"
        services = self.discover_services(service_prefix)
        if services:
            self.ping_services(services, "check_nodes", node.url)

        node.steward = os.getenv('STEWARD_ADDRESS')
        if not node.steward:
            raise ValueError("Steward address not provided. Set the STEWARD_ADDRESS environment variable.")

        self.update_node_state(node)
        self.check_chain_length_and_sync(services)
        self.update_validators()
        self.broadcast_node_data(node)

    def discover_services(self, prefix):
        discovered_services = []
        max_range = 10

        for i in range(1, max_range):
            service_name = f"{prefix}{i}.omne"
            try:
                service_address = socket.gethostbyname(service_name)

                if service_address != node.url:
                    discovered_services.append(service_name)
                    logging.debug(f"Discovered service: {service_name}")

            except socket.gaierror:
                continue

        if not discovered_services:
            logging.warning("No services were discovered.")

        return discovered_services

    def ping_services(self, services, endpoint, current_node_url):
        headers = {"Authorization": f"Bearer {AUTH_TOKEN}"}

        for service in services:
            service_base_url = f"http://{service}:3400"
            service_url = f"{service_base_url}/{endpoint}"

            if service_base_url == current_node_url:
                logging.debug(f"Skipping self ping: {service_base_url}")
                continue

            logging.debug(f"Attempting to ping {service_url}")
            try:
                response = requests.get(service_url, headers=headers)
                if response.status_code == 200:
                    logging.debug(f"Successfully pinged {service_url}")
                    received_nodes = response.json().get('nodes', [])
                    for received_node in received_nodes:
                        if not any(node['address'] == received_node['address'] for node in self.verifier.nodes):
                            verifier.nodes.append(received_node)
                            verifier.nodes.append(received_node)
                            self.validators.append(received_node['address'])
                            logging.debug(f"Added new node: {received_node['address']}")
                else:
                    logging.debug(f"Failed to ping {service_url}, status code: {response.status_code}")

            except requests.exceptions.RequestException as e:
                logging.error(f"Error pinging {service_url}: {e}")

    def post_data_to_services(self, services, endpoint, data):
        headers = {"Authorization": f"Bearer {AUTH_TOKEN}"}

        for service in services:
            service_base_url = f"http://{service}:3400"
            service_url = f"{service_base_url}/{endpoint}"

            if service_base_url == node.url:
                logging.debug(f"Skipping self post: {service_url}")
                continue

            logging.debug(f"Attempting to post data to {service_url}")
            try:
                response = requests.post(service_url, json=data, headers=headers)
                if response.status_code == 200:
                    logging.debug(f"Successfully posted data to {service_url}")
                else:
                    logging.debug(f"Failed to post data to {service_url}, status code: {response.status_code}")

            except requests.exceptions.RequestException as e:
                logging.error(f"Error posting data to {service_url}: {e}")

    def broadcast_self_info(self):
        if not node or not node.address or not node.url:
            logging.error("Node information is incomplete or incorrect. Cannot broadcast.")
            return

        node_info = node.to_dict()
        logging.info(f"Broadcasting self node information: {node_info}")

        services = self.discover_services("node")
        if not services:
            logging.warning("No other services discovered for broadcasting. Broadcast aborted.")
            return

        services = [service for service in services if service != node.url]
        if not services:
            logging.warning("No external services discovered for broadcasting. Broadcast aborted.")
            return

        self.post_data_to_services(services, "receive_node_info", node_info)
        logging.info("Successfully broadcasted self node information to other services.")

    def update_validators(self):
        services = self.discover_services("node")
        for service in services:
            service_base_url = f"http://{service}:3400"
            service_url = f"{service_base_url}/node_info"

            if service_base_url == node.url:
                continue

            try:
                response = requests.get(service_url)
                if response.status_code == 200:
                    node_data = response.json()
                    if node_data['address'] not in self.validators:
                        self.validators.append(node_data['address'])
            except requests.exceptions.RequestException as e:
                logging.error(f"Failed to retrieve node information from {service}: {e}")

    def sync_with_other_nodes(self, services):
        my_chain_length = len(self.chain)
        synchronized_chain = None
        authoritative_node_url = None

        for service in services:
            service_base_url = f"http://{service}:3400"
            service_url = f"{service_base_url}/get_chain"

            if service_base_url == node.url:
                continue

            try:
                response = requests.get(service_url)
                if response.status_code == 200:
                    other_chain = response.json()["chain"]
                    if len(other_chain) > my_chain_length:
                        my_chain_length = len(other_chain)
                        synchronized_chain = other_chain
                        authoritative_node_url = service_base_url
            except requests.exceptions.RequestException as e:
                logging.error(f"Error while trying to sync with {service_url}: {e}")

        if synchronized_chain:
            self.chain = synchronized_chain

        return authoritative_node_url, synchronized_chain

    def broadcast_node_data(self, node):
        headers = {"Authorization": f"Bearer {AUTH_TOKEN}"}
        node_data_complete = {
            'address': node.address,
            'public_key': node.public_key,
            'url': node.url,
            'stake_weight': node.stake_weight,
            'version': node.version,
            'steward': node.steward
        }

        services = self.discover_services("node")

        for service in services:
            service_base_url = f"http://{service}:3400"
            service_url = f"{service_base_url}/receive_node_data"

            if service_base_url == node.url:
                continue

            logging.debug(f"Broadcasting node data to {service_url}")
            try:
                response = requests.post(service_url, json=node_data_complete, headers=headers)
                if response.status_code == 201:
                    logging.debug(f"Successfully broadcasted new node data to {service_url}")
                elif response.status_code == 200:
                    logging.debug(f"Node data already exists on {service_url}")
                else:
                    logging.warning(f"Failed to broadcast node data to {service_url}, status code: {response.status_code}")
            except requests.exceptions.RequestException as e:
                logging.error(f"Error broadcasting node data to {service_url}: {e}")
                
    def update_accounts(self, address, balance):
        new_account = {
            'address': address,
            'balance': balance
        }

        service_prefix = "node"
        services = self.discover_services(service_prefix)

        filtered_services = [s for s in services if f"http://{s}:3400" != node.url]
        self.post_data_to_services(filtered_services, "propagate_account", new_account)

    def update_node_state(self, new_node):
        if new_node not in self.verifier.nodes:
            verifier.nodes.append(new_node)
            self.validators.append(new_node.address)
            logging.info(f"Node {new_node.address} added to local state.")

    def mine_new_block_periodically(self, interval=9):
        while True:
            self.check_for_mining_opportunity()
            time.sleep(interval * 60)

    def check_for_mining_opportunity(self):
        num_transactions = len(transactions.transactions)
        if num_transactions >= 1:
            self.check_pending_transactions()
        elif 4 <= num_transactions < 15 and self.is_time_to_mine():
            self.check_pending_transactions()

    def is_time_to_mine(self):
        latest_block = self.chain[-1]
        block_timestamp = datetime.strptime(latest_block['timestamp'], "%Y-%m-%d %H:%M:%S.%f%z")
        current_timestamp = datetime.now(timezone.utc)
        
        mining_interval = 9 * 60  # Fixed interval of 9 minutes
        return (current_timestamp - block_timestamp).total_seconds() >= mining_interval

    def create_new_wallet(self):
        mnemonic = crypto_utils.generate_mnemonic()
        account = self.wallet.account_manager.generate_account_from_mnemonic(mnemonic)
        
        # Add the new address with a balance of zero to the self.balance dictionary
        with coin.balance_lock:
            coin.balance[account['address']] = 0.0

        wallet_creation_transaction = {
            'address': account['address'],
            'balance': 0.0,
            'withdrawals': 0,
            'type': 'c'
        }

        cleaned_transaction = {
            'address': wallet_creation_transaction['address'],
            'balance': wallet_creation_transaction['balance'],
            'pub_key': account['pub_key'],
            'sub_type': 'c',
            'type': wallet_creation_transaction['type'],
            'withdrawals': wallet_creation_transaction['withdrawals']
        }

        initial_balance = 0.0

        account_dict = {
            'address': wallet_creation_transaction['address'],
            'balance': initial_balance,
        }

        sendable_transaction = {
            'mnemonic': mnemonic,
            'private_key': base64.b64encode(account['private_key']).decode('utf-8'),
            'pub_key': account['pub_key'],
            'address': account['address'],
        }

        return sendable_transaction

    def create_new_wallet_from_seed(self, seed):
        account = self.wallet.account_manager.generate_account_from_mnemonic(seed)

        wallet_creation_transaction = {
            'address': account['address'],
            'balance': 0.0,
            'withdrawals': 0,
            'type': 'c'
        }

        cleaned_transaction = {
            'address': wallet_creation_transaction['address'],
            'balance': wallet_creation_transaction['balance'],
            'pub_key': account['pub_key'],
            'type': wallet_creation_transaction['type'],
            'withdrawals': wallet_creation_transaction['withdrawals']
        }

        sendable_transaction = {
            'mnemonic': account['mnemonic'],
            'private_key': base64.b64encode(account['private_key']).decode('utf-8'),
            'pub_key': account['pub_key'],
            'address': account['address'],
        }

        private_key_bytes = base64.b64decode(sendable_transaction['private_key'])
        signature = crypto_utils.sign_transaction(private_key_bytes, wallet_creation_transaction)

        cleaned_transaction['signature'] = signature

        self.transactions.transactions.append(cleaned_transaction)
        self.update_accounts(wallet_creation_transaction['address'], wallet_creation_transaction['balance'])

        return sendable_transaction

    def get_chain_length(self):
        return len(self.chain) if hasattr(self, "blockchain") else 0

    def check_chain_length_and_sync(self, services):
        service_prefix = "node"
        services = self.discover_services(service_prefix)

        authoritative_node_url, synchronized_chain = self.sync_with_other_nodes(services)

        self.sync_account_list_data(authoritative_node_url, account_manager, coin, staked_coin)
        self.sync_treasury_data(authoritative_node_url)

        self.ping_services(services, "check_nodes", node.url)

        if synchronized_chain is not None:
            return {
                "chain": synchronized_chain,
                "message": "Chain synchronized successfully"
            }
        else:
            return {
                "chain": self.chain,
                "message": "Chain synchronization failed"
            }

    def sync_account_list_data(self, authoritative_node_url, account_manager, coin, staked_coin):
        if not authoritative_node_url:
            logging.error("No authoritative node URL provided for account list data synchronization.")
            return

        service_url = f"{authoritative_node_url}/retrieve_accounts"

        try:
            response = requests.get(service_url)
            if response.status_code == 200:
                data = response.json()

                main_accounts = data.get('data', [])
                for new_acc in main_accounts:
                    if 'address' in new_acc and 'balance' in new_acc:
                        account = next((acc for acc in account_manager.accounts if acc['address'] == new_acc['address']), None)
                        if account:
                            account['balance'] = new_acc['balance']
                            coin.balance[new_acc['address']] = new_acc['balance']
                            logging.info(f"Updated main account {new_acc['address']} for {coin.name}.")
                        else:
                            account_manager.accounts.append(new_acc)
                            coin.balance[new_acc['address']] = new_acc['balance']
                            logging.info(f"Added new main account {new_acc['address']} for {coin.name}.")

                precursor_accounts = data.get('precursor_accounts', [])
                for new_acc in precursor_accounts:
                    if 'address' in new_acc and 'balance' in new_acc:
                        account = next((acc for acc in account_manager.precursor_accounts if acc['address'] == new_acc['address']), None)
                        if account:
                            account['balance'] = new_acc['balance']
                            coin.balance[new_acc['address']] = new_acc['balance']
                            logging.info(f"Updated precursor account {new_acc['address']} for {coin.name}.")
                        else:
                            account_manager.precursor_accounts.append(new_acc)
                            coin.balance[new_acc['address']] = new_acc['balance']
                            logging.info(f"Added new precursor account {new_acc['address']} for {coin.name}.")

                staking_accounts = data.get('staking_accounts', [])
                for new_acc in staking_accounts:
                    if 'address' in new_acc and 'min_term' in new_acc:
                        account = next((acc for acc in staking_manager.staking_agreements if acc['address'] == new_acc['address']), None)
                        if account:
                            account['amount'] = new_acc['amount']
                            account['withdrawals'] = new_acc['withdrawals']
                            staked_coin.balance[new_acc['address']] = new_acc['amount']
                            logging.info(f"Updated staking account {new_acc['address']} for {staked_coin.name}.")
                        else:
                            staked_coin.accounts.append(new_acc)
                            staking_manager.staking_agreements.append(new_acc)
                            staked_coin.balance[new_acc['address']] = new_acc['amount']
                            logging.info(f"Added new staking account {new_acc['address']} for {staked_coin.name}.")

                self.validators = data.get('validators', [])
                if node.address not in self.validators:
                    self.validators.append(node.address)

                notification_data = {"message": "Data updated from authoritative node"}
                self.post_data_to_services(self.discover_services("node"), "notify_data_update", notification_data)

                logging.warning(f"Synchronized account list data with the authoritative node: {authoritative_node_url}")
            else:
                logging.error(f"Failed to retrieve account data from {service_url}, status code: {response.status_code}")
        except requests.RequestException as e:
            logging.error(f"Error retrieving account data from {service_url}: {e}")
    
    def sync_treasury_data(self, authoritative_node_url):
        if not authoritative_node_url:
            logging.error("No authoritative node URL provided for treasury data synchronization.")
            return False

        service_url = f"{authoritative_node_url}/retrieve_treasury_data"

        try:
            response = requests.get(service_url)
            if response.status_code == 200:
                response_data = response.json()
                if 'treasury_address' in response_data:
                    treasury.update_treasury_data(response_data['treasury_address'])
                    logging.warning("Synchronized treasury data with the authoritative node: %s", authoritative_node_url)
                    return True
                else:
                    logging.error(f"No treasury account data found in the response from {service_url}")
                    return False
            else:
                logging.error(f"Failed to retrieve treasury data from {service_url}, status code: {response.status_code}")
                return False
        except requests.RequestException as e:
            logging.error(f"Error retrieving treasury data from {service_url}: {e}")
            return False
    
    def add_account(self, account_data):
        address = account_data.get('address')
        balance_float = account_data.get('balance_float', 0)
        new_account = {}
        new_account['address'] = address
        new_account['balance'] = balance_float

        account_manager.accounts.append(new_account)
        coin.balance[address] = balance_float

        logging.info(f"Added/Updated account: {address} with balance {balance_float}")

    def add_staking_account(self, data):
        account_manager.staking_accounts.append(data)
        staked_coin.accounts.append(data)
        staking_manager.staking_accounts.append(data)

    def get_init_date(self):
        return coin.init_date

    def validate_chain(self, chain):
        previous_block = chain[0]
        for block in chain[1:]:
            if block['previous_hash'] != previous_block['hash']:
                return False

            block_data = block.copy()
            block_data.pop('hash')
            calculated_hash = self.calculate_block_hash(block_data)

            if block['hash'] != calculated_hash:
                return False

            if not self.validate_stake(block):
                return False

            previous_block = block

        return True

    def add_block(self, block):
        logging.info(f"Attempting to add block with index {block['index']}")
        if self.validate_received_block(block):
            with self.lock:
                if block['index'] == len(self.chain) + 1 and \
                   block['previous_hash'] == self.chain[-1]['hash']:
                    self.chain.append(block)
                    self.block_hashes.add(block['hash'])
                    logging.info(f"Block with index {block['index']} successfully added to the chain.")
                    self.broadcast_block(block)
                    return True
                else:
                    logging.warning(f"Block with index {block['index']} failed to match chain continuity.")
        else:
            logging.warning(f"Block with index {block['index']} failed validation.")
        return False
    
    def broadcast_block(self, new_block):
        block_data = json.dumps(new_block)

        service_prefix = "node"
        services = self.discover_services(service_prefix)

        self.post_data_to_services(services, "blocks/receive_block", block_data)
        
    def validate_foreign_tx(self, address, hash, pub_key, tx, signature):
        logging.debug(f"Validating tx from {address}")

        tx_hash = quantum_utils.quantum_resistant_hash(json.dumps(tx, sort_keys=True))
        if tx_hash != hash:
            logging.error(f"Hash mismatch for transaction with hash: {hash}")
            return None

        if not CUtils.verify_transaction(pub_key, tx, signature):
            logging.error(f"Invalid signature in foreign transaction with hash: {hash} from address: {address}")
            return None

        return True

    def vote_on_local_tx(self, address, hash, pub_key, tx, signature):
        valid_votes = []
        services = ledger.discover_services("node")

        if len(services) == 1 and services[0] == node.url:
            logging.info("Only one validator in the network, bypassing the voting process.")
            valid_votes.append(node.url)

        filtered_services = [s for s in services if f"http://{s}:3400" != node.url]
        for service in filtered_services:
            service_url = f"http://{service}:3400/vote_on_tx"

            try:
                data = {
                    'address': address,
                    'hash': hash,
                    'pub_key': pub_key,
                    'new_tx': tx,
                    'signature': signature
                }
                response = requests.post(service_url, json=data)
                if response.status_code == 200 and response.json().get('message') == 'Tx is valid':
                    valid_votes.append(service)
                    logging.info(f"Validator {service} approved the tx.")
                else:
                    logging.info(f"Validator {service} did not approve the tx.")
            except requests.exceptions.RequestException as e:
                logging.error(f"Error voting on block with {service}: {e}")

        return valid_votes

    def reach_tx_consensus(self, address, hash, pub_key, tx, signature):
        if len(self.validators) == 1:
            logging.info("Automatically reaching consensus with single validator")
            return True

        consensus_reached = self.vote_on_local_tx(address, hash, pub_key, tx, signature)

        if consensus_reached:
            logging.info("Tx consensus reached")
            return True
        else:
            logging.info("Tx consensus not reached")
            return False

    def receive_tx(self, address, hash, pub_key, tx, signature):
        try:
            if not self.validate_foreign_tx(address, hash, pub_key, tx, signature):
                logging.error(f"Received transaction, with hash {hash} from wallet {address}, did not pass verification")
                return False

            return True
        except Exception as e:
            logging.error(f"Error processing received transaction: {str(e)}")
            return False

    def receive_block(self, block):
        try:
            services = ledger.discover_services("node")
            authoritative_node_url, _ = ledger.sync_with_other_nodes(services)

            if authoritative_node_url:
                ledger.sync_account_list_data(authoritative_node_url, account_manager, coin, staked_coin)
                ledger.sync_treasury_data(authoritative_node_url)

            return True
        except Exception as e:
            logging.error(f"Error processing received block: {str(e)}")
            return False

    def broadcast_tx(self, address, hash, pub_key, new_tx, signature):
        data = {
            'address': address,
            'hash': hash,
            'pub_key': pub_key,
            'new_tx': new_tx,
            'signature': signature
        }

        services = ledger.discover_services("node")

        ledger.post_data_to_services(services, "transaction/receive_tx", data)

        return True
    
    def randomly_select_validator(self):
        if not self.validators:
            logging.warning("No validators available.")
            return None

        try:
            if len(self.validators) == 1:
                validator_address = self.validators[0]
                logging.info(f"Only one validator available. Selected validator address: {validator_address}")
                return validator_address

            max_value = len(self.validators) - 1
            random_bytes = QuantumUtils.quantum_random_bytes((max_value.bit_length() + 7) // 8)
            random_int = int.from_bytes(random_bytes, 'big') % (max_value + 1)
            validator_address = self.validators[random_int]
            logging.info(f"Randomly selected validator address: {validator_address}")
            return validator_address
        except Exception as e:
            logging.error(f"Error generating random index: {e}")
            return None

    def trigger_sync_on_all_nodes(self):
        services = ledger.discover_services("node")

        data = {}

        for service in services:
            service_base_url = f"http://{service}:3400"

            if service_base_url == node.url:
                logging.debug(f"Skipping self sync trigger: {service_base_url}")
                continue

            service_url = f"{service_base_url}/trigger_sync"
            logging.debug(f"Attempting to trigger sync on {service_url}")
            try:
                response = requests.post(service_url, json=data)
                if response.status_code == 200:
                    logging.debug(f"Successfully triggered sync on {service_url}")
                else:
                    logging.debug(f"Failed to trigger sync on {service_url}, status code: {response.status_code}")
            except requests.exceptions.RequestException as e:
                logging.error(f"Error triggering sync on {service_url}: {e}")

    def validate_received_block(self, block):
        logging.debug(f"Validating received block with index {block['index']}")
        if not self.validate_block_structure(block):
            logging.error("Block structure validation failed.")
            return False

        if not self.validate_block(block):
            logging.error("Block content validation failed.")
            return False

        if block['index'] != len(self.chain) + 1:
            logging.error(f"Block index {block['index']} does not follow the current chain length.")
            return False

        return True

    def validate_block_structure(self, block):
        logging.debug(f"Checking block structure for block with index {block['index']}")
        required_fields = [
            'index', 'previous_hash', 'timestamp', 'transactions',
            'merkle_root', 'stake_threshold', 'hash', 'miner', 'miner_share',
            'validator', 'validator_share', 'fee'
        ]

        missing_fields = [field for field in required_fields if field not in block]
        if missing_fields:
            logging.error(f"Block missing required fields: {missing_fields}")
            return False

        field_type_issues = False
        for field in required_fields:
            if field in block:
                expected_type = (int if field in ['index', 'timestamp'] else
                                 str if field in ['previous_hash', 'hash', 'miner', 'validator', 'merkle_root'] else
                                 list if field == 'transactions' else
                                 (int, float) if field in ['stake_threshold', 'fee', 'miner_share', 'validator_share'] else
                                 None)
                actual_type = type(block[field])
                if not isinstance(block[field], expected_type):
                    logging.error(f"Field '{field}' type mismatch: expected {expected_type}, got {actual_type}")
                    field_type_issues = True
            else:
                logging.error(f"Field '{field}' is missing from the block.")
                field_type_issues = True

        if field_type_issues:
            logging.error("One or more block field types are incorrect.")
            return False

        logging.debug("Block structure validated successfully.")
        return True
    
    def reach_consensus(self, proposed_block):
        if len(self.validators) == 1:
            logging.info("Automatically reaching consensus with single validator")
            return True

        consensus_reached = self.vote_on_local_block(proposed_block)

        if consensus_reached:
            logging.info("Consensus reached")
            return True
        else:
            logging.info("Consensus not reached")
            return False

    def vote_on_local_block(self, block):
        valid_votes = []
        services = self.discover_services("node")

        if len(services) == 1 and services[0] == node.url:
            logging.info("Only one validator in the network, bypassing the voting process.")
            valid_votes.append(node.url)

        filtered_services = [s for s in services if f"http://{s}:3400" != node.url]
        for service in filtered_services:
            service_url = f"http://{service}:3400/vote_on_block"

            try:
                response = requests.post(service_url, json=block)
                if response.status_code == 200 and response.json().get('message') == 'Block is valid':
                    valid_votes.append(service)
                    logging.info(f"Validator {service} approved the block.")
                else:
                    logging.info(f"Validator {service} did not approve the block.")
            except requests.exceptions.RequestException as e:
                logging.error(f"Error voting on block with {service}: {e}")

        return valid_votes

    def validate_block(self, block):
        logging.debug(f"Validating block with index {block['index']}")
        if block['validator'] not in self.validators:
            logging.error("Block validator is not recognized.")
            return False

        if not self.proof_of_stake(block):
            return False

        unique_addresses = set()
        double_spent_addresses = set()
        for transaction in block['transactions']:
            sender_address = transaction.get('address')
            if sender_address in unique_addresses:
                double_spent_addresses.add(sender_address)
            unique_addresses.add(sender_address)

        if double_spent_addresses:
            logging.error(f"Double spending detected for addresses: {', '.join(double_spent_addresses)}")
            raise DoubleSpendingError("Double spending detected for addresses: " + ', '.join(double_spent_addresses))

        block_string = str(block['index']) + str(block['timestamp']) + str(block['previous_hash']) + str(
            block['transactions']) + str(block['fee']) + str(block['validator']) + str(block['validator_share'])

        generated_hash = hashlib.sha256(block_string.encode()).hexdigest()
        if block['hash'] != generated_hash:
            logging.error("Block hash does not match the generated hash.")
            return False

        if not self.reach_consensus(block):
            logging.error("Failed to reach consensus.")
            return False

        logging.info(f"Block with index {block['index']} passed all validations.")
        return True

    def validate_foreign_block(self, block):
        logging.debug(f"Validating block with index {block['index']}")
        if block['validator'] not in self.validators:
            logging.error("Block validator is not recognized.")
            return False

        if not self.proof_of_stake(block):
            return False

        unique_addresses = set()
        double_spent_addresses = set()
        for transaction in block['transactions']:
            sender_address = transaction.get('address')
            if sender_address in unique_addresses:
                double_spent_addresses.add(sender_address)
            unique_addresses.add(sender_address)

        if double_spent_addresses:
            logging.error(f"Double spending detected for addresses: {', '.join(double_spent_addresses)}")
            raise DoubleSpendingError("Double spending detected for addresses: " + ', '.join(double_spent_addresses))

        block_string = str(block['index']) + str(block['timestamp']) + str(block['previous_hash']) + str(
            block['transactions']) + str(block['fee']) + str(block['validator']) + str(block['validator_share'])

        generated_hash = hashlib.sha256(block_string.encode()).hexdigest()
        if block['hash'] != generated_hash:
            logging.error("Block hash does not match the generated hash.")
            return False

        return True

    def generate_block_hash(self, block):
        transactions_string = json.dumps(block['transactions'], sort_keys=True)

        block_contents = (
            str(block['index']) +
            str(block['timestamp']) +
            str(block['previous_hash']) +
            transactions_string +
            str(block['fee']) +
            str(block['miner']) +
            str(block['miner_share']) +
            str(block['validator']) +
            str(block['validator_share'])
        )

        block_hash = hashlib.sha256(block_contents.encode()).hexdigest()
        return block_hash
    
    def proof_of_stake(self, block):
        logging.info("Starting proof of stake validation.")

        total_stake_weight = sum(node['stake_weight'] if isinstance(node, dict) else node.stake_weight for node in self.verifier.nodes)
        random_number = random.uniform(0, total_stake_weight)
        cumulative_stake_weight = 0

        logging.info(f"Total stake weight: {total_stake_weight}, Random number for validator selection: {random_number}")

        for current_node in self.verifier.nodes:
            node_stake_weight = current_node['stake_weight'] if isinstance(current_node, dict) else current_node.stake_weight
            cumulative_stake_weight += node_stake_weight

            if cumulative_stake_weight > random_number:
                selected_validator_address = current_node['address'] if isinstance(current_node, dict) else current_node.address
                logging.info(f"Selected validator address: {selected_validator_address}, Stake weight: {node_stake_weight}")

                if selected_validator_address == block['validator']:
                    logging.info(f"Validator {selected_validator_address} matches the block's validator.")
                    if node_stake_weight >= block['stake_threshold']:
                        logging.info(f"Validator {selected_validator_address} meets the stake threshold.")
                        return node_stake_weight
                    else:
                        logging.error(f"Validator {selected_validator_address} does not meet the stake threshold.")
                        return 0

        logging.error("No suitable validator found or the selected validator does not meet the stake threshold.")
        return 0

    def add_coin_transaction(self, address: str, amount: int, converted_amount: Union[int, float], fee: Union[int, float], hash: str, pub_key: str, signature: str, sub_type: str, type: str) -> Union[bool, str]:

        cleaned_transaction = {
            'address': address,
            'amount': amount,
            'converted_amount': converted_amount,
            'fee': fee,
            'hash': hash,
            'pub_key': pub_key,
            'signature': signature,
            'sub_type': sub_type,
            'type': type
        }

        if cleaned_transaction['signature']:
            return cleaned_transaction
        
    def select_miner(self) -> dict:
        accounts = staking_manager.staking_agreements

        # If no accounts are available, return None
        if not accounts:
            logging.warning("No staking accounts available for miner selection.")
            return None

        # Calculate the number of withdrawals for each account
        for account in accounts:
            account['withdrawals'] = sum(1 for block in self.chain for transaction in block['transactions']
                                        if 'address' in transaction and transaction.get('address') == account['address'])

        # Select the miner based on weighted selection
        miner = self.weighted_selection(accounts)
        return miner

    def weighted_selection(self, accounts: List[dict]) -> dict:
        # Calculate weights based on the number of withdrawals for each account
        weights = [1 / (acc['withdrawals'] + 1) for acc in accounts]
        total_weight = sum(weights)

        # Normalize the weights to ensure their sum is 1
        normalized_weights = [weight / total_weight for weight in weights]

        # Select an account using the normalized weights
        chosen_account = random.choices(
            accounts, weights=normalized_weights, k=1)[0]
        return chosen_account

    def calculate_fee_distribution(self, total_fee):
        fee_distribution = {}

        validator_percentage = 0.45
        miner_percentage = 0.315
        treasury_percentage = 0.235  # Updated to include the burn percentage

        fee_distribution['validator_share'] = total_fee * validator_percentage
        fee_distribution['miner_share'] = total_fee * miner_percentage
        fee_distribution['treasury_share'] = total_fee * treasury_percentage

        return fee_distribution
    
    def select_validator(self, block):
        selected_validator = self.verifier.select_validator(block)
        return selected_validator if selected_validator else None

    def validate_selected_validator(self, selected_validator, block):
        if selected_validator.malicious or selected_validator not in verifier.nodes:
            return False

        if selected_validator.address == block['validator'] and \
                selected_validator.stake_weight >= block['stake_threshold']:
            return True

        return False

    def add_malicious_validator(self, validator_address):
        for node in verifier.nodes:
            if node.address == validator_address:
                node.malicious = True
                break

    def create_new_block(self, transactions):
        latest_block = self.chain[-1]
        block_index = latest_block['index'] + 1
        timestamp = int(datetime.now(timezone.utc).timestamp())
        previous_hash = latest_block['hash']
        stake_threshold = node.stake_weight

        processed_transactions, total_fee = self.process_transactions(transactions)
        block_fee = self.coin.mint_for_block_fee(total_fee)
        fee_distribution = self.calculate_fee_distribution(block_fee)
        miner = self.select_miner()

        if miner is None:
            logging.error("Failed to select a miner. Aborting block creation.")
            return

        miner_address = miner['address']

        block = {
            'index': block_index,
            'timestamp': timestamp,
            'previous_hash': previous_hash,
            'transactions': processed_transactions,
            'stake_threshold': stake_threshold,
            'fee': block_fee
        }

        validator_node = self.select_validator(block)
        if validator_node:
            validator_address = validator_node['address'] if isinstance(validator_node, dict) else getattr(validator_node, 'address', node.address)
        else:
            validator_address = node.address

        for transaction in transactions:
            merkle_tree.add_transaction(str(transaction))

        merkle_tree.create_tree()
        merkle_root = merkle_tree.get_merkle_root()

        self.coin.credit(validator_address, fee_distribution['validator_share'])
        self.coin.credit(miner_address, fee_distribution['miner_share'])
        self.coin.credit(self.coin.treasury_address, fee_distribution['treasury_share'])

        new_block = {
            'index': block_index,
            'timestamp': timestamp,
            'previous_hash': previous_hash,
            'transactions': processed_transactions,
            'merkle_root': merkle_root,
            'stake_threshold': stake_threshold,
            'fee': block_fee,
            'miner': miner_address,
            'miner_share': fee_distribution['miner_share'],
            'validator': validator_address,
            'validator_share': fee_distribution['validator_share'],
            'treasury_share': fee_distribution['treasury_share']
        }

        logging.info(f"constructed block: {new_block}")

        block_string = str(new_block['index']) + str(new_block['timestamp']) + str(new_block['previous_hash']) + str(
            new_block['transactions']) + str(new_block['fee']) + str(new_block['validator']) + str(new_block['validator_share'])

        # Generate block hash
        block_hash = hashlib.sha256(block_string.encode()).hexdigest()

        new_block['hash'] = block_hash

        if self.add_block(new_block):
            self.transactions.cleaned_transactions = []
            logging.info(f"Successfully mined new block: {new_block}")
            return new_block
        else:
            logging.debug(f"Issue mining block: {new_block}")

    def process_transactions(self, transactions):
        processed_transactions = []
        total_fee = 0.0

        for transaction in transactions:
            transaction_type = transaction.get('sub_type')

            if transaction_type == 'r':
                processed_transaction = self.handle_staking_transaction(transaction)
            elif transaction_type == 'o':
                processed_transaction = self.handle_unstaking_transaction(transaction)
            elif transaction_type == 'k':
                processed_transaction = self.handle_transfer_transaction(transaction)
            elif transaction_type == 'w':
                processed_transaction = self.handle_pomc_whitelist_transaction(transaction)
            elif transaction_type in ['h', 'x', 'm', 'pr']:
                processed_transaction = self.handle_fee_payment_transaction(transaction)
            else:
                processed_transaction = self.handle_default_transaction(transaction)

            if processed_transaction:
                processed_transactions.append(processed_transaction)
                total_fee += processed_transaction.get('fee', 0.0)

        return processed_transactions, total_fee

    def handle_staking_transaction(self, transaction):
        try:
            fee_calculator = DynamicFeeCalculator()
            sender_address = transaction['address']
            staking_amount = transaction['amount']
            min_term = transaction['min_term']
            pub_key = transaction['pub_key']
            signature = transaction.get('signature')

            transaction_data = {
                'address': sender_address,
                'amount': staking_amount,
                'min_term': min_term,
                'pub_key': pub_key,
                'type': transaction['type']
            }

            transaction_fee, transaction_hash = dynamic_fee_calculator.get_base_dynamic_fee(transaction_data, transaction['type'])

            if not all([sender_address, staking_amount, min_term, pub_key, signature]):
                logging.error("Missing fields in staking transaction")
                return None

            sender_balance_info = self.wallet.get_account_balance(sender_address)
            if not sender_balance_info or sender_balance_info['balance_float'] < staking_amount + transaction_fee:
                logging.error("Insufficient balance for staking")
                return None

            transaction_for_verification = {
                'address': sender_address,
                'amount': staking_amount,
                'fee': transaction_fee,
                'hash': transaction_hash,
                'min_term': min_term,
                'pub_key': pub_key,
                'type': transaction['type']
            }

            if not crypto_utils.verify_transaction(transaction['pub_key'], transaction_for_verification, transaction['signature']):
                logging.error("Invalid signature in staking transaction")
                return None

            self.wallet.stake_coins(sender_address, staking_amount, min_term)

            processed_transaction = {
                'address': sender_address,
                'amount': staking_amount,
                'fee': transaction_fee,
                'hash': transaction_hash,
                'min_term': min_term,
                'stake_threshold': 3,
                'type': transaction['type'],
                'when': str(datetime.now(timezone.utc))
            }

            logging.info(f"Processed staking transaction for {sender_address}")
            return processed_transaction

        except Exception as e:
            logging.error(f"Error processing staking transaction: {e}")
            return None

    def handle_unstaking_transaction(self, transaction):
        try:
            fee_calculator = DynamicFeeCalculator()
            sender_address = transaction['address']
            contract_id = transaction['contract_id']
            pub_key = transaction['pub_key']
            signature = transaction.get('signature')

            transaction_data = {
                'address': sender_address,
                'contract_id': contract_id,
                'pub_key': pub_key,
                'type': transaction['type']
            }

            transaction_fee, transaction_hash = dynamic_fee_calculator.get_base_dynamic_fee(transaction_data, transaction['type'])

            if not all([sender_address, contract_id, pub_key, signature]):
                logging.error("Missing fields in unstaking transaction")
                return None

            sender_balance_info = self.wallet.get_account_balance(sender_address)
            if not sender_balance_info or sender_balance_info['balance_float'] < transaction_fee:
                logging.error("Insufficient balance for unstaking")
                return None

            transaction_for_verification = {
                'address': sender_address,
                'contract_id': contract_id,
                'fee': transaction_fee,
                'hash': transaction_hash,
                'pub_key': pub_key,
                'type': transaction['type']
            }

            if not crypto_utils.verify_transaction(transaction['pub_key'], transaction_for_verification, transaction['signature']):
                logging.error("Invalid signature in unstaking transaction")
                return None

            self.wallet.unstake_coins(sender_address, contract_id)

            processed_transaction = {
                'address': sender_address,
                'contract_id': contract_id,
                'fee': transaction_fee,
                'hash': transaction_hash,
                'stake_threshold': 2,
                'type': transaction['type'],
                'when': str(datetime.now(timezone.utc))
            }

            logging.info(f"Processed unstaking transaction for {sender_address}")
            return processed_transaction

        except Exception as e:
            logging.error(f"Error processing unstaking transaction: {e}")
            return None

    def handle_transfer_transaction(self, transaction):
        try:
            fee_calculator = DynamicFeeCalculator()
            sender_address = transaction['sender']
            recipient_address = transaction['recipient']
            transfer_amount = transaction['amount']
            pub_key = transaction['pub_key']
            signature = transaction.get('signature')

            transaction_data = {
                'sender': sender_address,
                'recipient': recipient_address,
                'amount': transfer_amount,
                'pub_key': pub_key,
                'type': transaction['type']
            }

            transaction_fee, transaction_hash = dynamic_fee_calculator.get_base_dynamic_fee(transaction_data, transaction['type'])

            if not all([sender_address, recipient_address, transfer_amount, pub_key, signature]):
                logging.error("Missing fields in transfer transaction")
                return None

            sender_balance_info = self.wallet.get_account_balance(sender_address)
            if not sender_balance_info or sender_balance_info['balance_float'] < transfer_amount + transaction_fee:
                logging.error("Insufficient balance for transfer")
                return None

            transaction_for_verification = {
                'sender': sender_address,
                'recipient': recipient_address,
                'amount': transfer_amount,
                'fee': transaction_fee,
                'hash': transaction_hash,
                'pub_key': pub_key,
                'type': transaction['type']
            }

            if not crypto_utils.verify_transaction(transaction['pub_key'], transaction_for_verification, transaction['signature']):
                logging.error("Invalid signature in transfer transaction")
                return None

            self.wallet.transfer(sender_address, recipient_address, transfer_amount)

            processed_transaction = {
                'sender': sender_address,
                'recipient': recipient_address,
                'amount': transfer_amount,
                'fee': transaction_fee,
                'hash': transaction_hash,
                'stake_threshold': 2,
                'type': transaction['type'],
                'when': str(datetime.now(timezone.utc))
            }

            logging.info(f"Processed transfer transaction from {sender_address} to {recipient_address}")
            return processed_transaction

        except Exception as e:
            logging.error(f"Error processing transfer transaction: {e}")
            return None
    
    def handle_pomc_whitelist_transaction(self, transaction):
        try:
            
            sender_address = transaction['sender']
            pub_key = transaction['pub_key']
            signature = transaction.get('signature')

            processed_transaction = {
                'fee': transaction['fee'],
                'hash': transaction['hash'],
                'sender': transaction['sender'],
                'sub_type': transaction['sub_type'],
                'stake_threshold': 2,
                'type': transaction['type'],
                'when': transaction['when']
            }

            logging.info(f"Processed transfer transaction from {sender_address} to join pOMC whitelist")
            return processed_transaction

        except Exception as e:
            logging.error(f"Error processing transfer transaction: {e}")
            return None

    def handle_fee_payment_transaction(self, transaction):
        try:
            fee_calculator = DynamicFeeCalculator()
            payer_address = transaction['from']
            fee_amount = transaction['fee']
            pub_key = transaction['pub_key']
            signature = transaction.get('signature')

            transaction_data = {
                'from': payer_address,
                'fee': fee_amount,
                'pub_key': pub_key,
                'type': transaction['type']
            }

            calculated_fee, transaction_hash = dynamic_fee_calculator.get_base_dynamic_fee(transaction_data, transaction['type'])

            if not all([payer_address, fee_amount, pub_key, signature]):
                logging.error("Missing fields in fee payment transaction")
                return None

            payer_balance_info = self.wallet.get_account_balance(payer_address)
            if not payer_balance_info or payer_balance_info['balance_float'] < fee_amount + calculated_fee:
                logging.error("Insufficient balance for fee payment")
                return None

            transaction_for_verification = {
                'from': payer_address,
                'fee': calculated_fee,
                'hash': transaction_hash,
                'pub_key': pub_key,
                'type': transaction['type']
            }

            if not crypto_utils.verify_transaction(transaction['pub_key'], transaction_for_verification, transaction['signature']):
                logging.error("Invalid signature in fee payment transaction")
                return None

            self.wallet.pay_fee(payer_address, fee_amount)

            processed_transaction = {
                'from': payer_address,
                'fee': calculated_fee,
                'hash': transaction_hash,
                'stake_threshold': 2,
                'type': transaction['type'],
                'when': str(datetime.now(timezone.utc))
            }

            logging.info(f"Processed fee payment transaction from {payer_address}")
            return processed_transaction

        except Exception as e:
            logging.error(f"Error processing fee payment transaction A1: {e}")
            return None

    def handle_default_transaction(self, transaction):
        try:
            fee_calculator = DynamicFeeCalculator()
            payer_address = transaction['address']

            transaction_data = {
                'from': payer_address,
                'type': 'e'
            }

            calculated_fee, transaction_hash = dynamic_fee_calculator.get_base_dynamic_fee(transaction_data, transaction['type'])

            processed_transaction = {
                'from': payer_address,
                'fee': 0.0,
                'hash': transaction_hash,
                'stake_threshold': 1,
                'type': 'e',
                'when': str(datetime.now(timezone.utc))
            }

            logging.info(f"Processed fee payment transaction from {payer_address}")
            return processed_transaction

        except Exception as e:
            logging.error(f"Error processing fee payment transaction A2: {e}")
            return None

    def clean_and_verify_transactions(self):
        new_transactions = self.transactions.batch_pending_transactions()
        cleaned_transactions = []

        for transaction in new_transactions:
            try:
                if transaction['type'] == 'c' and transaction['sub_type'] == 'c':
                    self.process_account_creation_transaction(transaction)
                elif transaction['type'] == 'c' and transaction['sub_type'] == 'w':
                    self.process_add_account_to_whitelist_transaction(transaction)
                elif transaction['type'] == 'o':
                    self.process_non_f_transaction(transaction)
                elif transaction['type'] == 'e':
                    self.process_f_transaction(transaction)
            except Exception as e:
                logging.error(f"Error processing transaction {transaction['type']}: {e}")

        return cleaned_transactions
    
    def process_account_creation_transaction(self, transaction):
        # Verify that the transaction is of the correct type
        if transaction['type'] != 'c':
            logging.error(f"Invalid transaction type for account creation: {transaction['type']}")
            return

        try:
            # Extract necessary fields from the transaction
            address = transaction['address']
            balance = transaction['balance']
            type = transaction['type']
            timestamp = ['timestamp']
            withdrawals = transaction['withdrawals']

            # Validate the transaction data
            if not all([address, type]):
                logging.error("Incomplete account creation transaction data")
                return

            # Check if the address already exists in the blockchain wallet
            # if any(acc['address'] == address for acc in account_manager.accounts):
            #     logging.info(f"Account already exists: {address}")
            #     return

            # # Create and append the new account to the wallet
            # new_account = {
            #     'address': address,
            #     'balance': balance,
            #     'withdrawals': withdrawals
            # }
            # account_manager.accounts.append(new_account)

            # Create a cleaned version of the transaction for the blockchain
            cleaned_transaction = {
                'address': address,
                'hash': transaction.get('hash'),
                'pub_key': transaction['pub_key'],
                'signature': transaction['signature'],
                'sub_type': 'c',
                'type': transaction['type'],
                'withdrawals': withdrawals
            }

            # Append the cleaned transaction to the list of processed transactions
            self.transactions.cleaned_transactions.append(cleaned_transaction)
            logging.info(f"Processed account creation transaction for {address}")

        except Exception as e:
            logging.error(f"Error processing account creation transaction A2: {e}")
            
    def process_add_account_to_whitelist_transaction(self, transaction):
        # Verify that the transaction is of the correct type
        if transaction['type'] != 'c':
            logging.error(f"Invalid transaction type to add account to whitelist: {transaction['type']}")
            return

        try:
            result = {
                'fee': transaction['fee'],
                'hash': transaction['hash'],
                'pub_key': transaction['pub_key'],
                'sender': transaction['sender'],
                'signature': transaction['signature'],
                'sub_type': transaction['sub_type'],
                'type': transaction['type'],
                'when': transaction['when']
            }
            # Extract necessary fields from the transaction
            address = transaction['sender']
            hash = transaction['hash']
            type = transaction['type']

            # Validate the transaction data
            if not all([address, hash, type]):
                logging.error("Incomplete account creation transaction data")
                return

            # Create a cleaned version of the transaction for the blockchain
            cleaned_transaction = {
                'fee': transaction['fee'],
                'hash': transaction['hash'],
                'pub_key': transaction['pub_key'],
                'sender': transaction['sender'],
                'signature': transaction['signature'],
                'sub_type': transaction['sub_type'],
                'type': transaction['type'],
                'when': transaction['when']
            }

            # Append the cleaned transaction to the list of processed transactions
            self.transactions.cleaned_transactions.append(cleaned_transaction)
            logging.info(f"Processed join whitelist transaction for {address}")

        except Exception as e:
            logging.error(f"Error processing join whiteist transaction A2: {e}")

    def process_f_transaction(self, transaction):
        try:
            transaction_type = transaction.get('type')
            sender_address = transaction.get('address')
            transaction_fee = transaction.get('fee', 0.0)

            if not sender_address or transaction_fee is None:
                logging.error("Invalid transaction format.")
                return None

            cleaned_transaction = None

            if transaction_type == 'e':
                sub_tx_type = transaction.get('sub_type')

                if sub_tx_type == 'p':
                    amount = transaction.get('amount')
                    recipient_address = transaction.get('recipient')

                    if crypto_utils.verify_transaction(sender_address, recipient_address, amount):
                        self.wallet.transfer(sender_address, recipient_address, amount)

                elif sub_tx_type == 'r':
                    amount = transaction.get('amount')
                    min_term = transaction.get('min_term')

                    self.wallet.stake_coins(sender_address, amount, min_term)

                elif sub_tx_type == 'z':
                    contract_id = transaction.get('contract_id')

                    self.wallet.unstake_coins(sender_address, contract_id)

            if cleaned_transaction:
                self.transactions.cleaned_transactions.append(cleaned_transaction)
                logging.info(f"Processed transaction of type {transaction_type} for {sender_address}")
                return cleaned_transaction
            else:
                logging.warning(f"Unhandled or failed transaction type/subtype: {transaction_type}/{sub_tx_type}")
                return None

        except Exception as e:
            logging.error(f"Error processing account creation transaction A2: {e}")

    def process_non_f_transaction(self, transaction):
        try:
            transaction_type = transaction.get('type')
            sender_address = transaction.get('address')
            transaction_fee = transaction.get('fee', 0.0)

            if not sender_address or transaction_fee is None:
                logging.error("Invalid transaction format.")
                return None

            cleaned_transaction = None

            if transaction_type == 'o':
                sub_tx_type = transaction.get('sub_type')

                if sub_tx_type == 's':
                    self.handle_post_transaction(transaction)

                elif sub_tx_type == 'j':
                    refined_transaction = self.handle_add_profile_transaction(transaction)
                    if refined_transaction:
                        cleaned_transaction = {
                            'address': transaction['address'],
                            'avi': transaction['avi'],
                            'clubs': transaction['clubs'],
                            'fee': transaction['fee'],
                            'handle': transaction['handle'],
                            'hash': transaction['hash'],
                            'intro': transaction['intro'],
                            'joined': transaction['joined'],
                            'name': transaction['name'],
                            'profile_id': transaction['profile_id'],
                            'profile_type': transaction['profile_type'],
                            'pt': transaction['pt'],
                            'pt_id': transaction['pt_id'],
                            'pub_key': transaction['pub_key'],
                            'signature': transaction['signature'],
                            'sub_type': transaction['sub_type'],
                            'tags': transaction['tags'],
                            'type': transaction['type'],
                            'version': transaction['version']
                        }

            if cleaned_transaction:
                transactions.cleaned_transactions.append(cleaned_transaction)
                logging.info(f"Processed transaction of type {transaction_type} for {sender_address}")
                return cleaned_transaction
            else:
                logging.warning(f"Unhandled or failed transaction type/subtype: {transaction_type}/{sub_tx_type}")
                return None

        except Exception as e:
            logging.error(f"Error processing transaction: {e}")
            return None

    def start_mining(self):
        self.create_new_block(self.transactions.cleaned_transactions)

    def check_pending_transactions(self):
        self.clean_and_verify_transactions()
        self.start_mining()

    def get_latest_block(self):
        return self.chain[-1]

    def main_loop(self):
        while True:
            self.start_mining()
            self.consume_blocks()

    def consume_blocks(self):
        for message in self.consumer:
            block_data = message.value.decode('utf-8')
            block = json.loads(block_data)
            self.receive_block(block)
    def __init__(self, coin, wallet, transactions, verifier):
        self.coin = coin
        self.wallet = wallet
        self.transactions = transactions
        self.verifier = verifier

        self.chain = []
        self.block_hashes = set()
        self.lock = threading.Lock()
        logging.basicConfig(level=logging.DEBUG)
        
        self.validators = []
        
        mining_thread = threading.Thread(target=self.mine_new_block_periodically)
        mining_thread.daemon = True
        mining_thread.start()

    @staticmethod
    def serialize_and_create_single_hash(cls):
        if not isinstance(cls, type):
            raise TypeError(f"Expected class type, got {type(cls)}")

        try:
            class_dict = {
                'attributes': {key: value for key, value in cls.__dict__.items() if not callable(value) and not key.startswith('__')},
                'methods': {
                    key: (value.__func__.__code__.co_code if isinstance(value, staticmethod) else value.__code__.co_code)
                    for key, value in cls.__dict__.items() if callable(value)
                }
            }
            class_serialized = json.dumps(class_dict, sort_keys=True, default=str)
            logging.debug(f"Serialized class {cls.__name__}: {class_serialized}")
            class_hash = hashlib.sha256(class_serialized.encode()).hexdigest()
            return class_hash
        except Exception as e:
            logging.error(f"Error serializing class {cls.__name__}: {e}")
            raise

    @staticmethod
    def verify_class_hashes():
        """
        This function retrieves the stored hashes of classes from the public API and compares them
        with the hashes of the current local classes to ensure integrity.
        """
        try:
            response = requests.get(HASH_API_URL)
            if response.status_code != 200:
                raise ValueError("Failed to fetch class hashes from public API.")

            stored_hashes = response.json()
        except Exception as e:
            logging.error(f"Error fetching class hashes from public API: {e}")
            raise

        classes_to_verify = {
            'coin': OMC,
            'quantum_utils': QuantumUtils,
            'transactions': Transactions,
            'permission_manager': PermissionMngr,
            'precursor_coin': pOMC,
            'verifier': Verifier,
            'crypto_utils': CUtils,
            'fee_calculator': DynamicFeeCalculator,
            'ledger': Ledger,
            'treasury': OMCTreasury
        }

        for class_name, cls in classes_to_verify.items():
            stored_hash = stored_hashes.get(class_name)
            if not stored_hash:
                logging.error(f"Stored hash for class {class_name} not found in the public API response.")
                raise ValueError(f"Stored hash for class {class_name} not found.")

            local_hash = Ledger.serialize_and_create_single_hash(cls)
            if stored_hash != local_hash:
                logging.error(f"Hash mismatch for class {class_name}. Possible tampering detected.")
                raise ValueError(f"Hash mismatch for class {class_name}. Possible tampering detected.")

        logging.info("All class hashes verified successfully. No tampering detected.")
        return True

    def initialize_node(self):
        service_prefix = "node"
        services = self.discover_services(service_prefix)
        if services:
            self.ping_services(services, "check_nodes", node.url)

        node.steward = os.getenv('STEWARD_ADDRESS')
        if not node.steward:
            raise ValueError("Steward address not provided. Set the STEWARD_ADDRESS environment variable.")

        self.update_node_state(node)
        self.check_chain_length_and_sync(services)
        self.update_validators()
        self.broadcast_node_data(node)

    def discover_services(self, prefix):
        discovered_services = []
        max_range = 10

        for i in range(1, max_range):
            service_name = f"{prefix}{i}.omne"
            try:
                service_address = socket.gethostbyname(service_name)

                if service_address != node.url:
                    discovered_services.append(service_name)
                    logging.debug(f"Discovered service: {service_name}")

            except socket.gaierror:
                continue

        if not discovered_services:
            logging.warning("No services were discovered.")

        return discovered_services

    def ping_services(self, services, endpoint, current_node_url):
        headers = {"Authorization": f"Bearer {AUTH_TOKEN}"}

        for service in services:
            service_base_url = f"http://{service}:3400"
            service_url = f"{service_base_url}/{endpoint}"

            if service_base_url == current_node_url:
                logging.debug(f"Skipping self ping: {service_base_url}")
                continue

            logging.debug(f"Attempting to ping {service_url}")
            try:
                response = requests.get(service_url, headers=headers)
                if response.status_code == 200:
                    logging.debug(f"Successfully pinged {service_url}")
                    received_nodes = response.json().get('nodes', [])
                    for received_node in received_nodes:
                        if not any(node['address'] == received_node['address'] for node in self.verifier.nodes):
                            verifier.nodes.append(received_node)
                            verifier.nodes.append(received_node)
                            self.validators.append(received_node['address'])
                            logging.debug(f"Added new node: {received_node['address']}")
                else:
                    logging.debug(f"Failed to ping {service_url}, status code: {response.status_code}")

            except requests.exceptions.RequestException as e:
                logging.error(f"Error pinging {service_url}: {e}")

    def post_data_to_services(self, services, endpoint, data):
        headers = {"Authorization": f"Bearer {AUTH_TOKEN}"}

        for service in services:
            service_base_url = f"http://{service}:3400"
            service_url = f"{service_base_url}/{endpoint}"

            if service_base_url == node.url:
                logging.debug(f"Skipping self post: {service_url}")
                continue

            logging.debug(f"Attempting to post data to {service_url}")
            try:
                response = requests.post(service_url, json=data, headers=headers)
                if response.status_code == 200:
                    logging.debug(f"Successfully posted data to {service_url}")
                else:
                    logging.debug(f"Failed to post data to {service_url}, status code: {response.status_code}")

            except requests.exceptions.RequestException as e:
                logging.error(f"Error posting data to {service_url}: {e}")

    def broadcast_self_info(self):
        if not node or not node.address or not node.url:
            logging.error("Node information is incomplete or incorrect. Cannot broadcast.")
            return

        node_info = node.to_dict()
        logging.info(f"Broadcasting self node information: {node_info}")

        services = self.discover_services("node")
        if not services:
            logging.warning("No other services discovered for broadcasting. Broadcast aborted.")
            return

        services = [service for service in services if service != node.url]
        if not services:
            logging.warning("No external services discovered for broadcasting. Broadcast aborted.")
            return

        self.post_data_to_services(services, "receive_node_info", node_info)
        logging.info("Successfully broadcasted self node information to other services.")

    def update_validators(self):
        services = self.discover_services("node")
        for service in services:
            service_base_url = f"http://{service}:3400"
            service_url = f"{service_base_url}/node_info"

            if service_base_url == node.url:
                continue

            try:
                response = requests.get(service_url)
                if response.status_code == 200:
                    node_data = response.json()
                    if node_data['address'] not in self.validators:
                        self.validators.append(node_data['address'])
            except requests.exceptions.RequestException as e:
                logging.error(f"Failed to retrieve node information from {service}: {e}")

    def sync_with_other_nodes(self, services):
        my_chain_length = len(self.chain)
        synchronized_chain = None
        authoritative_node_url = None

        for service in services:
            service_base_url = f"http://{service}:3400"
            service_url = f"{service_base_url}/get_chain"

            if service_base_url == node.url:
                continue

            try:
                response = requests.get(service_url)
                if response.status_code == 200:
                    other_chain = response.json()["chain"]
                    if len(other_chain) > my_chain_length:
                        my_chain_length = len(other_chain)
                        synchronized_chain = other_chain
                        authoritative_node_url = service_base_url
            except requests.exceptions.RequestException as e:
                logging.error(f"Error while trying to sync with {service_url}: {e}")

        if synchronized_chain:
            self.chain = synchronized_chain

        return authoritative_node_url, synchronized_chain

    def broadcast_node_data(self, node):
        headers = {"Authorization": f"Bearer {AUTH_TOKEN}"}
        node_data_complete = {
            'address': node.address,
            'public_key': node.public_key,
            'url': node.url,
            'stake_weight': node.stake_weight,
            'version': node.version,
            'steward': node.steward
        }

        services = self.discover_services("node")

        for service in services:
            service_base_url = f"http://{service}:3400"
            service_url = f"{service_base_url}/receive_node_data"

            if service_base_url == node.url:
                continue

            logging.debug(f"Broadcasting node data to {service_url}")
            try:
                response = requests.post(service_url, json=node_data_complete, headers=headers)
                if response.status_code == 201:
                    logging.debug(f"Successfully broadcasted new node data to {service_url}")
                elif response.status_code == 200:
                    logging.debug(f"Node data already exists on {service_url}")
                else:
                    logging.warning(f"Failed to broadcast node data to {service_url}, status code: {response.status_code}")
            except requests.exceptions.RequestException as e:
                logging.error(f"Error broadcasting node data to {service_url}: {e}")
                
    def update_accounts(self, address, balance):
        new_account = {
            'address': address,
            'balance': balance
        }

        service_prefix = "node"
        services = self.discover_services(service_prefix)

        filtered_services = [s for s in services if f"http://{s}:3400" != node.url]
        self.post_data_to_services(filtered_services, "propagate_account", new_account)

    def update_node_state(self, new_node):
        if new_node not in self.verifier.nodes:
            verifier.nodes.append(new_node)
            self.validators.append(new_node.address)
            logging.info(f"Node {new_node.address} added to local state.")

    def mine_new_block_periodically(self, interval=9):
        while True:
            self.check_for_mining_opportunity()
            time.sleep(interval * 60)

    def check_for_mining_opportunity(self):
        num_transactions = len(transactions.transactions)
        if num_transactions >= 1:
            self.check_pending_transactions()
        elif 4 <= num_transactions < 15 and self.is_time_to_mine():
            self.check_pending_transactions()

    def is_time_to_mine(self):
        latest_block = self.chain[-1]
        block_timestamp = datetime.strptime(latest_block['timestamp'], "%Y-%m-%d %H:%M:%S.%f%z")
        current_timestamp = datetime.now(timezone.utc)
        
        mining_interval = 9 * 60  # Fixed interval of 9 minutes
        return (current_timestamp - block_timestamp).total_seconds() >= mining_interval

    def create_new_wallet(self):
        mnemonic = crypto_utils.generate_mnemonic()
        account = self.wallet.account_manager.generate_account_from_mnemonic(mnemonic)
        
        # Add the new address with a balance of zero to the self.balance dictionary
        with coin.balance_lock:
            coin.balance[account['address']] = 0.0

        wallet_creation_transaction = {
            'address': account['address'],
            'balance': 0.0,
            'withdrawals': 0,
            'type': 'c'
        }

        cleaned_transaction = {
            'address': wallet_creation_transaction['address'],
            'balance': wallet_creation_transaction['balance'],
            'pub_key': account['pub_key'],
            'sub_type': 'c',
            'type': wallet_creation_transaction['type'],
            'withdrawals': wallet_creation_transaction['withdrawals']
        }

        initial_balance = 0.0

        account_dict = {
            'address': wallet_creation_transaction['address'],
            'balance': initial_balance,
        }

        sendable_transaction = {
            'mnemonic': mnemonic,
            'private_key': base64.b64encode(account['private_key']).decode('utf-8'),
            'pub_key': account['pub_key'],
            'address': account['address'],
        }

        return sendable_transaction

    def create_new_wallet_from_seed(self, seed):
        account = self.wallet.account_manager.generate_account_from_mnemonic(seed)

        wallet_creation_transaction = {
            'address': account['address'],
            'balance': 0.0,
            'withdrawals': 0,
            'type': 'c'
        }

        cleaned_transaction = {
            'address': wallet_creation_transaction['address'],
            'balance': wallet_creation_transaction['balance'],
            'pub_key': account['pub_key'],
            'type': wallet_creation_transaction['type'],
            'withdrawals': wallet_creation_transaction['withdrawals']
        }

        sendable_transaction = {
            'mnemonic': account['mnemonic'],
            'private_key': base64.b64encode(account['private_key']).decode('utf-8'),
            'pub_key': account['pub_key'],
            'address': account['address'],
        }

        private_key_bytes = base64.b64decode(sendable_transaction['private_key'])
        signature = crypto_utils.sign_transaction(private_key_bytes, wallet_creation_transaction)

        cleaned_transaction['signature'] = signature

        self.transactions.transactions.append(cleaned_transaction)
        self.update_accounts(wallet_creation_transaction['address'], wallet_creation_transaction['balance'])

        return sendable_transaction

    def get_chain_length(self):
        return len(self.chain) if hasattr(self, "blockchain") else 0

    def check_chain_length_and_sync(self, services):
        service_prefix = "node"
        services = self.discover_services(service_prefix)

        authoritative_node_url, synchronized_chain = self.sync_with_other_nodes(services)

        self.sync_account_list_data(authoritative_node_url, account_manager, coin, staked_coin)
        self.sync_treasury_data(authoritative_node_url)

        self.ping_services(services, "check_nodes", node.url)

        if synchronized_chain is not None:
            return {
                "chain": synchronized_chain,
                "message": "Chain synchronized successfully"
            }
        else:
            return {
                "chain": self.chain,
                "message": "Chain synchronization failed"
            }

    def sync_account_list_data(self, authoritative_node_url, account_manager, coin, staked_coin):
        if not authoritative_node_url:
            logging.error("No authoritative node URL provided for account list data synchronization.")
            return

        service_url = f"{authoritative_node_url}/retrieve_accounts"

        try:
            response = requests.get(service_url)
            if response.status_code == 200:
                data = response.json()

                main_accounts = data.get('data', [])
                for new_acc in main_accounts:
                    if 'address' in new_acc and 'balance' in new_acc:
                        account = next((acc for acc in account_manager.accounts if acc['address'] == new_acc['address']), None)
                        if account:
                            account['balance'] = new_acc['balance']
                            coin.balance[new_acc['address']] = new_acc['balance']
                            logging.info(f"Updated main account {new_acc['address']} for {coin.name}.")
                        else:
                            account_manager.accounts.append(new_acc)
                            coin.balance[new_acc['address']] = new_acc['balance']
                            logging.info(f"Added new main account {new_acc['address']} for {coin.name}.")

                precursor_accounts = data.get('precursor_accounts', [])
                for new_acc in precursor_accounts:
                    if 'address' in new_acc and 'balance' in new_acc:
                        account = next((acc for acc in account_manager.precursor_accounts if acc['address'] == new_acc['address']), None)
                        if account:
                            account['balance'] = new_acc['balance']
                            coin.balance[new_acc['address']] = new_acc['balance']
                            logging.info(f"Updated precursor account {new_acc['address']} for {coin.name}.")
                        else:
                            account_manager.precursor_accounts.append(new_acc)
                            coin.balance[new_acc['address']] = new_acc['balance']
                            logging.info(f"Added new precursor account {new_acc['address']} for {coin.name}.")

                staking_accounts = data.get('staking_accounts', [])
                for new_acc in staking_accounts:
                    if 'address' in new_acc and 'min_term' in new_acc:
                        account = next((acc for acc in staking_manager.staking_agreements if acc['address'] == new_acc['address']), None)
                        if account:
                            account['amount'] = new_acc['amount']
                            account['withdrawals'] = new_acc['withdrawals']
                            staked_coin.balance[new_acc['address']] = new_acc['amount']
                            logging.info(f"Updated staking account {new_acc['address']} for {staked_coin.name}.")
                        else:
                            staked_coin.accounts.append(new_acc)
                            staking_manager.staking_agreements.append(new_acc)
                            staked_coin.balance[new_acc['address']] = new_acc['amount']
                            logging.info(f"Added new staking account {new_acc['address']} for {staked_coin.name}.")

                self.validators = data.get('validators', [])
                if node.address not in self.validators:
                    self.validators.append(node.address)

                notification_data = {"message": "Data updated from authoritative node"}
                self.post_data_to_services(self.discover_services("node"), "notify_data_update", notification_data)

                logging.warning(f"Synchronized account list data with the authoritative node: {authoritative_node_url}")
            else:
                logging.error(f"Failed to retrieve account data from {service_url}, status code: {response.status_code}")
        except requests.RequestException as e:
            logging.error(f"Error retrieving account data from {service_url}: {e}")
    
    def sync_treasury_data(self, authoritative_node_url):
        if not authoritative_node_url:
            logging.error("No authoritative node URL provided for treasury data synchronization.")
            return False

        service_url = f"{authoritative_node_url}/retrieve_treasury_data"

        try:
            response = requests.get(service_url)
            if response.status_code == 200:
                response_data = response.json()
                if 'treasury_address' in response_data:
                    treasury.update_treasury_data(response_data['treasury_address'])
                    logging.warning("Synchronized treasury data with the authoritative node: %s", authoritative_node_url)
                    return True
                else:
                    logging.error(f"No treasury account data found in the response from {service_url}")
                    return False
            else:
                logging.error(f"Failed to retrieve treasury data from {service_url}, status code: {response.status_code}")
                return False
        except requests.RequestException as e:
            logging.error(f"Error retrieving treasury data from {service_url}: {e}")
            return False
    
    def add_account(self, account_data):
        address = account_data.get('address')
        balance_float = account_data.get('balance_float', 0)
        new_account = {}
        new_account['address'] = address
        new_account['balance'] = balance_float

        account_manager.accounts.append(new_account)
        coin.balance[address] = balance_float

        logging.info(f"Added/Updated account: {address} with balance {balance_float}")

    def add_staking_account(self, data):
        account_manager.staking_accounts.append(data)
        staked_coin.accounts.append(data)
        staking_manager.staking_accounts.append(data)

    def get_init_date(self):
        return coin.init_date

    def validate_chain(self, chain):
        previous_block = chain[0]
        for block in chain[1:]:
            if block['previous_hash'] != previous_block['hash']:
                return False

            block_data = block.copy()
            block_data.pop('hash')
            calculated_hash = self.calculate_block_hash(block_data)

            if block['hash'] != calculated_hash:
                return False

            if not self.validate_stake(block):
                return False

            previous_block = block

        return True

    def add_block(self, block):
        logging.info(f"Attempting to add block with index {block['index']}")
        if self.validate_received_block(block):
            with self.lock:
                if block['index'] == len(self.chain) + 1 and \
                   block['previous_hash'] == self.chain[-1]['hash']:
                    self.chain.append(block)
                    self.block_hashes.add(block['hash'])
                    logging.info(f"Block with index {block['index']} successfully added to the chain.")
                    self.broadcast_block(block)
                    return True
                else:
                    logging.warning(f"Block with index {block['index']} failed to match chain continuity.")
        else:
            logging.warning(f"Block with index {block['index']} failed validation.")
        return False
    
    def broadcast_block(self, new_block):
        block_data = json.dumps(new_block)

        service_prefix = "node"
        services = self.discover_services(service_prefix)

        self.post_data_to_services(services, "blocks/receive_block", block_data)
        
    def validate_foreign_tx(self, address, hash, pub_key, tx, signature):
        logging.debug(f"Validating tx from {address}")

        tx_hash = quantum_utils.quantum_resistant_hash(json.dumps(tx, sort_keys=True))
        if tx_hash != hash:
            logging.error(f"Hash mismatch for transaction with hash: {hash}")
            return None

        if not CUtils.verify_transaction(pub_key, tx, signature):
            logging.error(f"Invalid signature in foreign transaction with hash: {hash} from address: {address}")
            return None

        return True

    def vote_on_local_tx(self, address, hash, pub_key, tx, signature):
        valid_votes = []
        services = ledger.discover_services("node")

        if len(services) == 1 and services[0] == node.url:
            logging.info("Only one validator in the network, bypassing the voting process.")
            valid_votes.append(node.url)

        filtered_services = [s for s in services if f"http://{s}:3400" != node.url]
        for service in filtered_services:
            service_url = f"http://{service}:3400/vote_on_tx"

            try:
                data = {
                    'address': address,
                    'hash': hash,
                    'pub_key': pub_key,
                    'new_tx': tx,
                    'signature': signature
                }
                response = requests.post(service_url, json=data)
                if response.status_code == 200 and response.json().get('message') == 'Tx is valid':
                    valid_votes.append(service)
                    logging.info(f"Validator {service} approved the tx.")
                else:
                    logging.info(f"Validator {service} did not approve the tx.")
            except requests.exceptions.RequestException as e:
                logging.error(f"Error voting on block with {service}: {e}")

        return valid_votes

    def reach_tx_consensus(self, address, hash, pub_key, tx, signature):
        if len(self.validators) == 1:
            logging.info("Automatically reaching consensus with single validator")
            return True

        consensus_reached = self.vote_on_local_tx(address, hash, pub_key, tx, signature)

        if consensus_reached:
            logging.info("Tx consensus reached")
            return True
        else:
            logging.info("Tx consensus not reached")
            return False

    def receive_tx(self, address, hash, pub_key, tx, signature):
        try:
            if not self.validate_foreign_tx(address, hash, pub_key, tx, signature):
                logging.error(f"Received transaction, with hash {hash} from wallet {address}, did not pass verification")
                return False

            return True
        except Exception as e:
            logging.error(f"Error processing received transaction: {str(e)}")
            return False

    def receive_block(self, block):
        try:
            services = ledger.discover_services("node")
            authoritative_node_url, _ = ledger.sync_with_other_nodes(services)

            if authoritative_node_url:
                ledger.sync_account_list_data(authoritative_node_url, account_manager, coin, staked_coin)
                ledger.sync_treasury_data(authoritative_node_url)

            return True
        except Exception as e:
            logging.error(f"Error processing received block: {str(e)}")
            return False

    def broadcast_tx(self, address, hash, pub_key, new_tx, signature):
        data = {
            'address': address,
            'hash': hash,
            'pub_key': pub_key,
            'new_tx': new_tx,
            'signature': signature
        }

        services = ledger.discover_services("node")

        ledger.post_data_to_services(services, "transaction/receive_tx", data)

        return True
    
    def randomly_select_validator(self):
        if not self.validators:
            logging.warning("No validators available.")
            return None

        try:
            if len(self.validators) == 1:
                validator_address = self.validators[0]
                logging.info(f"Only one validator available. Selected validator address: {validator_address}")
                return validator_address

            max_value = len(self.validators) - 1
            random_bytes = QuantumUtils.quantum_random_bytes((max_value.bit_length() + 7) // 8)
            random_int = int.from_bytes(random_bytes, 'big') % (max_value + 1)
            validator_address = self.validators[random_int]
            logging.info(f"Randomly selected validator address: {validator_address}")
            return validator_address
        except Exception as e:
            logging.error(f"Error generating random index: {e}")
            return None

    def trigger_sync_on_all_nodes(self):
        services = ledger.discover_services("node")

        data = {}

        for service in services:
            service_base_url = f"http://{service}:3400"

            if service_base_url == node.url:
                logging.debug(f"Skipping self sync trigger: {service_base_url}")
                continue

            service_url = f"{service_base_url}/trigger_sync"
            logging.debug(f"Attempting to trigger sync on {service_url}")
            try:
                response = requests.post(service_url, json=data)
                if response.status_code == 200:
                    logging.debug(f"Successfully triggered sync on {service_url}")
                else:
                    logging.debug(f"Failed to trigger sync on {service_url}, status code: {response.status_code}")
            except requests.exceptions.RequestException as e:
                logging.error(f"Error triggering sync on {service_url}: {e}")

    def validate_received_block(self, block):
        logging.debug(f"Validating received block with index {block['index']}")
        if not self.validate_block_structure(block):
            logging.error("Block structure validation failed.")
            return False

        if not self.validate_block(block):
            logging.error("Block content validation failed.")
            return False

        if block['index'] != len(self.chain) + 1:
            logging.error(f"Block index {block['index']} does not follow the current chain length.")
            return False

        return True

    def validate_block_structure(self, block):
        logging.debug(f"Checking block structure for block with index {block['index']}")
        required_fields = [
            'index', 'previous_hash', 'timestamp', 'transactions',
            'merkle_root', 'stake_threshold', 'hash', 'miner', 'miner_share',
            'validator', 'validator_share', 'fee'
        ]

        missing_fields = [field for field in required_fields if field not in block]
        if missing_fields:
            logging.error(f"Block missing required fields: {missing_fields}")
            return False

        field_type_issues = False
        for field in required_fields:
            if field in block:
                expected_type = (int if field in ['index', 'timestamp'] else
                                 str if field in ['previous_hash', 'hash', 'miner', 'validator', 'merkle_root'] else
                                 list if field == 'transactions' else
                                 (int, float) if field in ['stake_threshold', 'fee', 'miner_share', 'validator_share'] else
                                 None)
                actual_type = type(block[field])
                if not isinstance(block[field], expected_type):
                    logging.error(f"Field '{field}' type mismatch: expected {expected_type}, got {actual_type}")
                    field_type_issues = True
            else:
                logging.error(f"Field '{field}' is missing from the block.")
                field_type_issues = True

        if field_type_issues:
            logging.error("One or more block field types are incorrect.")
            return False

        logging.debug("Block structure validated successfully.")
        return True
    
    def reach_consensus(self, proposed_block):
        if len(self.validators) == 1:
            logging.info("Automatically reaching consensus with single validator")
            return True

        consensus_reached = self.vote_on_local_block(proposed_block)

        if consensus_reached:
            logging.info("Consensus reached")
            return True
        else:
            logging.info("Consensus not reached")
            return False

    def vote_on_local_block(self, block):
        valid_votes = []
        services = self.discover_services("node")

        if len(services) == 1 and services[0] == node.url:
            logging.info("Only one validator in the network, bypassing the voting process.")
            valid_votes.append(node.url)

        filtered_services = [s for s in services if f"http://{s}:3400" != node.url]
        for service in filtered_services:
            service_url = f"http://{service}:3400/vote_on_block"

            try:
                response = requests.post(service_url, json=block)
                if response.status_code == 200 and response.json().get('message') == 'Block is valid':
                    valid_votes.append(service)
                    logging.info(f"Validator {service} approved the block.")
                else:
                    logging.info(f"Validator {service} did not approve the block.")
            except requests.exceptions.RequestException as e:
                logging.error(f"Error voting on block with {service}: {e}")

        return valid_votes

    def validate_block(self, block):
        logging.debug(f"Validating block with index {block['index']}")
        if block['validator'] not in self.validators:
            logging.error("Block validator is not recognized.")
            return False

        if not self.proof_of_stake(block):
            return False

        unique_addresses = set()
        double_spent_addresses = set()
        for transaction in block['transactions']:
            sender_address = transaction.get('address')
            if sender_address in unique_addresses:
                double_spent_addresses.add(sender_address)
            unique_addresses.add(sender_address)

        if double_spent_addresses:
            logging.error(f"Double spending detected for addresses: {', '.join(double_spent_addresses)}")
            raise DoubleSpendingError("Double spending detected for addresses: " + ', '.join(double_spent_addresses))

        block_string = str(block['index']) + str(block['timestamp']) + str(block['previous_hash']) + str(
            block['transactions']) + str(block['fee']) + str(block['validator']) + str(block['validator_share'])

        generated_hash = hashlib.sha256(block_string.encode()).hexdigest()
        if block['hash'] != generated_hash:
            logging.error("Block hash does not match the generated hash.")
            return False

        if not self.reach_consensus(block):
            logging.error("Failed to reach consensus.")
            return False

        logging.info(f"Block with index {block['index']} passed all validations.")
        return True

    def validate_foreign_block(self, block):
        logging.debug(f"Validating block with index {block['index']}")
        if block['validator'] not in self.validators:
            logging.error("Block validator is not recognized.")
            return False

        if not self.proof_of_stake(block):
            return False

        unique_addresses = set()
        double_spent_addresses = set()
        for transaction in block['transactions']:
            sender_address = transaction.get('address')
            if sender_address in unique_addresses:
                double_spent_addresses.add(sender_address)
            unique_addresses.add(sender_address)

        if double_spent_addresses:
            logging.error(f"Double spending detected for addresses: {', '.join(double_spent_addresses)}")
            raise DoubleSpendingError("Double spending detected for addresses: " + ', '.join(double_spent_addresses))

        block_string = str(block['index']) + str(block['timestamp']) + str(block['previous_hash']) + str(
            block['transactions']) + str(block['fee']) + str(block['validator']) + str(block['validator_share'])

        generated_hash = hashlib.sha256(block_string.encode()).hexdigest()
        if block['hash'] != generated_hash:
            logging.error("Block hash does not match the generated hash.")
            return False

        return True

    def generate_block_hash(self, block):
        transactions_string = json.dumps(block['transactions'], sort_keys=True)

        block_contents = (
            str(block['index']) +
            str(block['timestamp']) +
            str(block['previous_hash']) +
            transactions_string +
            str(block['fee']) +
            str(block['miner']) +
            str(block['miner_share']) +
            str(block['validator']) +
            str(block['validator_share'])
        )

        block_hash = hashlib.sha256(block_contents.encode()).hexdigest()
        return block_hash
    
    def proof_of_stake(self, block):
        logging.info("Starting proof of stake validation.")

        total_stake_weight = sum(node['stake_weight'] if isinstance(node, dict) else node.stake_weight for node in self.verifier.nodes)
        random_number = random.uniform(0, total_stake_weight)
        cumulative_stake_weight = 0

        logging.info(f"Total stake weight: {total_stake_weight}, Random number for validator selection: {random_number}")

        for current_node in self.verifier.nodes:
            node_stake_weight = current_node['stake_weight'] if isinstance(current_node, dict) else current_node.stake_weight
            cumulative_stake_weight += node_stake_weight

            if cumulative_stake_weight > random_number:
                selected_validator_address = current_node['address'] if isinstance(current_node, dict) else current_node.address
                logging.info(f"Selected validator address: {selected_validator_address}, Stake weight: {node_stake_weight}")

                if selected_validator_address == block['validator']:
                    logging.info(f"Validator {selected_validator_address} matches the block's validator.")
                    if node_stake_weight >= block['stake_threshold']:
                        logging.info(f"Validator {selected_validator_address} meets the stake threshold.")
                        return node_stake_weight
                    else:
                        logging.error(f"Validator {selected_validator_address} does not meet the stake threshold.")
                        return 0

        logging.error("No suitable validator found or the selected validator does not meet the stake threshold.")
        return 0

    def add_coin_transaction(self, address: str, amount: int, converted_amount: Union[int, float], fee: Union[int, float], hash: str, pub_key: str, signature: str, sub_type: str, type: str) -> Union[bool, str]:

        cleaned_transaction = {
            'address': address,
            'amount': amount,
            'converted_amount': converted_amount,
            'fee': fee,
            'hash': hash,
            'pub_key': pub_key,
            'signature': signature,
            'sub_type': sub_type,
            'type': type
        }

        if cleaned_transaction['signature']:
            return cleaned_transaction
        
    def select_miner(self) -> dict:
        accounts = staking_manager.staking_agreements

        # If no accounts are available, return None
        if not accounts:
            logging.warning("No staking accounts available for miner selection.")
            return None

        # Calculate the number of withdrawals for each account
        for account in accounts:
            account['withdrawals'] = sum(1 for block in self.chain for transaction in block['transactions']
                                        if 'address' in transaction and transaction.get('address') == account['address'])

        # Select the miner based on weighted selection
        miner = self.weighted_selection(accounts)
        return miner

    def weighted_selection(self, accounts: List[dict]) -> dict:
        # Calculate weights based on the number of withdrawals for each account
        weights = [1 / (acc['withdrawals'] + 1) for acc in accounts]
        total_weight = sum(weights)

        # Normalize the weights to ensure their sum is 1
        normalized_weights = [weight / total_weight for weight in weights]

        # Select an account using the normalized weights
        chosen_account = random.choices(
            accounts, weights=normalized_weights, k=1)[0]
        return chosen_account

    def calculate_fee_distribution(self, total_fee):
        fee_distribution = {}

        validator_percentage = 0.45
        miner_percentage = 0.315
        treasury_percentage = 0.235  # Updated to include the burn percentage

        fee_distribution['validator_share'] = total_fee * validator_percentage
        fee_distribution['miner_share'] = total_fee * miner_percentage
        fee_distribution['treasury_share'] = total_fee * treasury_percentage

        return fee_distribution
    
    def select_validator(self, block):
        selected_validator = self.verifier.select_validator(block)
        return selected_validator if selected_validator else None

    def validate_selected_validator(self, selected_validator, block):
        if selected_validator.malicious or selected_validator not in verifier.nodes:
            return False

        if selected_validator.address == block['validator'] and \
                selected_validator.stake_weight >= block['stake_threshold']:
            return True

        return False

    def add_malicious_validator(self, validator_address):
        for node in verifier.nodes:
            if node.address == validator_address:
                node.malicious = True
                break

    def create_new_block(self, transactions):
        latest_block = self.chain[-1]
        block_index = latest_block['index'] + 1
        timestamp = int(datetime.now(timezone.utc).timestamp())
        previous_hash = latest_block['hash']
        stake_threshold = node.stake_weight

        processed_transactions, total_fee = self.process_transactions(transactions)
        block_fee = self.coin.mint_for_block_fee(total_fee)
        fee_distribution = self.calculate_fee_distribution(block_fee)
        miner = self.select_miner()

        if miner is None:
            logging.error("Failed to select a miner. Aborting block creation.")
            return

        miner_address = miner['address']

        block = {
            'index': block_index,
            'timestamp': timestamp,
            'previous_hash': previous_hash,
            'transactions': processed_transactions,
            'stake_threshold': stake_threshold,
            'fee': block_fee
        }

        validator_node = self.select_validator(block)
        if validator_node:
            validator_address = validator_node['address'] if isinstance(validator_node, dict) else getattr(validator_node, 'address', node.address)
        else:
            validator_address = node.address

        for transaction in transactions:
            merkle_tree.add_transaction(str(transaction))

        merkle_tree.create_tree()
        merkle_root = merkle_tree.get_merkle_root()

        self.coin.credit(validator_address, fee_distribution['validator_share'])
        self.coin.credit(miner_address, fee_distribution['miner_share'])
        self.coin.credit(self.coin.treasury_address, fee_distribution['treasury_share'])

        new_block = {
            'index': block_index,
            'timestamp': timestamp,
            'previous_hash': previous_hash,
            'transactions': processed_transactions,
            'merkle_root': merkle_root,
            'stake_threshold': stake_threshold,
            'fee': block_fee,
            'miner': miner_address,
            'miner_share': fee_distribution['miner_share'],
            'validator': validator_address,
            'validator_share': fee_distribution['validator_share'],
            'treasury_share': fee_distribution['treasury_share']
        }

        logging.info(f"constructed block: {new_block}")

        block_string = str(new_block['index']) + str(new_block['timestamp']) + str(new_block['previous_hash']) + str(
            new_block['transactions']) + str(new_block['fee']) + str(new_block['validator']) + str(new_block['validator_share'])

        # Generate block hash
        block_hash = hashlib.sha256(block_string.encode()).hexdigest()

        new_block['hash'] = block_hash

        if self.add_block(new_block):
            self.transactions.cleaned_transactions = []
            logging.info(f"Successfully mined new block: {new_block}")
            return new_block
        else:
            logging.debug(f"Issue mining block: {new_block}")

    def process_transactions(self, transactions):
        processed_transactions = []
        total_fee = 0.0

        for transaction in transactions:
            transaction_type = transaction.get('sub_type')

            if transaction_type == 'r':
                processed_transaction = self.handle_staking_transaction(transaction)
            elif transaction_type == 'o':
                processed_transaction = self.handle_unstaking_transaction(transaction)
            elif transaction_type == 'k':
                processed_transaction = self.handle_transfer_transaction(transaction)
            elif transaction_type == 'w':
                processed_transaction = self.handle_pomc_whitelist_transaction(transaction)
            elif transaction_type in ['h', 'x', 'm', 'pr']:
                processed_transaction = self.handle_fee_payment_transaction(transaction)
            else:
                processed_transaction = self.handle_default_transaction(transaction)

            if processed_transaction:
                processed_transactions.append(processed_transaction)
                total_fee += processed_transaction.get('fee', 0.0)

        return processed_transactions, total_fee

    def handle_staking_transaction(self, transaction):
        try:
            fee_calculator = DynamicFeeCalculator()
            sender_address = transaction['address']
            staking_amount = transaction['amount']
            min_term = transaction['min_term']
            pub_key = transaction['pub_key']
            signature = transaction.get('signature')

            transaction_data = {
                'address': sender_address,
                'amount': staking_amount,
                'min_term': min_term,
                'pub_key': pub_key,
                'type': transaction['type']
            }

            transaction_fee, transaction_hash = dynamic_fee_calculator.get_base_dynamic_fee(transaction_data, transaction['type'])

            if not all([sender_address, staking_amount, min_term, pub_key, signature]):
                logging.error("Missing fields in staking transaction")
                return None

            sender_balance_info = self.wallet.get_account_balance(sender_address)
            if not sender_balance_info or sender_balance_info['balance_float'] < staking_amount + transaction_fee:
                logging.error("Insufficient balance for staking")
                return None

            transaction_for_verification = {
                'address': sender_address,
                'amount': staking_amount,
                'fee': transaction_fee,
                'hash': transaction_hash,
                'min_term': min_term,
                'pub_key': pub_key,
                'type': transaction['type']
            }

            if not crypto_utils.verify_transaction(transaction['pub_key'], transaction_for_verification, transaction['signature']):
                logging.error("Invalid signature in staking transaction")
                return None

            self.wallet.stake_coins(sender_address, staking_amount, min_term)

            processed_transaction = {
                'address': sender_address,
                'amount': staking_amount,
                'fee': transaction_fee,
                'hash': transaction_hash,
                'min_term': min_term,
                'stake_threshold': 3,
                'type': transaction['type'],
                'when': str(datetime.now(timezone.utc))
            }

            logging.info(f"Processed staking transaction for {sender_address}")
            return processed_transaction

        except Exception as e:
            logging.error(f"Error processing staking transaction: {e}")
            return None

    def handle_unstaking_transaction(self, transaction):
        try:
            fee_calculator = DynamicFeeCalculator()
            sender_address = transaction['address']
            contract_id = transaction['contract_id']
            pub_key = transaction['pub_key']
            signature = transaction.get('signature')

            transaction_data = {
                'address': sender_address,
                'contract_id': contract_id,
                'pub_key': pub_key,
                'type': transaction['type']
            }

            transaction_fee, transaction_hash = dynamic_fee_calculator.get_base_dynamic_fee(transaction_data, transaction['type'])

            if not all([sender_address, contract_id, pub_key, signature]):
                logging.error("Missing fields in unstaking transaction")
                return None

            sender_balance_info = self.wallet.get_account_balance(sender_address)
            if not sender_balance_info or sender_balance_info['balance_float'] < transaction_fee:
                logging.error("Insufficient balance for unstaking")
                return None

            transaction_for_verification = {
                'address': sender_address,
                'contract_id': contract_id,
                'fee': transaction_fee,
                'hash': transaction_hash,
                'pub_key': pub_key,
                'type': transaction['type']
            }

            if not crypto_utils.verify_transaction(transaction['pub_key'], transaction_for_verification, transaction['signature']):
                logging.error("Invalid signature in unstaking transaction")
                return None

            self.wallet.unstake_coins(sender_address, contract_id)

            processed_transaction = {
                'address': sender_address,
                'contract_id': contract_id,
                'fee': transaction_fee,
                'hash': transaction_hash,
                'stake_threshold': 2,
                'type': transaction['type'],
                'when': str(datetime.now(timezone.utc))
            }

            logging.info(f"Processed unstaking transaction for {sender_address}")
            return processed_transaction

        except Exception as e:
            logging.error(f"Error processing unstaking transaction: {e}")
            return None

    def handle_transfer_transaction(self, transaction):
        try:
            fee_calculator = DynamicFeeCalculator()
            sender_address = transaction['sender']
            recipient_address = transaction['recipient']
            transfer_amount = transaction['amount']
            pub_key = transaction['pub_key']
            signature = transaction.get('signature')

            transaction_data = {
                'sender': sender_address,
                'recipient': recipient_address,
                'amount': transfer_amount,
                'pub_key': pub_key,
                'type': transaction['type']
            }

            transaction_fee, transaction_hash = dynamic_fee_calculator.get_base_dynamic_fee(transaction_data, transaction['type'])

            if not all([sender_address, recipient_address, transfer_amount, pub_key, signature]):
                logging.error("Missing fields in transfer transaction")
                return None

            sender_balance_info = self.wallet.get_account_balance(sender_address)
            if not sender_balance_info or sender_balance_info['balance_float'] < transfer_amount + transaction_fee:
                logging.error("Insufficient balance for transfer")
                return None

            transaction_for_verification = {
                'sender': sender_address,
                'recipient': recipient_address,
                'amount': transfer_amount,
                'fee': transaction_fee,
                'hash': transaction_hash,
                'pub_key': pub_key,
                'type': transaction['type']
            }

            if not crypto_utils.verify_transaction(transaction['pub_key'], transaction_for_verification, transaction['signature']):
                logging.error("Invalid signature in transfer transaction")
                return None

            self.wallet.transfer(sender_address, recipient_address, transfer_amount)

            processed_transaction = {
                'sender': sender_address,
                'recipient': recipient_address,
                'amount': transfer_amount,
                'fee': transaction_fee,
                'hash': transaction_hash,
                'stake_threshold': 2,
                'type': transaction['type'],
                'when': str(datetime.now(timezone.utc))
            }

            logging.info(f"Processed transfer transaction from {sender_address} to {recipient_address}")
            return processed_transaction

        except Exception as e:
            logging.error(f"Error processing transfer transaction: {e}")
            return None
    
    def handle_pomc_whitelist_transaction(self, transaction):
        try:
            
            sender_address = transaction['sender']
            pub_key = transaction['pub_key']
            signature = transaction.get('signature')

            processed_transaction = {
                'fee': transaction['fee'],
                'hash': transaction['hash'],
                'sender': transaction['sender'],
                'sub_type': transaction['sub_type'],
                'stake_threshold': 2,
                'type': transaction['type'],
                'when': transaction['when']
            }

            logging.info(f"Processed transfer transaction from {sender_address} to join pOMC whitelist")
            return processed_transaction

        except Exception as e:
            logging.error(f"Error processing transfer transaction: {e}")
            return None

    def handle_fee_payment_transaction(self, transaction):
        try:
            fee_calculator = DynamicFeeCalculator()
            payer_address = transaction['from']
            fee_amount = transaction['fee']
            pub_key = transaction['pub_key']
            signature = transaction.get('signature')

            transaction_data = {
                'from': payer_address,
                'fee': fee_amount,
                'pub_key': pub_key,
                'type': transaction['type']
            }

            calculated_fee, transaction_hash = dynamic_fee_calculator.get_base_dynamic_fee(transaction_data, transaction['type'])

            if not all([payer_address, fee_amount, pub_key, signature]):
                logging.error("Missing fields in fee payment transaction")
                return None

            payer_balance_info = self.wallet.get_account_balance(payer_address)
            if not payer_balance_info or payer_balance_info['balance_float'] < fee_amount + calculated_fee:
                logging.error("Insufficient balance for fee payment")
                return None

            transaction_for_verification = {
                'from': payer_address,
                'fee': calculated_fee,
                'hash': transaction_hash,
                'pub_key': pub_key,
                'type': transaction['type']
            }

            if not crypto_utils.verify_transaction(transaction['pub_key'], transaction_for_verification, transaction['signature']):
                logging.error("Invalid signature in fee payment transaction")
                return None

            self.wallet.pay_fee(payer_address, fee_amount)

            processed_transaction = {
                'from': payer_address,
                'fee': calculated_fee,
                'hash': transaction_hash,
                'stake_threshold': 2,
                'type': transaction['type'],
                'when': str(datetime.now(timezone.utc))
            }

            logging.info(f"Processed fee payment transaction from {payer_address}")
            return processed_transaction

        except Exception as e:
            logging.error(f"Error processing fee payment transaction A1: {e}")
            return None

    def handle_default_transaction(self, transaction):
        try:
            fee_calculator = DynamicFeeCalculator()
            payer_address = transaction['address']

            transaction_data = {
                'from': payer_address,
                'type': 'e'
            }

            calculated_fee, transaction_hash = dynamic_fee_calculator.get_base_dynamic_fee(transaction_data, transaction['type'])

            processed_transaction = {
                'from': payer_address,
                'fee': 0.0,
                'hash': transaction_hash,
                'stake_threshold': 1,
                'type': 'e',
                'when': str(datetime.now(timezone.utc))
            }

            logging.info(f"Processed fee payment transaction from {payer_address}")
            return processed_transaction

        except Exception as e:
            logging.error(f"Error processing fee payment transaction A2: {e}")
            return None

    def clean_and_verify_transactions(self):
        new_transactions = self.transactions.batch_pending_transactions()
        cleaned_transactions = []

        for transaction in new_transactions:
            try:
                if transaction['type'] == 'c' and transaction['sub_type'] == 'c':
                    self.process_account_creation_transaction(transaction)
                elif transaction['type'] == 'c' and transaction['sub_type'] == 'w':
                    self.process_add_account_to_whitelist_transaction(transaction)
                elif transaction['type'] == 'o':
                    self.process_non_f_transaction(transaction)
                elif transaction['type'] == 'e':
                    self.process_f_transaction(transaction)
            except Exception as e:
                logging.error(f"Error processing transaction {transaction['type']}: {e}")

        return cleaned_transactions
    
    def process_account_creation_transaction(self, transaction):
        # Verify that the transaction is of the correct type
        if transaction['type'] != 'c':
            logging.error(f"Invalid transaction type for account creation: {transaction['type']}")
            return

        try:
            # Extract necessary fields from the transaction
            address = transaction['address']
            balance = transaction['balance']
            type = transaction['type']
            timestamp = ['timestamp']
            withdrawals = transaction['withdrawals']

            # Validate the transaction data
            if not all([address, type]):
                logging.error("Incomplete account creation transaction data")
                return

            # Check if the address already exists in the blockchain wallet
            # if any(acc['address'] == address for acc in account_manager.accounts):
            #     logging.info(f"Account already exists: {address}")
            #     return

            # # Create and append the new account to the wallet
            # new_account = {
            #     'address': address,
            #     'balance': balance,
            #     'withdrawals': withdrawals
            # }
            # account_manager.accounts.append(new_account)

            # Create a cleaned version of the transaction for the blockchain
            cleaned_transaction = {
                'address': address,
                'hash': transaction.get('hash'),
                'pub_key': transaction['pub_key'],
                'signature': transaction['signature'],
                'sub_type': 'c',
                'type': transaction['type'],
                'withdrawals': withdrawals
            }

            # Append the cleaned transaction to the list of processed transactions
            self.transactions.cleaned_transactions.append(cleaned_transaction)
            logging.info(f"Processed account creation transaction for {address}")

        except Exception as e:
            logging.error(f"Error processing account creation transaction A2: {e}")
            
    def process_add_account_to_whitelist_transaction(self, transaction):
        # Verify that the transaction is of the correct type
        if transaction['type'] != 'c':
            logging.error(f"Invalid transaction type to add account to whitelist: {transaction['type']}")
            return

        try:
            result = {
                'fee': transaction['fee'],
                'hash': transaction['hash'],
                'pub_key': transaction['pub_key'],
                'sender': transaction['sender'],
                'signature': transaction['signature'],
                'sub_type': transaction['sub_type'],
                'type': transaction['type'],
                'when': transaction['when']
            }
            # Extract necessary fields from the transaction
            address = transaction['sender']
            hash = transaction['hash']
            type = transaction['type']

            # Validate the transaction data
            if not all([address, hash, type]):
                logging.error("Incomplete account creation transaction data")
                return

            # Create a cleaned version of the transaction for the blockchain
            cleaned_transaction = {
                'fee': transaction['fee'],
                'hash': transaction['hash'],
                'pub_key': transaction['pub_key'],
                'sender': transaction['sender'],
                'signature': transaction['signature'],
                'sub_type': transaction['sub_type'],
                'type': transaction['type'],
                'when': transaction['when']
            }

            # Append the cleaned transaction to the list of processed transactions
            self.transactions.cleaned_transactions.append(cleaned_transaction)
            logging.info(f"Processed join whitelist transaction for {address}")

        except Exception as e:
            logging.error(f"Error processing join whiteist transaction A2: {e}")

    def process_f_transaction(self, transaction):
        try:
            transaction_type = transaction.get('type')
            sender_address = transaction.get('address')
            transaction_fee = transaction.get('fee', 0.0)

            if not sender_address or transaction_fee is None:
                logging.error("Invalid transaction format.")
                return None

            cleaned_transaction = None

            if transaction_type == 'e':
                sub_tx_type = transaction.get('sub_type')

                if sub_tx_type == 'p':
                    amount = transaction.get('amount')
                    recipient_address = transaction.get('recipient')

                    if crypto_utils.verify_transaction(sender_address, recipient_address, amount):
                        self.wallet.transfer(sender_address, recipient_address, amount)

                elif sub_tx_type == 'r':
                    amount = transaction.get('amount')
                    min_term = transaction.get('min_term')

                    self.wallet.stake_coins(sender_address, amount, min_term)

                elif sub_tx_type == 'z':
                    contract_id = transaction.get('contract_id')

                    self.wallet.unstake_coins(sender_address, contract_id)

            if cleaned_transaction:
                self.transactions.cleaned_transactions.append(cleaned_transaction)
                logging.info(f"Processed transaction of type {transaction_type} for {sender_address}")
                return cleaned_transaction
            else:
                logging.warning(f"Unhandled or failed transaction type/subtype: {transaction_type}/{sub_tx_type}")
                return None

        except Exception as e:
            logging.error(f"Error processing account creation transaction A2: {e}")

    def process_non_f_transaction(self, transaction):
        try:
            transaction_type = transaction.get('type')
            sender_address = transaction.get('address')
            transaction_fee = transaction.get('fee', 0.0)

            if not sender_address or transaction_fee is None:
                logging.error("Invalid transaction format.")
                return None

            cleaned_transaction = None

            if transaction_type == 'o':
                sub_tx_type = transaction.get('sub_type')

                if sub_tx_type == 's':
                    self.handle_post_transaction(transaction)

                elif sub_tx_type == 'j':
                    refined_transaction = self.handle_add_profile_transaction(transaction)
                    if refined_transaction:
                        cleaned_transaction = {
                            'address': transaction['address'],
                            'avi': transaction['avi'],
                            'clubs': transaction['clubs'],
                            'fee': transaction['fee'],
                            'handle': transaction['handle'],
                            'hash': transaction['hash'],
                            'intro': transaction['intro'],
                            'joined': transaction['joined'],
                            'name': transaction['name'],
                            'profile_id': transaction['profile_id'],
                            'profile_type': transaction['profile_type'],
                            'pt': transaction['pt'],
                            'pt_id': transaction['pt_id'],
                            'pub_key': transaction['pub_key'],
                            'signature': transaction['signature'],
                            'sub_type': transaction['sub_type'],
                            'tags': transaction['tags'],
                            'type': transaction['type'],
                            'version': transaction['version']
                        }

            if cleaned_transaction:
                transactions.cleaned_transactions.append(cleaned_transaction)
                logging.info(f"Processed transaction of type {transaction_type} for {sender_address}")
                return cleaned_transaction
            else:
                logging.warning(f"Unhandled or failed transaction type/subtype: {transaction_type}/{sub_tx_type}")
                return None

        except Exception as e:
            logging.error(f"Error processing transaction: {e}")
            return None

    def start_mining(self):
        self.create_new_block(self.transactions.cleaned_transactions)

    def check_pending_transactions(self):
        self.clean_and_verify_transactions()
        self.start_mining()

    def get_latest_block(self):
        return self.chain[-1]

    def main_loop(self):
        while True:
            self.start_mining()
            self.consume_blocks()

    def consume_blocks(self):
        for message in self.consumer:
            block_data = message.value.decode('utf-8')
            block = json.loads(block_data)
            self.receive_block(block)
 
class DoubleSpendingError(Exception):
    def __init__(self, message="Double spending detected"):
        self.message = message
        super().__init__(self.message)
 
class Ledger:
    def __init__(self, coin, wallet, transactions, verifier):
        self.coin = coin
        self.wallet = wallet
        self.transactions = transactions
        self.verifier = verifier

        self.chain = []
        self.block_hashes = set()
        self.lock = threading.Lock()
        logging.basicConfig(level=logging.DEBUG)
        
        self.validators = []
        
        mining_thread = threading.Thread(target=self.mine_new_block_periodically)
        mining_thread.daemon = True
        mining_thread.start()

    @staticmethod
    def serialize_and_create_single_hash(cls):
        if not isinstance(cls, type):
            raise TypeError(f"Expected class type, got {type(cls)}")

        try:
            class_dict = {
                'attributes': {key: value for key, value in cls.__dict__.items() if not callable(value) and not key.startswith('__')},
                'methods': {
                    key: (value.__func__.__code__.co_code if isinstance(value, staticmethod) else value.__code__.co_code)
                    for key, value in cls.__dict__.items() if callable(value)
                }
            }
            class_serialized = json.dumps(class_dict, sort_keys=True, default=str)
            logging.debug(f"Serialized class {cls.__name__}: {class_serialized}")
            class_hash = hashlib.sha256(class_serialized.encode()).hexdigest()
            return class_hash
        except Exception as e:
            logging.error(f"Error serializing class {cls.__name__}: {e}")
            raise

    @staticmethod
    def verify_class_hashes():
        """
        This function retrieves the stored hashes of classes from the public API and compares them
        with the hashes of the current local classes to ensure integrity.
        """
        try:
            response = requests.get(HASH_API_URL)
            if response.status_code != 200:
                raise ValueError("Failed to fetch class hashes from public API.")

            stored_hashes = response.json()
        except Exception as e:
            logging.error(f"Error fetching class hashes from public API: {e}")
            raise

        classes_to_verify = {
            'coin': OMC,
            'quantum_utils': QuantumUtils,
            'transactions': Transactions,
            'permission_manager': PermissionMngr,
            'precursor_coin': pOMC,
            'verifier': Verifier,
            'crypto_utils': CUtils,
            'fee_calculator': DynamicFeeCalculator,
            'ledger': Ledger,
            'treasury': OMCTreasury
        }

        for class_name, cls in classes_to_verify.items():
            stored_hash = stored_hashes.get(class_name)
            if not stored_hash:
                logging.error(f"Stored hash for class {class_name} not found in the public API response.")
                raise ValueError(f"Stored hash for class {class_name} not found.")

            local_hash = Ledger.serialize_and_create_single_hash(cls)
            if stored_hash != local_hash:
                logging.error(f"Hash mismatch for class {class_name}. Possible tampering detected.")
                raise ValueError(f"Hash mismatch for class {class_name}. Possible tampering detected.")

        logging.info("All class hashes verified successfully. No tampering detected.")
        return True

    def initialize_node(self):
        service_prefix = "node"
        services = self.discover_services(service_prefix)
        if services:
            self.ping_services(services, "check_nodes", node.url)

        node.steward = os.getenv('STEWARD_ADDRESS')
        if not node.steward:
            raise ValueError("Steward address not provided. Set the STEWARD_ADDRESS environment variable.")

        self.update_node_state(node)
        self.check_chain_length_and_sync(services)
        self.update_validators()
        self.broadcast_node_data(node)

    def discover_services(self, prefix):
        discovered_services = []
        max_range = 10

        for i in range(1, max_range):
            service_name = f"{prefix}{i}.omne"
            try:
                service_address = socket.gethostbyname(service_name)

                if service_address != node.url:
                    discovered_services.append(service_name)
                    logging.debug(f"Discovered service: {service_name}")

            except socket.gaierror:
                continue

        if not discovered_services:
            logging.warning("No services were discovered.")

        return discovered_services

    def ping_services(self, services, endpoint, current_node_url):
        headers = {"Authorization": f"Bearer {AUTH_TOKEN}"}

        for service in services:
            service_base_url = f"http://{service}:3400"
            service_url = f"{service_base_url}/{endpoint}"

            if service_base_url == current_node_url:
                logging.debug(f"Skipping self ping: {service_base_url}")
                continue

            logging.debug(f"Attempting to ping {service_url}")
            try:
                response = requests.get(service_url, headers=headers)
                if response.status_code == 200:
                    logging.debug(f"Successfully pinged {service_url}")
                    received_nodes = response.json().get('nodes', [])
                    for received_node in received_nodes:
                        if not any(node['address'] == received_node['address'] for node in self.verifier.nodes):
                            verifier.nodes.append(received_node)
                            verifier.nodes.append(received_node)
                            self.validators.append(received_node['address'])
                            logging.debug(f"Added new node: {received_node['address']}")
                else:
                    logging.debug(f"Failed to ping {service_url}, status code: {response.status_code}")

            except requests.exceptions.RequestException as e:
                logging.error(f"Error pinging {service_url}: {e}")

    def post_data_to_services(self, services, endpoint, data):
        headers = {"Authorization": f"Bearer {AUTH_TOKEN}"}

        for service in services:
            service_base_url = f"http://{service}:3400"
            service_url = f"{service_base_url}/{endpoint}"

            if service_base_url == node.url:
                logging.debug(f"Skipping self post: {service_url}")
                continue

            logging.debug(f"Attempting to post data to {service_url}")
            try:
                response = requests.post(service_url, json=data, headers=headers)
                if response.status_code == 200:
                    logging.debug(f"Successfully posted data to {service_url}")
                else:
                    logging.debug(f"Failed to post data to {service_url}, status code: {response.status_code}")

            except requests.exceptions.RequestException as e:
                logging.error(f"Error posting data to {service_url}: {e}")

    def broadcast_self_info(self):
        if not node or not node.address or not node.url:
            logging.error("Node information is incomplete or incorrect. Cannot broadcast.")
            return

        node_info = node.to_dict()
        logging.info(f"Broadcasting self node information: {node_info}")

        services = self.discover_services("node")
        if not services:
            logging.warning("No other services discovered for broadcasting. Broadcast aborted.")
            return

        services = [service for service in services if service != node.url]
        if not services:
            logging.warning("No external services discovered for broadcasting. Broadcast aborted.")
            return

        self.post_data_to_services(services, "receive_node_info", node_info)
        logging.info("Successfully broadcasted self node information to other services.")

    def update_validators(self):
        services = self.discover_services("node")
        for service in services:
            service_base_url = f"http://{service}:3400"
            service_url = f"{service_base_url}/node_info"

            if service_base_url == node.url:
                continue

            try:
                response = requests.get(service_url)
                if response.status_code == 200:
                    node_data = response.json()
                    if node_data['address'] not in self.validators:
                        self.validators.append(node_data['address'])
            except requests.exceptions.RequestException as e:
                logging.error(f"Failed to retrieve node information from {service}: {e}")

    def sync_with_other_nodes(self, services):
        my_chain_length = len(self.chain)
        synchronized_chain = None
        authoritative_node_url = None

        for service in services:
            service_base_url = f"http://{service}:3400"
            service_url = f"{service_base_url}/get_chain"

            if service_base_url == node.url:
                continue

            try:
                response = requests.get(service_url)
                if response.status_code == 200:
                    other_chain = response.json()["chain"]
                    if len(other_chain) > my_chain_length:
                        my_chain_length = len(other_chain)
                        synchronized_chain = other_chain
                        authoritative_node_url = service_base_url
            except requests.exceptions.RequestException as e:
                logging.error(f"Error while trying to sync with {service_url}: {e}")

        if synchronized_chain:
            self.chain = synchronized_chain

        return authoritative_node_url, synchronized_chain

    def broadcast_node_data(self, node):
        headers = {"Authorization": f"Bearer {AUTH_TOKEN}"}
        node_data_complete = {
            'address': node.address,
            'public_key': node.public_key,
            'url': node.url,
            'stake_weight': node.stake_weight,
            'version': node.version,
            'steward': node.steward
        }

        services = self.discover_services("node")

        for service in services:
            service_base_url = f"http://{service}:3400"
            service_url = f"{service_base_url}/receive_node_data"

            if service_base_url == node.url:
                continue

            logging.debug(f"Broadcasting node data to {service_url}")
            try:
                response = requests.post(service_url, json=node_data_complete, headers=headers)
                if response.status_code == 201:
                    logging.debug(f"Successfully broadcasted new node data to {service_url}")
                elif response.status_code == 200:
                    logging.debug(f"Node data already exists on {service_url}")
                else:
                    logging.warning(f"Failed to broadcast node data to {service_url}, status code: {response.status_code}")
            except requests.exceptions.RequestException as e:
                logging.error(f"Error broadcasting node data to {service_url}: {e}")
                
    def update_accounts(self, address, balance):
        new_account = {
            'address': address,
            'balance': balance
        }

        service_prefix = "node"
        services = self.discover_services(service_prefix)

        filtered_services = [s for s in services if f"http://{s}:3400" != node.url]
        self.post_data_to_services(filtered_services, "propagate_account", new_account)

    def update_node_state(self, new_node):
        if new_node not in self.verifier.nodes:
            verifier.nodes.append(new_node)
            self.validators.append(new_node.address)
            logging.info(f"Node {new_node.address} added to local state.")

    def mine_new_block_periodically(self, interval=9):
        while True:
            self.check_for_mining_opportunity()
            time.sleep(interval * 60)

    def check_for_mining_opportunity(self):
        num_transactions = len(transactions.transactions)
        if num_transactions >= 1:
            self.check_pending_transactions()
        elif 4 <= num_transactions < 15 and self.is_time_to_mine():
            self.check_pending_transactions()

    def is_time_to_mine(self):
        latest_block = self.chain[-1]
        block_timestamp = datetime.strptime(latest_block['timestamp'], "%Y-%m-%d %H:%M:%S.%f%z")
        current_timestamp = datetime.now(timezone.utc)
        
        mining_interval = 9 * 60  # Fixed interval of 9 minutes
        return (current_timestamp - block_timestamp).total_seconds() >= mining_interval

    def create_new_wallet(self):
        mnemonic = crypto_utils.generate_mnemonic()
        account = self.wallet.account_manager.generate_account_from_mnemonic(mnemonic)
        
        # Add the new address with a balance of zero to the self.balance dictionary
        with coin.balance_lock:
            coin.balance[account['address']] = 0.0

        wallet_creation_transaction = {
            'address': account['address'],
            'balance': 0.0,
            'withdrawals': 0,
            'type': 'c'
        }

        cleaned_transaction = {
            'address': wallet_creation_transaction['address'],
            'balance': wallet_creation_transaction['balance'],
            'pub_key': account['pub_key'],
            'sub_type': 'c',
            'type': wallet_creation_transaction['type'],
            'withdrawals': wallet_creation_transaction['withdrawals']
        }

        initial_balance = 0.0

        account_dict = {
            'address': wallet_creation_transaction['address'],
            'balance': initial_balance,
        }

        sendable_transaction = {
            'mnemonic': mnemonic,
            'private_key': base64.b64encode(account['private_key']).decode('utf-8'),
            'pub_key': account['pub_key'],
            'address': account['address'],
        }

        return sendable_transaction

    def create_new_wallet_from_seed(self, seed):
        account = self.wallet.account_manager.generate_account_from_mnemonic(seed)

        wallet_creation_transaction = {
            'address': account['address'],
            'balance': 0.0,
            'withdrawals': 0,
            'type': 'c'
        }

        cleaned_transaction = {
            'address': wallet_creation_transaction['address'],
            'balance': wallet_creation_transaction['balance'],
            'pub_key': account['pub_key'],
            'type': wallet_creation_transaction['type'],
            'withdrawals': wallet_creation_transaction['withdrawals']
        }

        sendable_transaction = {
            'mnemonic': account['mnemonic'],
            'private_key': base64.b64encode(account['private_key']).decode('utf-8'),
            'pub_key': account['pub_key'],
            'address': account['address'],
        }

        private_key_bytes = base64.b64decode(sendable_transaction['private_key'])
        signature = crypto_utils.sign_transaction(private_key_bytes, wallet_creation_transaction)

        cleaned_transaction['signature'] = signature

        self.transactions.transactions.append(cleaned_transaction)
        self.update_accounts(wallet_creation_transaction['address'], wallet_creation_transaction['balance'])

        return sendable_transaction

    def get_chain_length(self):
        return len(self.chain) if hasattr(self, "blockchain") else 0

    def check_chain_length_and_sync(self, services):
        service_prefix = "node"
        services = self.discover_services(service_prefix)

        authoritative_node_url, synchronized_chain = self.sync_with_other_nodes(services)

        self.sync_account_list_data(authoritative_node_url, account_manager, coin, staked_coin)
        self.sync_treasury_data(authoritative_node_url)

        self.ping_services(services, "check_nodes", node.url)

        if synchronized_chain is not None:
            return {
                "chain": synchronized_chain,
                "message": "Chain synchronized successfully"
            }
        else:
            return {
                "chain": self.chain,
                "message": "Chain synchronization failed"
            }

    def sync_account_list_data(self, authoritative_node_url, account_manager, coin, staked_coin):
        if not authoritative_node_url:
            logging.error("No authoritative node URL provided for account list data synchronization.")
            return

        service_url = f"{authoritative_node_url}/retrieve_accounts"

        try:
            response = requests.get(service_url)
            if response.status_code == 200:
                data = response.json()

                main_accounts = data.get('data', [])
                for new_acc in main_accounts:
                    if 'address' in new_acc and 'balance' in new_acc:
                        account = next((acc for acc in account_manager.accounts if acc['address'] == new_acc['address']), None)
                        if account:
                            account['balance'] = new_acc['balance']
                            coin.balance[new_acc['address']] = new_acc['balance']
                            logging.info(f"Updated main account {new_acc['address']} for {coin.name}.")
                        else:
                            account_manager.accounts.append(new_acc)
                            coin.balance[new_acc['address']] = new_acc['balance']
                            logging.info(f"Added new main account {new_acc['address']} for {coin.name}.")

                precursor_accounts = data.get('precursor_accounts', [])
                for new_acc in precursor_accounts:
                    if 'address' in new_acc and 'balance' in new_acc:
                        account = next((acc for acc in account_manager.precursor_accounts if acc['address'] == new_acc['address']), None)
                        if account:
                            account['balance'] = new_acc['balance']
                            coin.balance[new_acc['address']] = new_acc['balance']
                            logging.info(f"Updated precursor account {new_acc['address']} for {coin.name}.")
                        else:
                            account_manager.precursor_accounts.append(new_acc)
                            coin.balance[new_acc['address']] = new_acc['balance']
                            logging.info(f"Added new precursor account {new_acc['address']} for {coin.name}.")

                staking_accounts = data.get('staking_accounts', [])
                for new_acc in staking_accounts:
                    if 'address' in new_acc and 'min_term' in new_acc:
                        account = next((acc for acc in staking_manager.staking_agreements if acc['address'] == new_acc['address']), None)
                        if account:
                            account['amount'] = new_acc['amount']
                            account['withdrawals'] = new_acc['withdrawals']
                            staked_coin.balance[new_acc['address']] = new_acc['amount']
                            logging.info(f"Updated staking account {new_acc['address']} for {staked_coin.name}.")
                        else:
                            staked_coin.accounts.append(new_acc)
                            staking_manager.staking_agreements.append(new_acc)
                            staked_coin.balance[new_acc['address']] = new_acc['amount']
                            logging.info(f"Added new staking account {new_acc['address']} for {staked_coin.name}.")

                self.validators = data.get('validators', [])
                if node.address not in self.validators:
                    self.validators.append(node.address)

                notification_data = {"message": "Data updated from authoritative node"}
                self.post_data_to_services(self.discover_services("node"), "notify_data_update", notification_data)

                logging.warning(f"Synchronized account list data with the authoritative node: {authoritative_node_url}")
            else:
                logging.error(f"Failed to retrieve account data from {service_url}, status code: {response.status_code}")
        except requests.RequestException as e:
            logging.error(f"Error retrieving account data from {service_url}: {e}")
    
    def sync_treasury_data(self, authoritative_node_url):
        if not authoritative_node_url:
            logging.error("No authoritative node URL provided for treasury data synchronization.")
            return False

        service_url = f"{authoritative_node_url}/retrieve_treasury_data"

        try:
            response = requests.get(service_url)
            if response.status_code == 200:
                response_data = response.json()
                if 'treasury_address' in response_data:
                    treasury.update_treasury_data(response_data['treasury_address'])
                    logging.warning("Synchronized treasury data with the authoritative node: %s", authoritative_node_url)
                    return True
                else:
                    logging.error(f"No treasury account data found in the response from {service_url}")
                    return False
            else:
                logging.error(f"Failed to retrieve treasury data from {service_url}, status code: {response.status_code}")
                return False
        except requests.RequestException as e:
            logging.error(f"Error retrieving treasury data from {service_url}: {e}")
            return False
    
    def add_account(self, account_data):
        address = account_data.get('address')
        balance_float = account_data.get('balance_float', 0)
        new_account = {}
        new_account['address'] = address
        new_account['balance'] = balance_float

        account_manager.accounts.append(new_account)
        coin.balance[address] = balance_float

        logging.info(f"Added/Updated account: {address} with balance {balance_float}")

    def add_staking_account(self, data):
        account_manager.staking_accounts.append(data)
        staked_coin.accounts.append(data)
        staking_manager.staking_accounts.append(data)

    def get_init_date(self):
        return coin.init_date

    def validate_chain(self, chain):
        previous_block = chain[0]
        for block in chain[1:]:
            if block['previous_hash'] != previous_block['hash']:
                return False

            block_data = block.copy()
            block_data.pop('hash')
            calculated_hash = self.calculate_block_hash(block_data)

            if block['hash'] != calculated_hash:
                return False

            if not self.validate_stake(block):
                return False

            previous_block = block

        return True

    def add_block(self, block):
        logging.info(f"Attempting to add block with index {block['index']}")
        if self.validate_received_block(block):
            with self.lock:
                if block['index'] == len(self.chain) + 1 and \
                   block['previous_hash'] == self.chain[-1]['hash']:
                    self.chain.append(block)
                    self.block_hashes.add(block['hash'])
                    logging.info(f"Block with index {block['index']} successfully added to the chain.")
                    self.broadcast_block(block)
                    return True
                else:
                    logging.warning(f"Block with index {block['index']} failed to match chain continuity.")
        else:
            logging.warning(f"Block with index {block['index']} failed validation.")
        return False
    
    def broadcast_block(self, new_block):
        block_data = json.dumps(new_block)

        service_prefix = "node"
        services = self.discover_services(service_prefix)

        self.post_data_to_services(services, "blocks/receive_block", block_data)
        
    def validate_foreign_tx(self, address, hash, pub_key, tx, signature):
        logging.debug(f"Validating tx from {address}")

        tx_hash = quantum_utils.quantum_resistant_hash(json.dumps(tx, sort_keys=True))
        if tx_hash != hash:
            logging.error(f"Hash mismatch for transaction with hash: {hash}")
            return None

        if not CUtils.verify_transaction(pub_key, tx, signature):
            logging.error(f"Invalid signature in foreign transaction with hash: {hash} from address: {address}")
            return None

        return True

    def vote_on_local_tx(self, address, hash, pub_key, tx, signature):
        valid_votes = []
        services = ledger.discover_services("node")

        if len(services) == 1 and services[0] == node.url:
            logging.info("Only one validator in the network, bypassing the voting process.")
            valid_votes.append(node.url)

        filtered_services = [s for s in services if f"http://{s}:3400" != node.url]
        for service in filtered_services:
            service_url = f"http://{service}:3400/vote_on_tx"

            try:
                data = {
                    'address': address,
                    'hash': hash,
                    'pub_key': pub_key,
                    'new_tx': tx,
                    'signature': signature
                }
                response = requests.post(service_url, json=data)
                if response.status_code == 200 and response.json().get('message') == 'Tx is valid':
                    valid_votes.append(service)
                    logging.info(f"Validator {service} approved the tx.")
                else:
                    logging.info(f"Validator {service} did not approve the tx.")
            except requests.exceptions.RequestException as e:
                logging.error(f"Error voting on block with {service}: {e}")

        return valid_votes

    def reach_tx_consensus(self, address, hash, pub_key, tx, signature):
        if len(self.validators) == 1:
            logging.info("Automatically reaching consensus with single validator")
            return True

        consensus_reached = self.vote_on_local_tx(address, hash, pub_key, tx, signature)

        if consensus_reached:
            logging.info("Tx consensus reached")
            return True
        else:
            logging.info("Tx consensus not reached")
            return False

    def receive_tx(self, address, hash, pub_key, tx, signature):
        try:
            if not self.validate_foreign_tx(address, hash, pub_key, tx, signature):
                logging.error(f"Received transaction, with hash {hash} from wallet {address}, did not pass verification")
                return False

            return True
        except Exception as e:
            logging.error(f"Error processing received transaction: {str(e)}")
            return False

    def receive_block(self, block):
        try:
            services = ledger.discover_services("node")
            authoritative_node_url, _ = ledger.sync_with_other_nodes(services)

            if authoritative_node_url:
                ledger.sync_account_list_data(authoritative_node_url, account_manager, coin, staked_coin)
                ledger.sync_treasury_data(authoritative_node_url)

            return True
        except Exception as e:
            logging.error(f"Error processing received block: {str(e)}")
            return False

    def broadcast_tx(self, address, hash, pub_key, new_tx, signature):
        data = {
            'address': address,
            'hash': hash,
            'pub_key': pub_key,
            'new_tx': new_tx,
            'signature': signature
        }

        services = ledger.discover_services("node")

        ledger.post_data_to_services(services, "transaction/receive_tx", data)

        return True
    
    def randomly_select_validator(self):
        if not self.validators:
            logging.warning("No validators available.")
            return None

        try:
            if len(self.validators) == 1:
                validator_address = self.validators[0]
                logging.info(f"Only one validator available. Selected validator address: {validator_address}")
                return validator_address

            max_value = len(self.validators) - 1
            random_bytes = QuantumUtils.quantum_random_bytes((max_value.bit_length() + 7) // 8)
            random_int = int.from_bytes(random_bytes, 'big') % (max_value + 1)
            validator_address = self.validators[random_int]
            logging.info(f"Randomly selected validator address: {validator_address}")
            return validator_address
        except Exception as e:
            logging.error(f"Error generating random index: {e}")
            return None

    def trigger_sync_on_all_nodes(self):
        services = ledger.discover_services("node")

        data = {}

        for service in services:
            service_base_url = f"http://{service}:3400"

            if service_base_url == node.url:
                logging.debug(f"Skipping self sync trigger: {service_base_url}")
                continue

            service_url = f"{service_base_url}/trigger_sync"
            logging.debug(f"Attempting to trigger sync on {service_url}")
            try:
                response = requests.post(service_url, json=data)
                if response.status_code == 200:
                    logging.debug(f"Successfully triggered sync on {service_url}")
                else:
                    logging.debug(f"Failed to trigger sync on {service_url}, status code: {response.status_code}")
            except requests.exceptions.RequestException as e:
                logging.error(f"Error triggering sync on {service_url}: {e}")

    def validate_received_block(self, block):
        logging.debug(f"Validating received block with index {block['index']}")
        if not self.validate_block_structure(block):
            logging.error("Block structure validation failed.")
            return False

        if not self.validate_block(block):
            logging.error("Block content validation failed.")
            return False

        if block['index'] != len(self.chain) + 1:
            logging.error(f"Block index {block['index']} does not follow the current chain length.")
            return False

        return True

    def validate_block_structure(self, block):
        logging.debug(f"Checking block structure for block with index {block['index']}")
        required_fields = [
            'index', 'previous_hash', 'timestamp', 'transactions',
            'merkle_root', 'stake_threshold', 'hash', 'miner', 'miner_share',
            'validator', 'validator_share', 'fee'
        ]

        missing_fields = [field for field in required_fields if field not in block]
        if missing_fields:
            logging.error(f"Block missing required fields: {missing_fields}")
            return False

        field_type_issues = False
        for field in required_fields:
            if field in block:
                expected_type = (int if field in ['index', 'timestamp'] else
                                 str if field in ['previous_hash', 'hash', 'miner', 'validator', 'merkle_root'] else
                                 list if field == 'transactions' else
                                 (int, float) if field in ['stake_threshold', 'fee', 'miner_share', 'validator_share'] else
                                 None)
                actual_type = type(block[field])
                if not isinstance(block[field], expected_type):
                    logging.error(f"Field '{field}' type mismatch: expected {expected_type}, got {actual_type}")
                    field_type_issues = True
            else:
                logging.error(f"Field '{field}' is missing from the block.")
                field_type_issues = True

        if field_type_issues:
            logging.error("One or more block field types are incorrect.")
            return False

        logging.debug("Block structure validated successfully.")
        return True
    
    def reach_consensus(self, proposed_block):
        if len(self.validators) == 1:
            logging.info("Automatically reaching consensus with single validator")
            return True

        consensus_reached = self.vote_on_local_block(proposed_block)

        if consensus_reached:
            logging.info("Consensus reached")
            return True
        else:
            logging.info("Consensus not reached")
            return False

    def vote_on_local_block(self, block):
        valid_votes = []
        services = self.discover_services("node")

        if len(services) == 1 and services[0] == node.url:
            logging.info("Only one validator in the network, bypassing the voting process.")
            valid_votes.append(node.url)

        filtered_services = [s for s in services if f"http://{s}:3400" != node.url]
        for service in filtered_services:
            service_url = f"http://{service}:3400/vote_on_block"

            try:
                response = requests.post(service_url, json=block)
                if response.status_code == 200 and response.json().get('message') == 'Block is valid':
                    valid_votes.append(service)
                    logging.info(f"Validator {service} approved the block.")
                else:
                    logging.info(f"Validator {service} did not approve the block.")
            except requests.exceptions.RequestException as e:
                logging.error(f"Error voting on block with {service}: {e}")

        return valid_votes

    def validate_block(self, block):
        logging.debug(f"Validating block with index {block['index']}")
        if block['validator'] not in self.validators:
            logging.error("Block validator is not recognized.")
            return False

        if not self.proof_of_stake(block):
            return False

        unique_addresses = set()
        double_spent_addresses = set()
        for transaction in block['transactions']:
            sender_address = transaction.get('address')
            if sender_address in unique_addresses:
                double_spent_addresses.add(sender_address)
            unique_addresses.add(sender_address)

        if double_spent_addresses:
            logging.error(f"Double spending detected for addresses: {', '.join(double_spent_addresses)}")
            raise DoubleSpendingError("Double spending detected for addresses: " + ', '.join(double_spent_addresses))

        block_string = str(block['index']) + str(block['timestamp']) + str(block['previous_hash']) + str(
            block['transactions']) + str(block['fee']) + str(block['validator']) + str(block['validator_share'])

        generated_hash = hashlib.sha256(block_string.encode()).hexdigest()
        if block['hash'] != generated_hash:
            logging.error("Block hash does not match the generated hash.")
            return False

        if not self.reach_consensus(block):
            logging.error("Failed to reach consensus.")
            return False

        logging.info(f"Block with index {block['index']} passed all validations.")
        return True

    def validate_foreign_block(self, block):
        logging.debug(f"Validating block with index {block['index']}")
        if block['validator'] not in self.validators:
            logging.error("Block validator is not recognized.")
            return False

        if not self.proof_of_stake(block):
            return False

        unique_addresses = set()
        double_spent_addresses = set()
        for transaction in block['transactions']:
            sender_address = transaction.get('address')
            if sender_address in unique_addresses:
                double_spent_addresses.add(sender_address)
            unique_addresses.add(sender_address)

        if double_spent_addresses:
            logging.error(f"Double spending detected for addresses: {', '.join(double_spent_addresses)}")
            raise DoubleSpendingError("Double spending detected for addresses: " + ', '.join(double_spent_addresses))

        block_string = str(block['index']) + str(block['timestamp']) + str(block['previous_hash']) + str(
            block['transactions']) + str(block['fee']) + str(block['validator']) + str(block['validator_share'])

        generated_hash = hashlib.sha256(block_string.encode()).hexdigest()
        if block['hash'] != generated_hash:
            logging.error("Block hash does not match the generated hash.")
            return False

        return True

    def generate_block_hash(self, block):
        transactions_string = json.dumps(block['transactions'], sort_keys=True)

        block_contents = (
            str(block['index']) +
            str(block['timestamp']) +
            str(block['previous_hash']) +
            transactions_string +
            str(block['fee']) +
            str(block['miner']) +
            str(block['miner_share']) +
            str(block['validator']) +
            str(block['validator_share'])
        )

        block_hash = hashlib.sha256(block_contents.encode()).hexdigest()
        return block_hash
    
    def proof_of_stake(self, block):
        logging.info("Starting proof of stake validation.")

        total_stake_weight = sum(node['stake_weight'] if isinstance(node, dict) else node.stake_weight for node in self.verifier.nodes)
        random_number = random.uniform(0, total_stake_weight)
        cumulative_stake_weight = 0

        logging.info(f"Total stake weight: {total_stake_weight}, Random number for validator selection: {random_number}")

        for current_node in self.verifier.nodes:
            node_stake_weight = current_node['stake_weight'] if isinstance(current_node, dict) else current_node.stake_weight
            cumulative_stake_weight += node_stake_weight

            if cumulative_stake_weight > random_number:
                selected_validator_address = current_node['address'] if isinstance(current_node, dict) else current_node.address
                logging.info(f"Selected validator address: {selected_validator_address}, Stake weight: {node_stake_weight}")

                if selected_validator_address == block['validator']:
                    logging.info(f"Validator {selected_validator_address} matches the block's validator.")
                    if node_stake_weight >= block['stake_threshold']:
                        logging.info(f"Validator {selected_validator_address} meets the stake threshold.")
                        return node_stake_weight
                    else:
                        logging.error(f"Validator {selected_validator_address} does not meet the stake threshold.")
                        return 0

        logging.error("No suitable validator found or the selected validator does not meet the stake threshold.")
        return 0

    def add_coin_transaction(self, address: str, amount: int, converted_amount: Union[int, float], fee: Union[int, float], hash: str, pub_key: str, signature: str, sub_type: str, type: str) -> Union[bool, str]:

        cleaned_transaction = {
            'address': address,
            'amount': amount,
            'converted_amount': converted_amount,
            'fee': fee,
            'hash': hash,
            'pub_key': pub_key,
            'signature': signature,
            'sub_type': sub_type,
            'type': type
        }

        if cleaned_transaction['signature']:
            return cleaned_transaction
        
    def select_miner(self) -> dict:
        accounts = staking_manager.staking_agreements

        # If no accounts are available, return None
        if not accounts:
            logging.warning("No staking accounts available for miner selection.")
            return None

        # Calculate the number of withdrawals for each account
        for account in accounts:
            account['withdrawals'] = sum(1 for block in self.chain for transaction in block['transactions']
                                        if 'address' in transaction and transaction.get('address') == account['address'])

        # Select the miner based on weighted selection
        miner = self.weighted_selection(accounts)
        return miner

    def weighted_selection(self, accounts: List[dict]) -> dict:
        # Calculate weights based on the number of withdrawals for each account
        weights = [1 / (acc['withdrawals'] + 1) for acc in accounts]
        total_weight = sum(weights)

        # Normalize the weights to ensure their sum is 1
        normalized_weights = [weight / total_weight for weight in weights]

        # Select an account using the normalized weights
        chosen_account = random.choices(
            accounts, weights=normalized_weights, k=1)[0]
        return chosen_account

    def calculate_fee_distribution(self, total_fee):
        fee_distribution = {}

        validator_percentage = 0.45
        miner_percentage = 0.315
        treasury_percentage = 0.235  # Updated to include the burn percentage

        fee_distribution['validator_share'] = total_fee * validator_percentage
        fee_distribution['miner_share'] = total_fee * miner_percentage
        fee_distribution['treasury_share'] = total_fee * treasury_percentage

        return fee_distribution
    
    def select_validator(self, block):
        selected_validator = self.verifier.select_validator(block)
        return selected_validator if selected_validator else None

    def validate_selected_validator(self, selected_validator, block):
        if selected_validator.malicious or selected_validator not in verifier.nodes:
            return False

        if selected_validator.address == block['validator'] and \
                selected_validator.stake_weight >= block['stake_threshold']:
            return True

        return False

    def add_malicious_validator(self, validator_address):
        for node in verifier.nodes:
            if node.address == validator_address:
                node.malicious = True
                break

    def create_new_block(self, transactions):
        latest_block = self.chain[-1]
        block_index = latest_block['index'] + 1
        timestamp = int(datetime.now(timezone.utc).timestamp())
        previous_hash = latest_block['hash']
        stake_threshold = node.stake_weight

        processed_transactions, total_fee = self.process_transactions(transactions)
        block_fee = self.coin.mint_for_block_fee(total_fee)
        fee_distribution = self.calculate_fee_distribution(block_fee)
        miner = self.select_miner()

        if miner is None:
            logging.error("Failed to select a miner. Aborting block creation.")
            return

        miner_address = miner['address']

        block = {
            'index': block_index,
            'timestamp': timestamp,
            'previous_hash': previous_hash,
            'transactions': processed_transactions,
            'stake_threshold': stake_threshold,
            'fee': block_fee
        }

        validator_node = self.select_validator(block)
        if validator_node:
            validator_address = validator_node['address'] if isinstance(validator_node, dict) else getattr(validator_node, 'address', node.address)
        else:
            validator_address = node.address

        for transaction in transactions:
            merkle_tree.add_transaction(str(transaction))

        merkle_tree.create_tree()
        merkle_root = merkle_tree.get_merkle_root()

        self.coin.credit(validator_address, fee_distribution['validator_share'])
        self.coin.credit(miner_address, fee_distribution['miner_share'])
        self.coin.credit(self.coin.treasury_address, fee_distribution['treasury_share'])

        new_block = {
            'index': block_index,
            'timestamp': timestamp,
            'previous_hash': previous_hash,
            'transactions': processed_transactions,
            'merkle_root': merkle_root,
            'stake_threshold': stake_threshold,
            'fee': block_fee,
            'miner': miner_address,
            'miner_share': fee_distribution['miner_share'],
            'validator': validator_address,
            'validator_share': fee_distribution['validator_share'],
            'treasury_share': fee_distribution['treasury_share']
        }

        logging.info(f"constructed block: {new_block}")

        block_string = str(new_block['index']) + str(new_block['timestamp']) + str(new_block['previous_hash']) + str(
            new_block['transactions']) + str(new_block['fee']) + str(new_block['validator']) + str(new_block['validator_share'])

        # Generate block hash
        block_hash = hashlib.sha256(block_string.encode()).hexdigest()

        new_block['hash'] = block_hash

        if self.add_block(new_block):
            self.transactions.cleaned_transactions = []
            logging.info(f"Successfully mined new block: {new_block}")
            return new_block
        else:
            logging.debug(f"Issue mining block: {new_block}")

    def process_transactions(self, transactions):
        processed_transactions = []
        total_fee = 0.0

        for transaction in transactions:
            transaction_type = transaction.get('sub_type')

            if transaction_type == 'r':
                processed_transaction = self.handle_staking_transaction(transaction)
            elif transaction_type == 'o':
                processed_transaction = self.handle_unstaking_transaction(transaction)
            elif transaction_type == 'k':
                processed_transaction = self.handle_transfer_transaction(transaction)
            elif transaction_type == 'w':
                processed_transaction = self.handle_pomc_whitelist_transaction(transaction)
            elif transaction_type in ['h', 'x', 'm', 'pr']:
                processed_transaction = self.handle_fee_payment_transaction(transaction)
            else:
                processed_transaction = self.handle_default_transaction(transaction)

            if processed_transaction:
                processed_transactions.append(processed_transaction)
                total_fee += processed_transaction.get('fee', 0.0)

        return processed_transactions, total_fee

    def handle_staking_transaction(self, transaction):
        try:
            fee_calculator = DynamicFeeCalculator()
            sender_address = transaction['address']
            staking_amount = transaction['amount']
            min_term = transaction['min_term']
            pub_key = transaction['pub_key']
            signature = transaction.get('signature')

            transaction_data = {
                'address': sender_address,
                'amount': staking_amount,
                'min_term': min_term,
                'pub_key': pub_key,
                'type': transaction['type']
            }

            transaction_fee, transaction_hash = dynamic_fee_calculator.get_base_dynamic_fee(transaction_data, transaction['type'])

            if not all([sender_address, staking_amount, min_term, pub_key, signature]):
                logging.error("Missing fields in staking transaction")
                return None

            sender_balance_info = self.wallet.get_account_balance(sender_address)
            if not sender_balance_info or sender_balance_info['balance_float'] < staking_amount + transaction_fee:
                logging.error("Insufficient balance for staking")
                return None

            transaction_for_verification = {
                'address': sender_address,
                'amount': staking_amount,
                'fee': transaction_fee,
                'hash': transaction_hash,
                'min_term': min_term,
                'pub_key': pub_key,
                'type': transaction['type']
            }

            if not crypto_utils.verify_transaction(transaction['pub_key'], transaction_for_verification, transaction['signature']):
                logging.error("Invalid signature in staking transaction")
                return None

            self.wallet.stake_coins(sender_address, staking_amount, min_term)

            processed_transaction = {
                'address': sender_address,
                'amount': staking_amount,
                'fee': transaction_fee,
                'hash': transaction_hash,
                'min_term': min_term,
                'stake_threshold': 3,
                'type': transaction['type'],
                'when': str(datetime.now(timezone.utc))
            }

            logging.info(f"Processed staking transaction for {sender_address}")
            return processed_transaction

        except Exception as e:
            logging.error(f"Error processing staking transaction: {e}")
            return None

    def handle_unstaking_transaction(self, transaction):
        try:
            fee_calculator = DynamicFeeCalculator()
            sender_address = transaction['address']
            contract_id = transaction['contract_id']
            pub_key = transaction['pub_key']
            signature = transaction.get('signature')

            transaction_data = {
                'address': sender_address,
                'contract_id': contract_id,
                'pub_key': pub_key,
                'type': transaction['type']
            }

            transaction_fee, transaction_hash = dynamic_fee_calculator.get_base_dynamic_fee(transaction_data, transaction['type'])

            if not all([sender_address, contract_id, pub_key, signature]):
                logging.error("Missing fields in unstaking transaction")
                return None

            sender_balance_info = self.wallet.get_account_balance(sender_address)
            if not sender_balance_info or sender_balance_info['balance_float'] < transaction_fee:
                logging.error("Insufficient balance for unstaking")
                return None

            transaction_for_verification = {
                'address': sender_address,
                'contract_id': contract_id,
                'fee': transaction_fee,
                'hash': transaction_hash,
                'pub_key': pub_key,
                'type': transaction['type']
            }

            if not crypto_utils.verify_transaction(transaction['pub_key'], transaction_for_verification, transaction['signature']):
                logging.error("Invalid signature in unstaking transaction")
                return None

            self.wallet.unstake_coins(sender_address, contract_id)

            processed_transaction = {
                'address': sender_address,
                'contract_id': contract_id,
                'fee': transaction_fee,
                'hash': transaction_hash,
                'stake_threshold': 2,
                'type': transaction['type'],
                'when': str(datetime.now(timezone.utc))
            }

            logging.info(f"Processed unstaking transaction for {sender_address}")
            return processed_transaction

        except Exception as e:
            logging.error(f"Error processing unstaking transaction: {e}")
            return None

    def handle_transfer_transaction(self, transaction):
        try:
            fee_calculator = DynamicFeeCalculator()
            sender_address = transaction['sender']
            recipient_address = transaction['recipient']
            transfer_amount = transaction['amount']
            pub_key = transaction['pub_key']
            signature = transaction.get('signature')

            transaction_data = {
                'sender': sender_address,
                'recipient': recipient_address,
                'amount': transfer_amount,
                'pub_key': pub_key,
                'type': transaction['type']
            }

            transaction_fee, transaction_hash = dynamic_fee_calculator.get_base_dynamic_fee(transaction_data, transaction['type'])

            if not all([sender_address, recipient_address, transfer_amount, pub_key, signature]):
                logging.error("Missing fields in transfer transaction")
                return None

            sender_balance_info = self.wallet.get_account_balance(sender_address)
            if not sender_balance_info or sender_balance_info['balance_float'] < transfer_amount + transaction_fee:
                logging.error("Insufficient balance for transfer")
                return None

            transaction_for_verification = {
                'sender': sender_address,
                'recipient': recipient_address,
                'amount': transfer_amount,
                'fee': transaction_fee,
                'hash': transaction_hash,
                'pub_key': pub_key,
                'type': transaction['type']
            }

            if not crypto_utils.verify_transaction(transaction['pub_key'], transaction_for_verification, transaction['signature']):
                logging.error("Invalid signature in transfer transaction")
                return None

            self.wallet.transfer(sender_address, recipient_address, transfer_amount)

            processed_transaction = {
                'sender': sender_address,
                'recipient': recipient_address,
                'amount': transfer_amount,
                'fee': transaction_fee,
                'hash': transaction_hash,
                'stake_threshold': 2,
                'type': transaction['type'],
                'when': str(datetime.now(timezone.utc))
            }

            logging.info(f"Processed transfer transaction from {sender_address} to {recipient_address}")
            return processed_transaction

        except Exception as e:
            logging.error(f"Error processing transfer transaction: {e}")
            return None
    
    def handle_pomc_whitelist_transaction(self, transaction):
        try:
            
            sender_address = transaction['sender']
            pub_key = transaction['pub_key']
            signature = transaction.get('signature')

            processed_transaction = {
                'fee': transaction['fee'],
                'hash': transaction['hash'],
                'sender': transaction['sender'],
                'sub_type': transaction['sub_type'],
                'stake_threshold': 2,
                'type': transaction['type'],
                'when': transaction['when']
            }

            logging.info(f"Processed transfer transaction from {sender_address} to join pOMC whitelist")
            return processed_transaction

        except Exception as e:
            logging.error(f"Error processing transfer transaction: {e}")
            return None

    def handle_fee_payment_transaction(self, transaction):
        try:
            fee_calculator = DynamicFeeCalculator()
            payer_address = transaction['from']
            fee_amount = transaction['fee']
            pub_key = transaction['pub_key']
            signature = transaction.get('signature')

            transaction_data = {
                'from': payer_address,
                'fee': fee_amount,
                'pub_key': pub_key,
                'type': transaction['type']
            }

            calculated_fee, transaction_hash = dynamic_fee_calculator.get_base_dynamic_fee(transaction_data, transaction['type'])

            if not all([payer_address, fee_amount, pub_key, signature]):
                logging.error("Missing fields in fee payment transaction")
                return None

            payer_balance_info = self.wallet.get_account_balance(payer_address)
            if not payer_balance_info or payer_balance_info['balance_float'] < fee_amount + calculated_fee:
                logging.error("Insufficient balance for fee payment")
                return None

            transaction_for_verification = {
                'from': payer_address,
                'fee': calculated_fee,
                'hash': transaction_hash,
                'pub_key': pub_key,
                'type': transaction['type']
            }

            if not crypto_utils.verify_transaction(transaction['pub_key'], transaction_for_verification, transaction['signature']):
                logging.error("Invalid signature in fee payment transaction")
                return None

            self.wallet.pay_fee(payer_address, fee_amount)

            processed_transaction = {
                'from': payer_address,
                'fee': calculated_fee,
                'hash': transaction_hash,
                'stake_threshold': 2,
                'type': transaction['type'],
                'when': str(datetime.now(timezone.utc))
            }

            logging.info(f"Processed fee payment transaction from {payer_address}")
            return processed_transaction

        except Exception as e:
            logging.error(f"Error processing fee payment transaction A1: {e}")
            return None

    def handle_default_transaction(self, transaction):
        try:
            fee_calculator = DynamicFeeCalculator()
            payer_address = transaction['address']

            transaction_data = {
                'from': payer_address,
                'type': 'e'
            }

            calculated_fee, transaction_hash = dynamic_fee_calculator.get_base_dynamic_fee(transaction_data, transaction['type'])

            processed_transaction = {
                'from': payer_address,
                'fee': 0.0,
                'hash': transaction_hash,
                'stake_threshold': 1,
                'type': 'e',
                'when': str(datetime.now(timezone.utc))
            }

            logging.info(f"Processed fee payment transaction from {payer_address}")
            return processed_transaction

        except Exception as e:
            logging.error(f"Error processing fee payment transaction A2: {e}")
            return None

    def clean_and_verify_transactions(self):
        new_transactions = self.transactions.batch_pending_transactions()
        cleaned_transactions = []

        for transaction in new_transactions:
            try:
                if transaction['type'] == 'c' and transaction['sub_type'] == 'c':
                    self.process_account_creation_transaction(transaction)
                elif transaction['type'] == 'c' and transaction['sub_type'] == 'w':
                    self.process_add_account_to_whitelist_transaction(transaction)
                elif transaction['type'] == 'o':
                    self.process_non_f_transaction(transaction)
                elif transaction['type'] == 'e':
                    self.process_f_transaction(transaction)
            except Exception as e:
                logging.error(f"Error processing transaction {transaction['type']}: {e}")

        return cleaned_transactions
    
    def process_account_creation_transaction(self, transaction):
        # Verify that the transaction is of the correct type
        if transaction['type'] != 'c':
            logging.error(f"Invalid transaction type for account creation: {transaction['type']}")
            return

        try:
            # Extract necessary fields from the transaction
            address = transaction['address']
            balance = transaction['balance']
            type = transaction['type']
            timestamp = ['timestamp']
            withdrawals = transaction['withdrawals']

            # Validate the transaction data
            if not all([address, type]):
                logging.error("Incomplete account creation transaction data")
                return

            # Check if the address already exists in the blockchain wallet
            # if any(acc['address'] == address for acc in account_manager.accounts):
            #     logging.info(f"Account already exists: {address}")
            #     return

            # # Create and append the new account to the wallet
            # new_account = {
            #     'address': address,
            #     'balance': balance,
            #     'withdrawals': withdrawals
            # }
            # account_manager.accounts.append(new_account)

            # Create a cleaned version of the transaction for the blockchain
            cleaned_transaction = {
                'address': address,
                'hash': transaction.get('hash'),
                'pub_key': transaction['pub_key'],
                'signature': transaction['signature'],
                'sub_type': 'c',
                'type': transaction['type'],
                'withdrawals': withdrawals
            }

            # Append the cleaned transaction to the list of processed transactions
            self.transactions.cleaned_transactions.append(cleaned_transaction)
            logging.info(f"Processed account creation transaction for {address}")

        except Exception as e:
            logging.error(f"Error processing account creation transaction A2: {e}")
            
    def process_add_account_to_whitelist_transaction(self, transaction):
        # Verify that the transaction is of the correct type
        if transaction['type'] != 'c':
            logging.error(f"Invalid transaction type to add account to whitelist: {transaction['type']}")
            return

        try:
            result = {
                'fee': transaction['fee'],
                'hash': transaction['hash'],
                'pub_key': transaction['pub_key'],
                'sender': transaction['sender'],
                'signature': transaction['signature'],
                'sub_type': transaction['sub_type'],
                'type': transaction['type'],
                'when': transaction['when']
            }
            # Extract necessary fields from the transaction
            address = transaction['sender']
            hash = transaction['hash']
            type = transaction['type']

            # Validate the transaction data
            if not all([address, hash, type]):
                logging.error("Incomplete account creation transaction data")
                return

            # Create a cleaned version of the transaction for the blockchain
            cleaned_transaction = {
                'fee': transaction['fee'],
                'hash': transaction['hash'],
                'pub_key': transaction['pub_key'],
                'sender': transaction['sender'],
                'signature': transaction['signature'],
                'sub_type': transaction['sub_type'],
                'type': transaction['type'],
                'when': transaction['when']
            }

            # Append the cleaned transaction to the list of processed transactions
            self.transactions.cleaned_transactions.append(cleaned_transaction)
            logging.info(f"Processed join whitelist transaction for {address}")

        except Exception as e:
            logging.error(f"Error processing join whiteist transaction A2: {e}")

    def process_f_transaction(self, transaction):
        try:
            transaction_type = transaction.get('type')
            sender_address = transaction.get('address')
            transaction_fee = transaction.get('fee', 0.0)

            if not sender_address or transaction_fee is None:
                logging.error("Invalid transaction format.")
                return None

            cleaned_transaction = None

            if transaction_type == 'e':
                sub_tx_type = transaction.get('sub_type')

                if sub_tx_type == 'p':
                    amount = transaction.get('amount')
                    recipient_address = transaction.get('recipient')

                    if crypto_utils.verify_transaction(sender_address, recipient_address, amount):
                        self.wallet.transfer(sender_address, recipient_address, amount)

                elif sub_tx_type == 'r':
                    amount = transaction.get('amount')
                    min_term = transaction.get('min_term')

                    self.wallet.stake_coins(sender_address, amount, min_term)

                elif sub_tx_type == 'z':
                    contract_id = transaction.get('contract_id')

                    self.wallet.unstake_coins(sender_address, contract_id)

            if cleaned_transaction:
                self.transactions.cleaned_transactions.append(cleaned_transaction)
                logging.info(f"Processed transaction of type {transaction_type} for {sender_address}")
                return cleaned_transaction
            else:
                logging.warning(f"Unhandled or failed transaction type/subtype: {transaction_type}/{sub_tx_type}")
                return None

        except Exception as e:
            logging.error(f"Error processing account creation transaction A2: {e}")

    def process_non_f_transaction(self, transaction):
        try:
            transaction_type = transaction.get('type')
            sender_address = transaction.get('address')
            transaction_fee = transaction.get('fee', 0.0)

            if not sender_address or transaction_fee is None:
                logging.error("Invalid transaction format.")
                return None

            cleaned_transaction = None

            if transaction_type == 'o':
                sub_tx_type = transaction.get('sub_type')

                if sub_tx_type == 's':
                    self.handle_post_transaction(transaction)

                elif sub_tx_type == 'j':
                    refined_transaction = self.handle_add_profile_transaction(transaction)
                    if refined_transaction:
                        cleaned_transaction = {
                            'address': transaction['address'],
                            'avi': transaction['avi'],
                            'clubs': transaction['clubs'],
                            'fee': transaction['fee'],
                            'handle': transaction['handle'],
                            'hash': transaction['hash'],
                            'intro': transaction['intro'],
                            'joined': transaction['joined'],
                            'name': transaction['name'],
                            'profile_id': transaction['profile_id'],
                            'profile_type': transaction['profile_type'],
                            'pt': transaction['pt'],
                            'pt_id': transaction['pt_id'],
                            'pub_key': transaction['pub_key'],
                            'signature': transaction['signature'],
                            'sub_type': transaction['sub_type'],
                            'tags': transaction['tags'],
                            'type': transaction['type'],
                            'version': transaction['version']
                        }

            if cleaned_transaction:
                transactions.cleaned_transactions.append(cleaned_transaction)
                logging.info(f"Processed transaction of type {transaction_type} for {sender_address}")
                return cleaned_transaction
            else:
                logging.warning(f"Unhandled or failed transaction type/subtype: {transaction_type}/{sub_tx_type}")
                return None

        except Exception as e:
            logging.error(f"Error processing transaction: {e}")
            return None

    def start_mining(self):
        self.create_new_block(self.transactions.cleaned_transactions)

    def check_pending_transactions(self):
        self.clean_and_verify_transactions()
        self.start_mining()

    def get_latest_block(self):
        return self.chain[-1]

    def main_loop(self):
        while True:
            self.start_mining()
            self.consume_blocks()

    def consume_blocks(self):
        for message in self.consumer:
            block_data = message.value.decode('utf-8')
            block = json.loads(block_data)
            self.receive_block(block)
        
## Creating a Web App
app = Flask(__name__)
CORS(app)

dynamic_fee_calculator = DynamicFeeCalculator()

verifier = Verifier()

crypto_utils = CUtils()

# Create transaction class
transactions = Transactions()

merkle_tree = MerkleTree()

permission_manager = PermissionMngr()

# Initialize the OMC class
coin = OMC()

#Initialize the pOMC class
precursor_coin = pOMC()

account_manager = AccMngr()

# Staked coin
staked_coin = StakedOMC()

staking_manager = StakingMngr()

# Creating a Wallet
wallet = Wallet()

node = Node()

staked_coin.treasury_account = coin.treasury_address
coin.treasury_account = coin.treasury_address

ledger = Ledger(coin, node, wallet, transactions, verifier)

def require_authentication(func):
    """
    A decorator function that enforces authentication by checking the
    presence and validity of an authorization token in the request headers.

    Args:
        func (function): The function to be wrapped by the decorator.

    Returns:
        function: A wrapped function that checks the authorization token
        and returns an error response if the token is missing or invalid.
    """
    @wraps(func)
    def wrapper(*args, **kwargs):
        token = request.headers.get("Authorization")
        if token != f"Bearer {AUTH_TOKEN}":
            return jsonify({"error": "Unauthorized"}), 401
        return func(*args, **kwargs)
    return wrapper

@app.route('/endpoints', methods=['GET'])
def get_endpoints():
    output = []
    for rule in app.url_map.iter_rules():
        if rule.endpoint != 'endpoints':
            output.append(rule.rule)
    return jsonify(output)

@app.route('/health', methods=['GET'])
def health_check():
    return jsonify({"status": "healthy"}), 200

@app.route('/trigger_sync', methods=['POST'])
@require_authentication
def trigger_sync():
    try:
        services = ledger.discover_services("node")
        result = ledger.check_chain_length_and_sync(services)
        return jsonify(result), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500

def validate_date(date_text):
    """
    Validates if the date text is in a proper date format.

    Args:
        date_text (str): The date in string format.

    Returns:
        bool: True if the date is valid, False otherwise.
    """
    try:
        datetime.strptime(date_text, '%Y-%m-%d')  # Using ISO date format
        return True
    except ValueError:
        return False

#==== ACCOUNT OPS ====#

# Create new wallet
@app.route('/create_account', methods=['GET'])
@require_authentication
def generate_account_from_mnemonic():

    o = ledger.create_new_wallet()

    # Construct sendable_account dictionary
    sendable_account = {
        'mnemonic': o['mnemonic'],
        'private_key': o['private_key'],
        'pub_key': o['pub_key'],
        'address': o['address']
    }

    response = {
        'message': 'Account generated successfully',
        'account': sendable_account
    }
    return jsonify(response), 200

#Create new wallet from owned seed phrase
@app.route('/create_another_account', methods=['POST'])
@require_authentication
def generate_another_account_from_seed():

    data = request.get_json()
    m = data.get('i')
    logging.info(f"m is: {m}")
    o = ledger.create_new_wallet_from_seed(m)

    # Construct sendable_account dictionary
    sendable_account = {
        'mnemonic': o['mnemonic'],
        'private_key': o['private_key'],
        'pub_key': o['pub_key'],
        'address': o['address']
    }

    response = {
        'message': 'Account generated successfully',
        'account': sendable_account
    }
    return jsonify(response), 200

# Propogate account
@app.route('/propagate_account', methods=['POST'])
def propagate_account():
    data = request.json
    address = data['address']
    balance = data['balance']

    # Check if account exists
    account_exists = any(account['address'] == address for account in account_manager.accounts)

    if not account_exists:
        # Update account_manager.accounts
        account_manager.accounts.append({'address': address, 'balance': balance})

        # Update coin.accounts and coin.balance
        coin.accounts.append(address)
        coin.balance[address] = balance

        return jsonify({'message': 'Account updated successfully'}), 200

    return jsonify({'message': 'Account already exists'}), 200

# Recover wallet
@app.route('/recover_wallet', methods=['POST'])
def recover_wallet():
    try:
        data = request.get_json()
        mnemonic = data.get('mnemonic')
        if not mnemonic:
            return jsonify({"error": "Mnemonic is required"}), 400

        # Assuming there's a function to recover the wallet and then fetch the balance
        wallet_details = wallet.recover_wallet(mnemonic)
        if not wallet_details:
            return jsonify({"error": "Failed to recover wallet"}), 400

        # Fetch the balance for the recovered wallet address
        balance = coin.get_balance(wallet_details['address'])
        if balance is None:
            return jsonify({"error": "Failed to retrieve balance"}), 400

        response = {
            'message': 'Wallet recovered and balance retrieved successfully',
            'balance': balance,
            'address': wallet_details['address']  # Providing the wallet address might be useful
        }
        return jsonify(response), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500

# Give site permission to connect to wallet
@app.route('/add_permission', methods=['POST'])
def add_permission():
    """
    Flask endpoint to add a new permission object to the wallet.

    Expected JSON format in the request body:
    {
        "address": "0x...",
        "url": "https://example.com",
        "permission": true
    }

    Returns:
    {
        "success": true,
        "message": "Permission added successfully."
    }
    """
    try:
        data = request.get_json()
        address = data.get('address')
        url = data.get('url')
        permission = data.get('permission')

        wallet.add_or_update_permission(address, url, permission)

        response = {
            "success": True,
            "message": "Permission added successfully."
        }
    except Exception as e:
        response = {
            "success": False,
            "message": str(e)
        }

    return jsonify(response)

def require_authentication(func):
    """
    A decorator function that enforces authentication by checking the
    presence and validity of an authorization token in the request headers.

    Args:
        func (function): The function to be wrapped by the decorator.

    Returns:
        function: A wrapped function that checks the authorization token
        and returns an error response if the token is missing or invalid.
    """
    @wraps(func)
    def wrapper(*args, **kwargs):
        token = request.headers.get("Authorization")
        if token != f"Bearer {AUTH_TOKEN}":
            return jsonify({"error": "Unauthorized"}), 401
        return func(*args, **kwargs)
    return wrapper

def validate_date(date_text):
    """
    Validates if the date text is in a proper date format.

    Args:
        date_text (str): The date in string format.

    Returns:
        bool: True if the date is valid, False otherwise.
    """
    try:
        datetime.strptime(date_text, '%Y-%m-%d')  # Using ISO date format
        return True
    except ValueError:
        return False

# Decrypt the data of the request
def decrypt_data(encrypted_data, private_key_path):
    with open(private_key_path, "rb") as private_key_file:
        private_key = serialization.load_pem_private_key(
            private_key_file.read(),
            password=None,
        )

    decrypted_data = private_key.decrypt(
        encrypted_data,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        ),
    )

    return decrypted_data

# Retrieve NonIterableList data
@app.route('/get_account_list_data', methods=['GET'])
def get_account_list_data():
    account_list_data = account_manager.accounts
    return jsonify({"account_list_data": account_list_data}), 200

# Retrieve accounts
@app.route('/retrieve_accounts', methods=['GET'])
def retrieve_accounts():
    try:
        account_list_data = account_manager.accounts
        precursor_accounts = account_manager.precursor_accounts
        staking_accounts = staking_manager.staking_agreements
        validators = ledger.validators

        # Convert nodes to dictionaries; handle both Node objects and already dictionary nodes
        nodes = []
        for node in verifier.nodes:
            if isinstance(node, Node):
                nodes.append(node.to_dict())  # Convert Node object to dictionary using a method
            elif isinstance(node, dict):
                nodes.append(node)  # It's already a dictionary, append as is

        response_data = {
            'data': account_list_data,
            'precursor_accounts': precursor_accounts,
            'staking_accounts': staking_accounts,
            'validators': validators,
            'nodes': nodes
        }

        return jsonify(response_data), 200

    except Exception as e:
        return jsonify({"message": "Error retrieving accounts", "error": str(e)}), 500

#==== CHAIN MAINTENANCE ====#

# Getting the full Blockchain
@app.route('/get_chain', methods=['GET'])
def get_chain():
    response = {
        'chain': ledger.chain,
        'length': len(ledger.chain)
    }
    return jsonify(response), 200

# Check validators
@app.route('/check_validators', methods=['GET'])
@require_authentication
def check_validators():
    # Extracting the address attribute from each node
    node_addresses = [node.address for node in verifier.nodes]

    response = {
        'validators': node_addresses,
        'length': len(node_addresses)
    }
    return jsonify(response), 200

# Check connected nodes including verification nodes
@app.route('/check_nodes', methods=['GET'])
@require_authentication
def check_nodes():
    # Convert nodes to dictionaries; handle both Node objects and already dictionary nodes
    node_dicts = []
    for node in verifier.nodes:
        if isinstance(node, Node):
            node_dicts.append(node.to_dict())  # Convert Node object to dictionary using a method
        elif isinstance(node, dict):
            node_dicts.append(node)  # It's already a dictionary, append as is

    response = {
        'nodes': node_dicts,
        'length': len(node_dicts)
    }
    return jsonify(response), 200

# Retrieve single node data
@app.route('/retrieve_node_endpoint', methods=['GET'])
@require_authentication
def get_node_data():
    response = {
        'address': node.address,
        'url': node.url,
        'version': node.version,
        'public_key': node.public_key
    }
    return jsonify(response), 200

# Receive single node data
@app.route('/receive_node_data', methods=['POST'])
@require_authentication
def receive_node_data():
    logging.info("Received request to add new node data.")
    json_ = request.get_json()
    logging.debug(f"Received node data: {json_}")

    # Check for all required fields in the received JSON data
    required_keys = ['address', 'url', 'version', 'public_key', 'stake_weight', 'steward']
    if not all(key in json_ for key in required_keys):
        missing_keys = [key for key in required_keys if key not in json_]
        logging.warning(f"Missing required node data: {missing_keys}")
        return jsonify({'error': 'Missing required node data', 'missing_keys': missing_keys}), 400

    # Adjust this to check both dicts and Node objects properly
    if any((node.address if isinstance(node, Node) else node['address']) == json_['address'] for node in verifier.nodes):
        logging.info(f"Node {json_['address']} is already in the roster of nodes.")
        return jsonify({'message': f'Node {json_["address"]} is already added to roster of nodes'}), 200

    # Append the new node as a dictionary to the validators and nodes lists
    new_node = {
        'address': json_['address'],
        'public_key': json_['public_key'],
        'url': json_['url'],
        'stake_weight': json_['stake_weight'],
        'version': json_['version'],
        'steward': json_['steward']
    }
    verifier.nodes.append(new_node)  # Only add if not already present
    ledger.validators.append(new_node['address'])  # Manage this list separately if needed
    logging.info(f"Node {json_['address']} successfully added to the roster of nodes.")
    return jsonify({'message': f'Node {json_["address"]} added to roster of nodes'}), 201

# Return new block
@app.route('/check_new_block', methods=['GET'])
def check_new_block():
    nb = ledger.create_new_block()
    response = {
        'new_block': nb
    }
    return jsonify(response), 200

# Inform adjacent nodes that data was updated
@app.route('/notify_data_update', methods=['POST'])
def notify_data_update():
    # Perform any necessary actions when notified of a data update
    # This can include updating the local data or logging the update

    # Respond with a success message or an appropriate status code
    response = {'message': 'Data update notification received'}
    return jsonify(response), 200

#==== CHAIN OPERATIONS ====#

# Check transaction
@app.route('/check_transaction', methods=['POST'])
def check_transaction():
    data = request.json
    transaction_hash = data.get('hash')

    if not transaction_hash:
        return jsonify({"error": "No hash provided"}), 400

    # Check in ledger.chain
    for block in ledger.chain:
        if any(tx['hash'] == transaction_hash for tx in block['transactions']):
            return jsonify({
                "hash": transaction_hash,
                "status": "processed & recorded",
                "merkle_root": block['merkle_root']
            }), 200

    # Check in transactions.cleaned_transactions
    if any(tx['hash'] == transaction_hash for tx in transactions.cleaned_transactions):
        return jsonify({
            "hash": transaction_hash,
            "status": "in queue",
            "merkle_root": "N/A"  # Modify if merkle_root is available for cleaned transactions
        }), 200

    # Check in transactions.transactions
    if any(tx['hash'] == transaction_hash for tx in transactions.transactions):
        return jsonify({
            "hash": transaction_hash,
            "status": "buffer pool",
            "merkle_root": "N/A"  # Modify if merkle_root is available for pending transactions
        }), 200

    # Hash not found
    return jsonify({"error": "Transaction hash not found"}), 404

# Vote on foregin tx
@app.route('/vote_on_tx', methods=['POST'])
def vote_on_received_tx():
    data = request.get_json()

    address = data['address']
    hash = data['hash']
    pub_key = data['pub_key']
    tx = data['tx']
    signature = data['signature']

    logging.info(f"Received tx data for voting: {tx}")

    if not tx:
        logging.error("No tx data received for voting.")
        return jsonify({'error': 'Invalid or missing tx data'}), 400

    try:
        if ledger.validate_foreign_tx(address, hash, pub_key, tx, signature):
            logging.info("Tx validated successfully in voting.")
            return jsonify({'message': 'Tx is valid'}), 200
        else:
            logging.error("Tx validation failed in voting.")
            return jsonify({'error': 'Tx is invalid'}), 400
    except Exception as e:
        logging.error(f"Error during tx validation: {str(e)}")
        return jsonify({'error': 'Tx validation encountered an error'}), 500

# Vote on foregin block
@app.route('/vote_on_block', methods=['POST'])
def vote_on_received_block():
    block = request.get_json()
    logging.info(f"Received block data for voting: {block}")

    if not block:
        logging.error("No block data received for voting.")
        return jsonify({'error': 'Invalid or missing block data'}), 400

    try:
        if ledger.validate_foreign_block(block):
            logging.info("Block validated successfully in voting.")
            return jsonify({'message': 'Block is valid'}), 200
        else:
            logging.error("Block validation failed in voting.")
            return jsonify({'error': 'Block is invalid'}), 400
    except Exception as e:
        logging.error(f"Error during block validation: {str(e)}")
        return jsonify({'error': 'Block validation encountered an error'}), 500

# Receive neighboring node data
@app.route('/receive_node_info', methods=['POST'])
@require_authentication
def receive_node_info():
    received_node_info = request.json
    logging.info(f"Received node information for processing: {received_node_info}")

    # Check if the node already exists in the blockchain's nodes list
    existing_node = next((node for node in verifier.nodes if node.address == received_node_info['address']), None)

    if existing_node is None:
        # If the node does not exist, create a new Node instance and add it to the list
        new_node = received_node_info
        verifier.nodes.append(new_node)
        ledger.validators.append(new_node.address)
        logging.info(f"Added new node with address: {received_node_info['address']}")
    else:
        # If the node already exists, log that information
        logging.info(f"Node with address {existing_node.address} already exists and was not added again.")

    return jsonify({"status": "success"}), 200

# Route to get the chain length
@app.route('/get_chain_length', methods=['GET'])
def get_chain_length():
    chain_length = len(ledger.chain)
    return jsonify({"chain_length": chain_length}), 200

#Verify data sent from another node
def verify_request_signature(request):
    public_key = b"..."  # Replace with the corresponding public key
    signature_header = request.headers.get("Signature")
    data = json.dumps(request.json, separators=(",", ":"), sort_keys=True)

    expected_signature = sign_data(public_key, data)
    return expected_signature == signature_header

# Sign data to be transmitted to another node
def sign_data(private_key_path, data):
    with open(private_key_path, "rb") as private_key_file:
        private_key = serialization.load_pem_private_key(
            private_key_file.read(),
            password=None,
        )
    signature = private_key.sign(
        data,
        padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
        hashes.SHA256(),
    )
    return signature

# Encrypt data to be transmitted to another node
def encrypt_data(data, public_key_path):
    with open(public_key_path, "rb") as public_key_file:
        public_key = serialization.load_pem_public_key(public_key_file.read())
    encrypted_data = public_key.encrypt(
        data,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        ),
    )
    return encrypted_data

# Locate transactions
@app.route('/get_all_transactions', methods=['GET'])
@require_authentication
def get_all_transactions():
    mined_transactions = []
    pending_transactions = []

    for block in ledger.chain:
        for transaction in block['transactions']:
            mined_transactions.append(transaction)

    cleaned_transactions = transactions.get_cleaned_transactions()

    transactions_data = {
        'mined_transactions': mined_transactions,
        'cleaned_transactions': transactions.cleaned_transactions,
        'pending_transactions': transactions.transactions
    }

    return jsonify(transactions_data), 200

# Retrieve init date
@app.route('/retrieve_init_date', methods=['GET'])
def retrieve_init_date():
    init_date = ledger.get_init_date()  # Call a method to retrieve the init_date
    return jsonify({"init_date": str(init_date)})

# Calculate tx hash
@app.route('/calculate_hash', methods=['POST'])
def hash_transaction():
    json_ = request.get_json()
    if not data:
        return jsonify({'error': 'No data provided'}), 400

    try:
        hash_result = crypto_utils.calculate_sha256_hash(json_['tx'])
        return jsonify({'hash': hash_result}), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 500

# Calculate tx fee
@app.route('/calculate_fee', methods=['POST'])
def calculate_fee():
    data = request.get_json()
    if not data or 'transaction_data' not in data or 'transaction_type' not in data:
        return jsonify({'error': 'Invalid request. Please provide transaction data and type.'}), 400

    try:
        transaction_data = data['transaction_data']
        transaction_type = data['transaction_type']

        cost, transaction_hash = dynamic_fee_calculator.get_base_dynamic_fee(transaction_data, transaction_type)
        return jsonify({
            'cost': cost,
            'transaction_hash': transaction_hash
        }), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 500

#==== COIN OPERATIONS ====#

# Transfer coins
@app.route('/transfer_coins', methods=['POST'])
def transfer_coins():
    try:
        data = request.get_json()

        # Extract the relevant data from the request
        sender = data.get('from_address')
        recipient = data.get('to_address')
        amount = data.get('amount')
        fee = data.get('fee')
        hash = data.get('hash')
        pub_key = data.get('pub_key')
        signature = data.get('signature')
        sub_type = data.get('sub_type')
        type = data.get('type')

        # Validate required data
        if sender is None or recipient is None or amount is None:
            return jsonify({"error": "Invalid request data"}), 400

        # Check if the transfer request exists and if permission is granted
        transfer_request = next((req for req in list(coin.request_queue.queue) if req.permission['id'] == hash), None)

        if transfer_request and transfer_request.permission['processed']:
            # Ensure the request has the appropriate permission
            if transfer_request.permission['permission'] == 'approved':
                # Proceed with the transfer
                if ledger.add_transfer_transaction(amount, fee, hash, pub_key, recipient, sender, signature, sub_type, type):
                    response = {'message': 'Transfer tx built successfully. It will be mined in the next block'}
                    return jsonify(response), 200
                else:
                    response = {'message': 'Failed to transfer coins'}
                    return jsonify(response), 400
            else:
                return jsonify({"error": "Permission not granted for this transfer"}), 403
        else:
            return jsonify({"error": "Transfer request not found or not processed"}), 404

    except ValueError as e:
        return jsonify({'success': False, 'message': str(e)}), 400
    except Exception as e:
        return jsonify({'success': False, 'message': 'Internal Server Error'}), 500

# Create Transfer Request
@app.route('/create_transfer_request', methods=['POST'])
def create_transfer_request():
    data = request.get_json()

    sender = data.get('from_address')
    recipient = data.get('to_address')
    amount = data.get('amount')
    permission = data.get('permission')

    if sender is None or recipient is None or amount is None:
        return jsonify({"error": "Invalid request data"}), 400

    request = coin.create_transfer_request(sender, recipient, amount, permission)
    return jsonify({"message": "Transfer request created successfully", "request_id": request.permission['id']}), 200

# Approve Transfer Request
@app.route('/approve_transfer_request/<request_id>', methods=['POST'])
def approve_transfer_request(request_id):
    data = request.get_json()
    sender_pub = data['sender_pub']
    permission_sig = data['permission_sig']

    if coin.approve_transfer_request(request_id, sender_pub, permission_sig):
        return jsonify({"message": "Transfer request approved successfully"}), 200
    else:
        return jsonify({"error": "Failed to approve transfer request"}), 400

# Process Transfer Request
@app.route('/process_transfer_request/<request_id>', methods=['POST'])
def process_transfer_request(request_id):
    if coin.process_transfer_request(request_id):
        return jsonify({"message": "Transfer request processed successfully"}), 200
    else:
        return jsonify({"error": "Failed to process transfer request"}), 400

# Get Specific Transfer Request
@app.route('/get_request/<request_id>', methods=['GET'])
def get_request(request_id):
    with coin.balance_lock:
        requested_request = next((request_obj for request_obj in list(coin.request_queue.queue)
                                 if request_obj.permission['id'] == request_id), None)
        if requested_request:
            return jsonify({
                'from_address': requested_request.from_address,
                'to_address': requested_request.to_address,
                'amount': requested_request.amount,
                'permission': {
                    'amount': requested_request.permission['amount'],
                    'created': requested_request.permission['created'].isoformat(),
                    'from_address': requested_request.permission['from_address'],
                    'id': requested_request.permission['id'],
                    'permission': None,
                    'processed': None,
                    'to_address': requested_request.permission['to_address']
                },
                'timestamp': requested_request.timestamp.isoformat()
            })
        else:
            return jsonify({'error': 'Request not found'}), 404

# Get All Unprocessed Requests
@app.route('/get_requests', methods=['GET'])
def get_requests():
    with coin.balance_lock:
        filtered_requests = [
            {
                'from_address': request_obj.from_address,
                'to_address': request_obj.to_address,
                'amount': request_obj.amount,
                'permission': {
                    'amount': request_obj.permission['amount'],
                    'created': request_obj.permission['created'].isoformat(),
                    'from_address': request_obj.permission['from_address'],
                    'id': request_obj.permission['id'],
                    'permission': None,
                    'processed': None,
                    'to_address': request_obj.permission['to_address']
                },
                'timestamp': request_obj.timestamp.isoformat()
            }
            for request_obj in list(coin.request_queue.queue)
            if request_obj.permission['processed'] is None
        ]
        return jsonify(filtered_requests)

# Update Request Permissions
@app.route('/update_request_permissions/<request_id>', methods=['POST'])
def update_request_permissions(request_id):
    try:
        data = request.get_json()
        sender_pub = data.get('sender_pub')
        permission_sig = data.get('permission_sig')
        permission_approval = data.get('permission_approval')

        if not sender_pub or not permission_sig or not permission_approval:
            return jsonify({'error': 'Invalid request data'}), 400

        with coin.balance_lock:
            coin.update_request_permissions(request_id, sender_pub, permission_sig, permission_approval)

        return jsonify({'success': 'Request permissions updated successfully'})
    except ValueError as e:
        logging.error(f"ValueError: {e}")
        return jsonify({'error': str(e)}), 400
    except Exception as e:
        logging.error(f"Exception: {e}")
        return jsonify({'error': 'Internal Server Error'}), 500

# OMC info
@app.route('/omc_info', methods=['GET'])
def coin_info():
    return jsonify({
        'name': coin.name,
        'symbol': coin.symbol,
        'decimals': coin.decimals,
        'image': coin.image
    })

# Find coin
@app.route('/find_coin', methods=['POST'])
def find_coin():
    data = request.get_json()
    address = data.get('address')

    if address == coin.id:
        # Return details for coin1
        return jsonify({
            'name': coin.name,
            'symbol': coin.symbol,
            'decimals': coin.decimals,
            'id': coin.id,
            'image': coin.image
        })
    elif address == staked_coin.id:
        return jsonify({
            'name': staked_coin.name,
            'symbol': staked_coin.symbol,
            'decimals':staked_coin.decimals,
            'id': staked_coin.id,
            'image': staked_coin.image,
        })
    else:
        # Return a message if the address does not match any known addresses
        return jsonify({'message': 'Address not found'}), 404

# Retrieve base coins
@app.route('/retrieve_base_coins', methods=['GET'])
def retrieve_base_coins():
    # Prepare a list of all coins
    all_coins = [
        {
            'name': coin.name,
            'symbol': coin.symbol,
            'decimals': coin.decimals,
            'id': coin.id,
            'image': coin.image
        },
        {
            'name': staked_coin.name,
            'symbol': staked_coin.symbol,
            'decimals': staked_coin.decimals,
            'id': staked_coin.id,
            'image': staked_coin.image
        }
    ]

    # Return the list of all coins
    return jsonify(all_coins)

# Endpoint to check the balance of a wallet
@app.route('/omc_balance', methods=['POST'])
def get_account_balance():
    json_ = request.get_json()
    address = json_['address']

    # Debug log to check the address you're looking for
    app.logger.debug(f"Searching for balance of address: {address}")

    balance = coin.get_balance(address)

    if balance is not None:
        # Debug log to check the balance you found
        app.logger.debug(f"Found balance {balance} for address: {address}")

        response = {
            'message': 'Account balance retrieved successfully',
            'balance': balance,
            'balance_float': balance / (10 ** coin.decimals)
        }
        return jsonify(response), 200
    else:
        app.logger.debug(f"Address {address} not found in coin.balance")
        return 'Account not found', 404

# Stake OMC
@app.route('/stake_omc', methods=['POST'])
def stake_coins():
    try:
        json_ = request.get_json()
        address = json_['address']
        amount = json_['amount']
        fee = json_['fee']
        hash = json_['hash']
        pub_key = json_['pub_key']
        min_term = json_['min_term']
        node_address = ledger.randomly_select_validator()
        signature = json_['signature']
        sub_type = json_['sub_type']

        transaction = {
            'address': address,
            'amount': amount,
            'fee': fee,
            'hash': hash,
            'pub_key': pub_key,
            'min_term': min_term,
            'node_address': node_address,
            'signature': signature,
            'sub_type': sub_type,
            'type': 'r'
        }

        if ledger.add_staking_transaction(address, amount, fee, hash, pub_key, min_term, node_address, signature, sub_type, type):
            response = {
                'message': 'Stake tx built successfully. It will be mined in the next block'}
            return jsonify(response), 200
        else:
            response = {'message': 'Failed to stake coins'}
            return jsonify(response), 400

    except ValueError as e:
        return jsonify({'success': False, 'message': str(e)}), 400
    except Exception as e:
        return jsonify({'success': False, 'message': 'Internal Server Error'}), 500

# Unstake coins
@app.route('/unstake_omc', methods=['POST'])
def unstake_coins():
    try:
        json_ = request.get_json()
        address = json_['address']
        amount = json_['amount']
        contract_id = json_['contract_id']
        fee = json_['fee']
        hash = json_['hash']
        pub_key = json_['pub_key']
        signature = json_['signature']
        sub_type = json_['sub_type']

        transaction = {
            'address': address,
            'amount': amount,
            'contract_id': contract_id,
            'fee': fee,
            'hash': hash,
            'pub_key': pub_key,
            'signature': signature,
            'sub_type': sub_type,
            'type': 'o'
        }

        if ledger.add_unstaking_transaction(address, amount, contract_id, fee, hash, pub_key, signature, sub_type, type):
            response = {
                'message': 'Unstake tx built successfully. It will be mined in the next block'}
            return jsonify(response), 200
        else:
            response = {'message': 'Failed to stake coins'}
            return jsonify(response), 400

    except ValueError as e:
        return jsonify({'success': False, 'message': str(e)}), 400
    except Exception as e:
        return jsonify({'success': False, 'message': 'Internal Server Error'}), 500

# Endpoint to check the sOMC balance of a wallet
@app.route('/somc_balance', methods=['POST'])
def get_account_somc_balance():
    json_ = request.get_json()
    address = json_['address']

    # Debug log to check the address you're looking for
    app.logger.debug(f"Searching for balance of address: {address}")

    balance = staked_coin.get_balance(address)

    if balance is not None:
        # Debug log to check the balance you found
        app.logger.debug(f"Found balance {balance} for address: {address}")

        response = {
            'message': 'Account balance retrieved successfully',
            'balance': balance,
            'balance_float': balance / (10 ** coin.decimals)
        }
        return jsonify(response), 200
    else:
        app.logger.debug(f"Address {address} not found in coin.balance")
        return 'Account not found', 404

# sOMC info
@app.route('/somc_info', methods=['GET'])
def somc_info():
    return jsonify({
        'name': staked_coin.name,
        'symbol': staked_coin.symbol,
        'decimals': staked_coin.decimals,
        'image': staked_coin.image
    })

# # Get activity for wallet
@app.route('/check_activity', methods=['POST'])
def check_activity():
    data = request.get_json()
    address = data.get('address')

    if not address:
        return jsonify({"error": "Address not provided"}), 400

    # Initialize result dictionaries for each history type
    transfer_result = 0
    minting_result = 0
    burning_result = 0
    other_activity_result = 0

    # Check for the address in each history list and calculate the total for other_activity
    for from_address, to_address, amount in coin.transfer_history:
        if from_address == address:
            transfer_result -= amount
        if to_address == address:
            transfer_result += amount

    for to_address, amount in coin.minting_history:
        if to_address == address:
            minting_result += amount

    for amount in coin.burning_history:
        burning_result -= amount

    # Prepare the response
    response_data = {
        "address": address,
        "transfer_history": transfer_result,
        "minting_history": minting_result,
        "burning_history": burning_result
    }

    return jsonify(response_data), 200

#Get circulation figures for OMC
@app.route('/get_coin_economy', methods=['GET'])
def get_max_coin_economy():
    return jsonify(coin.report_coin_economy())

# Whitelist address for pOMC
@app.route('/whitelist_address_for_pomc', methods=['POST'])
def whitelist_address_for_pomc():
    data = request.json
    address = data.get('address')
    pub_key = data.get('pub_key')
    signature = data.get('signature')

    if not address:
        return jsonify({"message": "Address is required"}), 400
    
    if not pub_key:
        return jsonify({"message": "Public key is required"}), 400
    
    if not signature:
        return jsonify({"message": "Signature is required"}), 400

    try:
        precursor_coin.whitelist_address(address, pub_key, signature)
        return jsonify({"message": f"Address {address} whitelisted successfully"}), 200
    except ValueError as e:
        return jsonify({"message": str(e)}), 400
    except Exception as e:
        return jsonify({"message": "An error occurred", "error": str(e)}), 500

#==== BLOCK PROPAGATION OPS ====#

#receive new block
@app.route('/blocks/receive_block', methods=['POST'])
def receive_block_endpoint():
    received_block = request.get_json()  # Parse JSON data from the request

    if ledger.receive_block(received_block):
        # Block successfully added to the local blockchain
        return 'Block received and processed successfully', 200
    else:
        # If there's an issue processing the block
        response = {'message': 'Issue processing the received block'}
        return jsonify(response), 400

# Endpoint for adding a block
@app.route('/blocks/add', methods=['POST'])
def add_block():
    block_data = request.get_json()
    ledger.add_block(block_data)
    return "Block added successfully"

# Endpoint for reaching consensus on a proposed block
@app.route('/blocks/consensus', methods=['POST'])
def reach_consensus():
    proposed_block = request.get_json()
    ledger.reach_consensus(proposed_block)
    return "Consensus reached for the proposed block"

#==== TRANSACTIONS ====#

# Retrieve transaction to validate and vote on
@app.route('/transactions/receive_tx', methods=['POST'])
def receive_transaction():
    transaction = request.get_json()  # Parse JSON data from the request

    # Assume transaction is a dictionary with 'address', 'pub_key', 'new_tx', and 'signature'
    if ledger.receive_tx(transaction['address'], transaction['hash'], transaction['pub_key'], transaction['new_tx'], transaction['signature']):
        return 'Transaction received and validateded successfully', 200
    else:
        response = {'message': 'Issue validating the received transaction'}
        return jsonify(response), 400

#==== USER OPERATIONS ====#

@app.route('/get_latest_price', methods=['GET'])
def get_latest_price():
    latest_price = 1.00  # Replace this with the actual logic to get the latest price
    return jsonify({'price': latest_price})

@app.route('/initialize_lockup', methods=['POST'])
def initialize_lockup():
    try:
        data = request.get_json()
        amount = data['amount']
        address1 = data['address1']
        address2 = data['address2']

        success = vault.initialize_lockup(amount, address1, address2)
        if success:
            return jsonify({'message': 'Lockup initialized successfully.'}), 200
        else:
            return jsonify({'message': 'Failed to initialize lockup.'}), 400
    except KeyError as e:
        logging.error(f"Missing key in request data: {e}")
        return jsonify({'error': f"Missing key in request data: {e}"}), 400
    except Exception as e:
        logging.error(f"An error occurred: {e}")
        return jsonify({'error': f"An error occurred: {e}"}), 500

#run it
if __name__ == '__main__':
    app.run(host='0.0.0.0', port=3400)