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

HASH_API_URL = "http://localhost:3000/hashes"

def fetch_auth_token():
    try:
        response = requests.get(f"{HASH_API_URL}/auth-token")
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

class Oracle:
    def __init__(self, api_key=None, current_node_url="http://current-node-url:3400"):
        self.current_node_url = current_node_url
        self.services = self.discover_services("node")

    def fetch_price(self):
        # Discover services if not already discovered
        if not self.services:
            self.services = self.discover_services("node")

        # Attempt to fetch price from each discovered service
        for service in self.services:
            try:
                url = f"http://{service}:3400/get_latest_price"
                response = requests.get(url)
                if response.status_code == 200:
                    data = response.json()
                    usd_to_other_currency = data.get("price", None)
                    if usd_to_other_currency is not None:
                        return usd_to_other_currency
                    else:
                        logging.error("Currency data not found in the response.")
                else:
                    logging.error(f"Failed to fetch currency data from {service}. Status code: {response.status_code}")
            except Exception as e:
                logging.error(f"Error fetching currency data from {service}: {e}")

        raise ValueError("Error fetching currency data from all available nodes.")

    def discover_services(self, prefix):
        discovered_services = []
        max_range = 10

        for i in range(1, max_range):
            service_name = f"{prefix}{i}.omne"
            try:
                service_address = socket.gethostbyname(service_name)
                if service_address != self.current_node_url:
                    discovered_services.append(service_name)
                    logging.debug(f"Discovered service: {service_name}")
            except socket.gaierror:
                continue

        if not discovered_services:
            logging.warning("No services were discovered.")
        return discovered_services

class Verifier:
    def __init__(self):
        self.verified_nodes = []
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
        for node in self.verified_nodes:
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
        self.calculate_stake_weights()  # Make sure this updates the stake weights in self.verified_nodes

        # Corrected the sum to properly handle both dict and Node instances
        total_stake_weight = sum(node['stake_weight'] if isinstance(node, dict) else node.stake_weight for node in self.verified_nodes)
        random_number = random.uniform(0, total_stake_weight)
        cumulative_stake_weight = 0

        for node in self.verified_nodes:
            node_stake_weight = node['stake_weight'] if isinstance(node, dict) else node.stake_weight
            cumulative_stake_weight += node_stake_weight

            if cumulative_stake_weight > random_number:
                return node

        logging.warning("No validator was selected, returning None.")
        return None

class CUtils:
    def __init__(self):
        u = {}

    @staticmethod
    def generate_mnemonic():
        mnemonic = Mnemonic('english').generate(strength=128)
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
        """
        Sign a transaction using the private key bytes after hashing the transaction data.
        Returns the signature as a hexadecimal string.
        """
        # Convert the private key bytes to a SigningKey object
        private_key = ecdsa.SigningKey.from_string(private_key_bytes, curve=ecdsa.SECP256k1)

        # Serialize the transaction data and sort keys
        transaction_data_str = json.dumps(transaction, sort_keys=True, cls=CustomEncoder)

        # Hash the serialized transaction data using SHA256
        transaction_data_hash = hashlib.sha256(transaction_data_str.encode('utf-8')).digest()

        # Sign the hashed transaction data
        signature = private_key.sign(transaction_data_hash, sigencode=sigencode_der)

        # Return the signature as a hexadecimal string
        return signature.hex()

    @staticmethod
    def verify_transaction(public_key_str, transaction, signature_base64):
        try:
            # Convert the public key from hex to a VerifyingKey
            public_key_bytes = bytes.fromhex(public_key_str)
            verifying_key = ecdsa.VerifyingKey.from_string(public_key_bytes, curve=ecdsa.SECP256k1)

            # Serialize transaction data for hashing, ensuring keys are sorted for consistent hashing
            transaction_data_str = json.dumps(transaction, sort_keys=True)

            # Create a SHA256 hash of the serialized transaction data
            transaction_data_hash = sha256(transaction_data_str.encode('utf-8')).digest()

            # Decode the base64 signature to bytes
            signature_bytes = base64.b64decode(signature_base64)

            # Verify the signature against the hash of the transaction data
            if verifying_key.verify(signature_bytes, transaction_data_hash, hashfunc=sha256, sigdecode=ecdsa.util.sigdecode_der):
                return True, "Signature verified"
            else:
                return False, "Signature does not match"
        except ecdsa.BadSignatureError:
            return False, "Bad signature"
        except Exception as e:
            return False, f"Verification failed with error: {e}"

    @staticmethod
    def decrypt_val(cipher_text, hex_key):
        # Convert hex string to byte array
        key = bytes.fromhex(hex_key)

        # Ensure the key is of valid length (16, 24, or 32 bytes)
        if len(key) not in [16, 24, 32]:
            raise ValueError("Incorrect AES key length (%d bytes)" % len(key))

        decipher = AES.new(key, AES.MODE_ECB)
        decrypted_text = decipher.decrypt(base64.b64decode(cipher_text))
        return decrypted_text.strip().decode('utf-8')

    @staticmethod
    def calculate_sha256_hash(transaction: dict) -> str:
        """
        Calculate the SHA256 hash of a transaction dictionary.
        Returns the hash as a hexadecimal string.
        """
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
    def __init__(self, oracle, rebaser):
        self.init_date = datetime.now(timezone.utc)
        self.accounts = []
        self.name = 'Medivolve Coin'
        self.symbol = 'OMC'
        self.decimals = 18
        self.cge_base = 13300000
        self.initial_supply = self.cge_base * (10 ** self.decimals)
        self.balance = {}
        self.circulating_supply = 0.0
        self.treasury_address = "0x123"
        self.oracle = oracle
        self.rebaser = rebaser
        self.last_known_price = None
        self.balance_lock = threading.Lock()
        self.total_staked = 0.0
        self.total_minted = 0
        self.total_burned = 0
        self.staked_coins = []

        self.fetch_current_price_from_oracle()

    def get_balance(self, address):
        with self.balance_lock:
            return self.balance.get(address, Decimal(0))

    def fetch_current_price_from_oracle(self):
        return self.oracle.fetch_price()

    def is_within_band(self, price):
        return self.rebaser.price_band[0] <= price <= self.rebaser.price_band[1]

    def transfer(self, from_address, to_address, amount):
        with self.balance_lock:
            if self.balance.get(from_address, 0) >= amount:
                fee = amount * 0.01
                self.balance[from_address] -= amount
                self.balance[to_address] = self.balance.get(to_address, 0) + (amount - fee)
                self.balance[self.treasury_address] += fee
                logging.info(f"Transferred {amount - fee} from {from_address} to {to_address}. Fee {fee} to treasury.")
                return True
            else:
                logging.error("Insufficient balance for transfer")
                return False

    def mint_coins(self, to_address, amount):
        with self.balance_lock:
            fee = amount * 0.01
            self.balance[to_address] = self.balance.get(to_address, 0) + (amount - fee)
            self.balance[self.treasury_address] += fee
            self.circulating_supply += amount
            self.total_minted += amount
            logging.info(f"Minted {amount - fee} to {to_address}. Fee {fee} to treasury.")
            return True

    def burn_coins(self, from_address, amount):
        burn_address = "0b0000000000000000000000000000000000000000"
        with self.balance_lock:
            if self.balance.get(from_address, 0) >= amount * (10 ** self.decimals):
                self.balance[from_address] -= amount * (10 ** self.decimals)
                self.balance[burn_address] = self.balance.get(burn_address, 0) + amount * (10 ** self.decimals)
                self.circulating_supply -= amount
                self.total_burned += amount
                logging.info(f"Burned {amount} coins from {from_address}, transferred to burn address {burn_address}.")
                return True
            else:
                logging.error("Insufficient balance for burn")
                return False

    def report_coin_economy(self):
        normalized_circulating_supply = self.circulating_supply / (10 ** self.decimals)
        normalized_total_minted = self.total_minted / (10 ** self.decimals)
        normalized_total_burned = self.total_burned / (10 ** self.decimals)

        if self.last_known_price is not None:
            conversion_rate = f" ${self.last_known_price}"
        else:
            conversion_rate = "Current price not available"

        return {
            'circulating_supply_raw': str(self.circulating_supply),
            'circulating_supply_normalized': str(normalized_circulating_supply),
            'total_minted': str(normalized_total_minted),
            'total_burned': str(normalized_total_burned),
            'current_conversion_rate': conversion_rate
        }

    def mint_for_block_fee(self, base_amount, transaction_fee):
        adjustment_factor = 0.08
        base_fee = 47

        if transaction_fee > base_fee:
            percent_increase = ((transaction_fee - base_fee) / base_fee) * 100
            number_of_adjustments = percent_increase // 5
            for _ in range(int(number_of_adjustments)):
                base_amount *= (1 - adjustment_factor)

        with self.balance_lock:
            self.balance[self.treasury_address] += base_amount
            self.circulating_supply += base_amount
            self.total_minted += base_amount
            logging.info(f"Minted {base_amount} to treasury for block fee purposes.")

        return base_amount

    def broadcast_price_data(self, price):
        self.oracle.broadcast_price_data(price)

class Rebaser:
    def __init__(self, omc, target_price=1.00, price_band=(0.87, 1.10), price_change_threshold=0.02, rebase_interval_minutes=60):
        self.omc = omc
        self.target_price = target_price
        self.price_band = price_band
        self.price_change_threshold = price_change_threshold
        self.rebase_interval_minutes = rebase_interval_minutes
        self.last_rebase_time = time.time()

        self.monitor_thread = threading.Thread(target=self.background_monitoring)
        self.monitor_thread.daemon = True
        self.monitor_thread.start()

    def should_rebase(self, new_price):
        if self.omc.last_known_price is None:
            return True
        price_change = abs(new_price - self.omc.last_known_price) / self.omc.last_known_price
        return price_change >= self.price_change_threshold

    def calculate_rebase_factor(self, current_price):
        if current_price > self.target_price:
            percentage_change = (current_price - self.target_price) / self.target_price
            return max(0.5, min(2.0, (1 + percentage_change ** 0.5)))
        elif current_price < self.target_price:
            percentage_change = (self.target_price - current_price) / self.target_price
            return max(0.5, min(2.0, (1 - percentage_change ** 0.5)))
        return 1.0

    def rebase(self, new_price):
        with self.omc.lock:
            if self.should_rebase(new_price):
                rebase_factor = self.calculate_rebase_factor(new_price)
                for address in list(self.omc.balance):
                    self.omc.balance[address] *= rebase_factor
                self.omc.circulating_supply *= rebase_factor
                self.omc.last_known_price = new_price
                logging.info(f"Rebase executed. New supply: {self.omc.circulating_supply}, Rebase factor: {rebase_factor}")
                self.omc.broadcast_price_data(new_price)

    def background_monitoring(self):
        while True:
            try:
                current_time = time.time()
                if current_time - self.last_rebase_time >= self.rebase_interval_minutes * 60:
                    current_price = self.omc.fetch_current_price_from_oracle()
                    if current_price and not self.omc.is_within_band(current_price):
                        self.rebase(current_price)
                        self.last_rebase_time = current_time
                time.sleep(60)
            except Exception as e:
                logging.error(f"Background monitoring error: {e}")

class AccMngr:
    def __init__(self):
        self.accounts = []
        self.precursor_accounts = []
        self.staking_accounts = []

    def generate_account_from_mnemonic(self, mnemonic: str) -> dict:
        private_key, public_key = crypto_utils.generate_keys_from_mnemonic(mnemonic)
        return {'address': '0b' + public_key[-40:], 'pub_key': public_key, 'private_key': private_key, 'mnemonic': mnemonic}

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
        self.id = "0b48d76b0690dcdcb32f1893d75c99681f2b595b36"
        self.image = "https://bafybeihbanfylphrqzpzgaibz6pwwl7wyq7kp2n2yt2bq4irrrwirwgcga.ipfs.w3s.link/sOMC-3.png"
        self.balance = {}
        self.burn_address = "0b0000000000000000000000000000000000000000"
        self.staked_omc_distributed = 0.0
        self.treasury_address = None

    def mint(self, recipient, amount):
        """
        Mint staked coins and send them to the specified recipient.
        """
        if amount <= 0:
            raise ValueError("Amount must be a positive value")

        # Convert the staked amount to a value with the correct number of decimal places
        amount_with_decimals = amount * (10 ** self.decimals)

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
        logging.info(f"Stake on node: {node_address}")
        try:
            if not self.check_balance_for_staking(address, amount):
                raise ValueError("Insufficient balance for staking")
        except ValueError as e:
            raise ValueError("Failed to check balance for staking: " + str(e))

        # Generate a unique hexadecimal contract ID for the staking agreement
        contract_id = '0s' + str(secrets.token_hex(16))

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

        # Mint StakedOMC and send them to the wallet
        staked_coin.mint(address, amount)

        # Add staking details to the wallet's staking agreements
        self.staking_agreements.append(staking_contract)

        logging.warning(f"Staked {amount} OMC for {min_term} days successfully. Contract ID: {contract_id}")

        # Return the staking contract to the caller
        return staking_contract

    def unstake_coins(self, staking_address, contract_id):
        current_time = time.time()

        for agreement in self.staking_agreements.copy():
            staking_address_agreement = agreement['address']
            staking_amount = agreement['amount']
            min_term = agreement['min_term']
            agreement_contract_id = agreement['contract_id']

            if current_time >= agreement['staking_end_time'] and staking_address_agreement == staking_address and agreement_contract_id == contract_id:
                # Remove the staking agreement from the list
                self.staking_agreements.remove(agreement)

                # Update the OMC staked_coins and total_staked
                for staked_coin in coin.staked_coins.copy():
                    if staked_coin['address'] == staking_address_agreement and staked_coin['amount'] == staking_amount and staked_coin['contract_id'] == contract_id:
                        coin.staked_coins.remove(staked_coin)
                        coin.total_staked -= staking_amount

                # Mint and send the unstaked OMC back to the wallet
                staked_omc_balance = staked_omc.get_balance(staking_address_agreement)
                staked_omc.burn(staking_address_agreement, staked_omc_balance)

                # Credit the wallet with the unstaked OMC
                account_manager.credit_account(staking_address_agreement, staked_omc_balance, staking_address_agreement, 'unstake')

                logging.warning(f"Unstaked {staked_omc_balance} OMC for {min_term} days from {staking_address_agreement}. Contract ID: {contract_id}")

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
    def generate_key_from_passphrase(self, private_key, password):
        try:
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
    def __init__(self, current_node_url="http://current-node-url:3400", address=None, stake_weight=0,
                 version="0.0.1", private_key=None, public_key=None, signature=None, steward=None):
        self.address = address
        self.stake_weight = stake_weight
        self.version = version
        self.private_key = private_key
        self.public_key = public_key
        self.signature = signature
        self.steward = steward
        self.current_node_url = current_node_url
        
        # Discover existing services and set the URL dynamically
        discovered_services = self.discover_services("node")
        node_num = len(discovered_services) + 1
        self.url = f"http://node{node_num}.omne:3400"

        # If address and keys are not provided, generate new ones
        if not self.address or not self.private_key or not self.public_key:
            mnemonic = crypto_utils.generate_mnemonic()
            account = account_manager.generate_account_from_mnemonic(mnemonic)

            # Extract key data
            self.address = account['address']
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

    def discover_services(self, prefix):
        discovered_services = []
        max_range = 10

        for i in range(1, max_range):
            service_name = f"{prefix}{i}.omne"
            try:
                service_address = socket.gethostbyname(service_name)
                if service_address != self.current_node_url:
                    discovered_services.append(service_name)
                    logging.debug(f"Discovered service: {service_name}")
            except socket.gaierror:
                continue

        if not discovered_services:
            logging.warning("No services were discovered.")
        return discovered_services

class Block:
    def __init__(self, index: int, fee: int, previous_hash: str, timestamp: str, transactions: list, validator: str, validator_fee: int):
        self.index = index
        self.previous_hash = previous_hash
        self.timestamp = timestamp
        self.transactions = transactions
        self.nonce = 0
        self.fee = fee
        self.hash = self.calculate_hash()
        self.validator = validator
        self.validator_fee = validator_fee

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

class DoubleSpendingError(Exception):
    def __init__(self, message="Double spending detected"):
        self.message = message
        super().__init__(self.message)

class Blockchain:
    def __init__(self, node, wallet, transactions, treasury, verifier):
        self.node = node
        self.wallet = wallet
        self.transactions = transactions
        self.treasury = treasury
        self.verifier = verifier

        self.open_bounties = []
        self.claimed_bounties = {}
        self.completed_bounties = []
        self.accounts = []
        self.chain = []
        self.block_hashes = set()
        self.lock = threading.Lock()
        logging.basicConfig(level=logging.DEBUG)
        self.nodes = []
        self.validators = []

    @staticmethod
    def serialize_and_create_single_hash(cls):
        # Ensure cls is a class type, not an instance
        if not isinstance(cls, type):
            raise TypeError(f"Expected class type, got {type(cls)}")

        # Serialize the class's attributes and methods
        try:
            # Gather class attributes and methods
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
            'verifier': Verifier,
            'crypto_utils': CUtils,
            'fee_calculator': DynamicFeeCalculator
        }

        for class_name, cls in classes_to_verify.items():
            stored_hash = stored_hashes.get(class_name)
            if not stored_hash:
                logging.error(f"Stored hash for class {class_name} not found in the public API response.")
                raise ValueError(f"Stored hash for class {class_name} not found.")

            local_hash = Blockchain.serialize_and_create_single_hash(cls)
            if stored_hash != local_hash:
                logging.error(f"Hash mismatch for class {class_name}. Possible tampering detected.")
                raise ValueError(f"Hash mismatch for class {class_name}. Possible tampering detected.")

        logging.info("All class hashes verified successfully. No tampering detected.")
        return True

    def initialize_node(self):
        """
        Initialize the node after class hashes have been verified.
        """
        # Service discovery and pinging
        service_prefix = "node"  # Adjust the prefix according to your container naming convention
        services = self.discover_services(service_prefix)
        if services:  # Ensure services is not None or empty
            self.ping_services(services, "check_nodes", self.node.url)

        # Set steward address from environment variable
        self.node.steward = os.getenv('STEWARD_ADDRESS')
        if not self.node.steward:
            raise ValueError("Steward address not provided. Set the STEWARD_ADDRESS environment variable.")

        self.update_node_state(self.node)
        self.check_chain_length_and_sync(services)
        self.update_validators()
        self.broadcast_node_data(self.node)

        # Start the mining thread
        mining_thread = threading.Thread(target=self.mine_new_block_periodically)
        mining_thread.daemon = True  # Daemonize the thread
        mining_thread.start()
        
    def create_bounty_for_new_physician(self, physician):
        bounty = {
            'id': '0o' + str(secrets.token_hex(19)),
            'name': f"{physician['first_name']} {physician['last_name']}",
            'state': physician['contact_info']['state'],
            'license_number': physician['license_number'],
            'verification_url': "",
            'status': "Unverified",
            'bounty_hunter': "",
            'target_class': ['physician']  # This bounty is only accessible to other physicians
        }
        self.bounties.append(bounty)
        logging.info(f"Bounty created for new physician: {bounty['name']}")
        return True

    def claim_bounty(self, bounty_id, claimant_address):
        # Move bounty from open to claimed if available
        for bounty in self.open_bounties:
            if bounty['id'] == bounty_id and 'physician' in bounty['target_class']:  # Ensure the bounty is intended for physicians
                self.open_bounties.remove(bounty)
                bounty['bounty_hunter'] = claimant_address
                bounty['status'] = 'Claimed'
                self.claimed_bounties[bounty_id] = {
                    'bounty': bounty,
                    'claimant': claimant_address,
                    'deadline': datetime.utcnow() + timedelta(hours=24)  # Set 24-hour deadline
                }
                return True, "Bounty claimed successfully."
        return False, "Bounty not available or already claimed."

    def check_bounty_status(self):
        # Revert expired bounties to the open list
        expired_bounties = [b_id for b_id, b_info in self.claimed_bounties.items() if b_info['deadline'] < datetime.now()]
        for b_id in expired_bounties:
            bounty_info = self.claimed_bounties.pop(b_id)
            self.open_bounties.append(bounty_info['bounty'])
            print(f"Bounty {b_id} has expired and is now open again.")

    def update_bounty_verification(self, bounty_id, verification_url, hunter_address):
        # Find the claimed bounty and ensure the claimant matches
        if bounty_id in self.claimed_bounties and self.claimed_bounties[bounty_id]['claimant'] == hunter_address:
            bounty = self.claimed_bounties[bounty_id]['bounty']
            bounty['verification_url'] = verification_url
            bounty['status'] = 'Pending'  # Update status to pending verification
            # Update deadline
            self.claimed_bounties[bounty_id]['deadline'] = datetime.utcnow() + timedelta(hours=24)
            return True, "Bounty updated successfully for verification."
        return False, "No matching bounty found or mismatched claimant."

    def randomly_select_validator(self):
        if not self.validators:
            logging.warning("No validators available.")
            return None

        # Randomly select a validator address from the list
        validator_address = random.choice(self.validators)

        logging.info(f"Randomly selected validator address: {validator_address}")
        return validator_address

    @staticmethod
    def trigger_sync_on_all_nodes(self):
        # Discover all services (nodes)
        services = self.discover_services("node")

        # Data to send - it can be an empty dictionary if no data needs to be sent
        data = {}

        # Trigger sync on each service by calling the '/trigger_sync' endpoint
        for service in services:
            service_base_url = f"http://{service}:3400"

            # Check if the base service URL is the same as the current node's URL
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
                logging.error(f"Error triggering sync on {service_url}: {e}")

    def discover_services(self, prefix):
        discovered_services = []
        max_range = 10  # Adjust the range as needed

        for i in range(1, max_range):
            service_name = f"{prefix}{i}.medivolve"
            try:
                service_address = socket.gethostbyname(service_name)

                # Check if the discovered service is not the current node
                if service_address != self.node.url:
                    discovered_services.append(service_name)
                    logging.debug(f"Discovered service: {service_name}")

            except socket.gaierror:
                continue  # Service not found, move to the next

        if not discovered_services:
            logging.warning("No services were discovered.")

        return discovered_services

    def ping_services(self, services, endpoint, current_node_url):
        # Assuming AUTH_TOKEN is accessible here, or retrieve it as needed
        headers = {"Authorization": f"Bearer {AUTH_TOKEN}"}

        for service in services:
            service_base_url = f"http://{service}:3400"
            service_url = f"{service_base_url}/{endpoint}"

            # Check if the base service URL is the same as the current node's URL
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
                        if not any(node['address'] == received_node['address'] for node in self.nodes):
                            self.nodes.append(received_node)
                            self.verifier.verified_nodes.append(received_node)
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

            # Check if the base service URL is the same as the current node's URL
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
        if not node or not node.address or not node.url:
            logging.error("Node information is incomplete or incorrect. Cannot broadcast.")
            return

        node_info = node.to_dict()
        logging.info(f"Broadcasting self node information: {node_info}")

        services = self.discover_services("node")
        if not services:
            logging.warning("No other services discovered for broadcasting. Broadcast aborted.")
            return

        # Exclude the current node's URL from the services list
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

            # Skip posting to itself
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

        # Iterating through all services to find the node with the longest chain
        for service in services:
            service_base_url = f"http://{service}:3400"
            service_url = f"{service_base_url}/get_chain"

            if service_base_url == self.node.url:
                continue

            try:
                response = requests.get(service_url)
                if response.status_code == 200:
                    other_chain = response.json()["chain"]
                    # Only update if the other node's chain is longer than the current longest chain
                    if len(other_chain) > my_chain_length:
                        my_chain_length = len(other_chain)
                        synchronized_chain = other_chain
                        authoritative_node_url = service_base_url
            except requests.exceptions.RequestException as e:
                logging.error(f"Error while trying to sync with {service_url}: {e}")

        # Update the local chain if a longer chain was found
        if synchronized_chain:
            self.chain = synchronized_chain

        return authoritative_node_url, synchronized_chain

    def broadcast_node_data(self, node):
        headers = {"Authorization": f"Bearer {AUTH_TOKEN}"}
        # Prepare data for broadcasting
        node_data_complete = {
            'address': node.address,
            'public_key': node.public_key,
            'url': node.url,
            'stake_weight': node.stake_weight,
            'version': node.version,
            'steward': node.steward
        }

        # Fetch service list
        services = self.discover_services("node")

        # Iterate through services and post the node data
        for service in services:
            service_base_url = f"http://{service}:3400"
            service_url = f"{service_base_url}/receive_node_data"

            # Skip posting to itself
            if service_base_url == self.node.url:
                continue

            # Post the node data to the service
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
        # Prepare data for broadcasting
        new_acount = {
            'address': address,
            'balance': balance
        }

        # Fetch service list
        service_prefix = "node"
        services = self.discover_services(service_prefix)

        # Exclude the current node to prevent recursion
        filtered_services = [s for s in services if f"http://{s}:3400" != node.url]
        self.post_data_to_services(filtered_services, "propagate_account", new_acount)

    def update_node_state(self, new_node):
        # Add node to the local state without broadcasting
        # This is invoked by the receive_node_data endpoint
        if new_node not in self.nodes:
            self.nodes.append(new_node)
            self.verifier.verified_nodes.append(new_node)
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
        current_timestamp = datetime.now(pytz.UTC)
        return (current_timestamp - block_timestamp).total_seconds() >= 8 * 60

    def create_new_wallet(self):
        # Generate mnemonic and account using CryptoUtils and AccountManager
        mnemonic = crypto_utils.generate_mnemonic()
        account = self.wallet.account_manager.generate_account_from_mnemonic(mnemonic)

        # Creating a wallet creation transaction
        wallet_creation_transaction = {
            'address': account['address'],
            'balance': 0.0,
            'withdrawals': 0,
            'type': 'c'
        }

        # Cleaning and preparing the transaction
        cleaned_transaction = {
            'address': wallet_creation_transaction['address'],
            'balance': wallet_creation_transaction['balance'],
            'pub_key': account['pub_key'],
            'sub_type': 'c',
            'type': wallet_creation_transaction['type'],
            'withdrawals': wallet_creation_transaction['withdrawals']
        }

        initial_balance = 0.0

        # Create the new account and record in wallet
        account_dict = {
            'address': wallet_creation_transaction['address'],
            'balance': initial_balance,
        }
        account_manager.accounts.append(account_dict)

        # Preparing sendable transaction data
        sendable_transaction = {
            'mnemonic': mnemonic,
            'private_key': base64.b64encode(account['private_key']).decode('utf-8'),
            'pub_key': account['pub_key'],
            'address': account['address'],
        }

        # Return the sendable transaction data
        return sendable_transaction

    def create_new_wallet_from_seed(self, seed):
        # Generate account using AccountManager
        account = self.wallet.account_manager.generate_account_from_mnemonic(seed)

        # Creating a wallet creation transaction
        wallet_creation_transaction = {
            'address': account['address'],
            'balance': 0.0,
            'withdrawals': 0,
            'type': 'c'
        }

        # Cleaning and preparing the transaction
        cleaned_transaction = {
            'address': wallet_creation_transaction['address'],
            'balance': wallet_creation_transaction['balance'],
            'pub_key': account['pub_key'],
            'type': wallet_creation_transaction['type'],
            'withdrawals': wallet_creation_transaction['withdrawals']
        }

        # Preparing sendable transaction data
        sendable_transaction = {
            'mnemonic': account['mnemonic'],
            'private_key': base64.b64encode(account['private_key']).decode('utf-8'),
            'pub_key': account['pub_key'],
            'address': account['address'],
        }

        private_key_bytes = base64.b64decode(sendable_transaction['private_key'])
        signature = crypto_utils.sign_transaction(private_key_bytes, wallet_creation_transaction)

        cleaned_transaction['signature'] = signature

        # Adding account transaction
        transactions.transactions.append(cleaned_transaction)
        self.update_accounts(wallet_creation_transaction['address'], wallet_creation_transaction['balance'])

        # Return the sendable transaction data
        return sendable_transaction

    def get_chain_length(self):
        return len(self.chain) if hasattr(self, "blockchain") else 0

    def check_chain_length_and_sync(self, services):
        # Generate the list of services
        service_prefix = "node"  # Adjust as necessary
        services = self.discover_services(service_prefix)

        # Synchronize with other nodes and determine the authoritative node
        authoritative_node_url, synchronized_chain = self.sync_with_other_nodes(services)

        # Sync account list, and treasury data from the authoritative node
        self.sync_account_list_data(authoritative_node_url, account_manager, coin, staked_coin)
        self.sync_treasury_data(authoritative_node_url)

        # Ping services after checking chain length and before returning
        self.ping_services(services, "check_nodes", self.node.url)

        if synchronized_chain is not None:
            return {
                "chain": synchronized_chain,
                "message": "Chain synchronized successfully"
            }
        else:
            return {
                "chain": self.chain,  # Return the current chain
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

                # Update OMC accounts
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

                # Update StakedOMC accounts
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

                # Update validators
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
                # Update local treasury data with the data from the authoritative node
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
        """
        Add or update a single account with new data, including updating the balance in OMC class.
        """
        address = account_data.get('address')
        balance_float = account_data.get('balance_float', 0)
        new_account = {}
        new_account['address'] = address
        new_account['balance'] = balance_float

        # Add new account
        # coin.accounts[address] = account_data
        account_manager.accounts.append(new_account)

        # Update the balance
        coin.balance[address] = balance_float

        logging.info(f"Added/Updated account: {address} with balance {balance_float}")

    def add_staking_account(self, data):
        # Add the new account to the wallet's accounts list
        account_manager.staking_accounts.append(data)
        staked_coin.accounts.append(data)
        staking_manager.staking_accounts.append(data)

    def get_init_date(self):
        """
        Get the initialization date of the blockchain.
        """
        return coin.init_date

    def validate_chain(self, chain):
        """
        Validate the integrity and validity of the given blockchain chain using proof of stake.
        """
        previous_block = chain[0]
        for block in chain[1:]:
            # Check if the previous block's hash matches the stored previous_hash
            if block['previous_hash'] != previous_block['hash']:
                return False

            # Recalculate the hash of the current block and compare with stored hash
            block_data = block.copy()
            block_data.pop('hash')  # Remove the stored hash for re-calculation
            calculated_hash = self.calculate_block_hash(block_data)

            if block['hash'] != calculated_hash:
                return False

            # Check if the proof of stake is valid
            if not self.validate_stake(block):
                return False

            previous_block = block

        return True

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

    def validate_foreign_tx(self, address, hash, pub_key, tx, signature):
        logging.debug(f"Validating tx from {address}")

        # Verify the transaction signature
        if not crypto_utils.verify_transaction(pub_key, tx, signature):
            logging.error(f"Invalid signature in foregin transaction with hash: {hash} from address: {address}")
            return None

        return True

    def vote_on_local_tx(self, address, hash, pub_key, tx, signature):
        valid_votes = []
        services = self.discover_services("node")

        # If there's only one service (the current node), bypass the voting process
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

    def vote_on_local_block(self, block):
        valid_votes = []
        services = self.discover_services("node")

        # If there's only one service (the current node), bypass the voting process
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

    def add_block(self, block):
        logging.info(f"Attempting to add block with index {block['index']}")
        if self.validate_received_block(block):
            with self.lock:
                if block['index'] == len(self.chain) + 1 and \
                   block['previous_hash'] == self.chain[-1]['hash']:
                    self.chain.append(block)
                    self.block_hashes.add(block['hash'])
                    logging.info(f"Block with index {block['index']} successfully added to the chain.")
                    # Broadcast the block to the network
                    self.broadcast_block(block)
                    return True
                else:
                    logging.warning(f"Block with index {block['index']} failed to match chain continuity.")
        else:
            logging.warning(f"Block with index {block['index']} failed validation.")
        return False

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

        # Initial check for the presence of all required fields
        missing_fields = [field for field in required_fields if field not in block]
        if missing_fields:
            logging.error(f"Block missing required fields: {missing_fields}")
            return False

        # Detailed type check for each field
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

    def validate_block(self, block):
        logging.debug(f"Validating block with index {block['index']}")
        # Check if validator is valid
        if block['validator'] not in self.validators:
            logging.error("Block validator is not recognized.")
            return False

        # Check stake
        stake = self.proof_of_stake(block)
        # if stake < block['stake_threshold']:
        #     logging.error(f"Block with index {block['index']} did not meet the stake threshold.")
        #     return False

        # Check for double spending
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

        # Validate block hash
        block_string = str(block['index']) + str(block['timestamp']) + str(block['previous_hash']) + str(
            block['transactions']) + str(block['fee']) + str(block['validator']) + str(block['validator_share'])

        # Generate block hash
        generated_hash = hashlib.sha256(block_string.encode()).hexdigest()
        if block['hash'] != generated_hash:
            logging.error("Block hash does not match the generated hash.")
            return False

        # Additional checks like consensus can be added here
        if not self.reach_consensus(block):  # Implement this method based on your consensus algorithm
            logging.error("Failed to reach consensus.")
            return False

        logging.info(f"Block with index {block['index']} passed all validations.")
        return True

    def validate_foreign_block(self, block):
        logging.debug(f"Validating block with index {block['index']}")
        # Check if validator is valid
        if block['validator'] not in self.validators:
            logging.error("Block validator is not recognized.")
            return False

        # Check stake
        stake = self.proof_of_stake(block)
        if stake < block['stake_threshold']:
            logging.error(f"Block with index {block['index']} did not meet the stake threshold.")
            return False

        # Check for double spending
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

        # Validate block hash
        block_string = str(block['index']) + str(block['timestamp']) + str(block['previous_hash']) + str(
            block['transactions']) + str(block['fee']) + str(block['validator']) + str(block['validator_share'])

        # Generate block hash
        generated_hash = hashlib.sha256(block_string.encode()).hexdigest()
        if block['hash'] != generated_hash:
            logging.error("Block hash does not match the generated hash.")
            return False

        return True

    def generate_block_hash(self, block):
        # Serialize transactions to a JSON string
        transactions_string = json.dumps(block['transactions'], sort_keys=True)

        # Concatenate the block contents
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

        # Compute the SHA-256 hash of the concatenated block contents
        block_hash = hashlib.sha256(block_contents.encode()).hexdigest()
        return block_hash

    def reach_tx_consensus(self, address, hash, pub_key, tx, signature):
        # Automatically approve if there's only one validator, potentially the node itself
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

    def reach_consensus(self, proposed_block):
        # Automatically approve if there's only one validator, potentially the node itself
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

    def receive_tx(self, address, hash, pub_key, tx, signature):
        try:
            # Verify the transaction using a hypothetical crypto_utils module
            if not self.validate_foreign_tx(address, hash, pub_key, tx, signature):
                logging.error(f"Received transaction, with hash {hash} from wallet {address}, did not pass verification")
                return False

            return True
        except Exception as e:
            logging.error(f"Error processing received transaction: {str(e)}")
            return False

    def receive_block(self, block):
        try:
            # Determine the authoritative node by syncing with other nodes
            services = self.discover_services("node")  # Discover the services/nodes in the network
            authoritative_node_url, _ = self.sync_with_other_nodes(services)

            # Synchronize data with the authoritative node
            if authoritative_node_url:
                self.sync_account_list_data(authoritative_node_url, account_manager, coin, staked_coin)
                self.sync_treasury_data(authoritative_node_url)

            # Assuming block processing is successful if the above operations are successful
            return True
        except Exception as e:
            logging.error(f"Error processing received block: {str(e)}")
            return False

    def select_miner(self) -> dict:
        accounts = staking_manager.staking_agreements

        # Calculate the number of withdrawals for each account
        account_withdrawals = {}
        for block in self.chain:
            for transaction in block['transactions']:
                address = transaction.get('address')
                if address:
                    account_withdrawals[address] = account_withdrawals.get(address, 0) + 1

        # Update accounts with the number of withdrawals
        for account in accounts:
            account['withdrawals'] = account_withdrawals.get(account['address'], 0)

        # Select the miner using weighted selection
        miner = self.weighted_selection(accounts)
        return miner
    
    def weighted_selection(self, accounts: List[dict]) -> dict:
        # Calculate weights based on the balance and the number of withdrawals
        total_weight = sum(acc['balance'] / (acc['withdrawals'] + 1) for acc in accounts)
        normalized_weights = [(acc['balance'] / (acc['withdrawals'] + 1)) / total_weight for acc in accounts]

        # Select an account using the normalized weights
        chosen_account = random.choices(accounts, weights=normalized_weights, k=1)[0]
        return chosen_account

    def proof_of_stake(self, block):
        logging.info("Starting proof of stake validation.")

        total_stake_weight = sum(node['stake_weight'] if isinstance(node, dict) else node.stake_weight for node in self.nodes)
        random_number = random.uniform(0, total_stake_weight)
        cumulative_stake_weight = 0

        logging.info(f"Total stake weight: {total_stake_weight}, Random number for validator selection: {random_number}")

        for current_node in self.nodes:
            node_stake_weight = current_node['stake_weight'] if isinstance(current_node, dict) else current_node.stake_weight
            cumulative_stake_weight += node_stake_weight

            if cumulative_stake_weight > random_number:
                selected_validator_address = current_node['address'] if isinstance(current_node, dict) else current_node.address
                logging.info(f"Selected validator address: {selected_validator_address}, Stake weight: {node_stake_weight}")

                # Check if the selected validator is the same as the block's validator
                if selected_validator_address == block['validator']:
                    logging.info(f"Validator {selected_validator_address} matches the block's validator.")
                    if node_stake_weight >= block['stake_threshold']:
                        logging.info(f"Validator {selected_validator_address} meets the stake threshold.")
                        return node_stake_weight
                    else:
                        logging.error(f"Validator {selected_validator_address} does not meet the stake threshold.")
                        return 0  # Exit here if the matching validator does not meet the threshold

        logging.error("No suitable validator found or the selected validator does not meet the stake threshold.")
        return 0

    def broadcast_tx(self, address, hash, pub_key, new_tx, signature):
        data = {
            'address': address,
            'hash': hash,
            'pub_key': pub_key,
            'new_tx': new_tx,
            'signature': signature
        }

        # Fetch service list
        service_prefix = "node"
        services = self.discover_services(service_prefix)

        # Use post_data_to_services method to broadcast new block's data
        self.post_data_to_services(services, "transaction/receive_tx", data)

        return True

    def broadcast_block(self, new_block):
        block_data = json.dumps(new_block)

        # Fetch service list
        service_prefix = "node"
        services = self.discover_services(service_prefix)

        # Use post_data_to_services method to broadcast new block's data
        self.post_data_to_services(services, "blocks/receive_block", block_data)

    def consume_blocks(self):
        for message in self.consumer:
            block_data = message.value.decode('utf-8')
            block = json.loads(block_data)
            self.receive_block(block)

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

    def calculate_current_year(self):
        # Get the current UTC time
        current_time = datetime.now(timezone.utc)

        # Calculate the time elapsed since blockchain initialization
        time_elapsed = current_time - self.init_date

        # Calculate the current year (assuming 365 days per year)
        current_year = time_elapsed.days / 365

        return current_year

    def calculate_average_transaction_size(self):
        if not self.transactions:
            return 0  # Avoid division by zero
        total_size = sum(tx.size for tx in self.transactions)  # Assuming each tx has a 'size' attribute
        return total_size / len(self.transactions)

    def is_network_congested(self):
        max_pending_transactions = 1000
        max_block_generation_rate = 2
        max_block_size = 2000

        num_pending_transactions = len(self.transactions)

        average_transaction_size = self.calculate_average_transaction_size()  # Call the method to get average size
        time_to_mine_block = 60 / max_block_generation_rate

        if average_transaction_size == 0:
            max_transaction_capacity = float('inf')  # Handle case where no transactions are present
        else:
            max_transaction_capacity = max_block_size / average_transaction_size

        if num_pending_transactions > max_pending_transactions or num_pending_transactions > max_transaction_capacity:
            return True
        return False

    def create_new_block(self, transactions):
        latest_block = self.chain[-1]
        block_index = latest_block['index'] + 1
        timestamp = int(datetime.now(timezone.utc).timestamp())  # Convert to an integer timestamp
        previous_hash = latest_block['hash']
        stake_threshold = node.stake_weight

        # Handle transactions and calculate fees using specialized classes
        processed_transactions = self.process_transactions(transactions)

        # Calculate the total transaction fee and mint block fee
        total_fee = sum(tx['fee'] for tx in transactions)
        block_fee = coin.mint_for_block_fee(165.925925926, total_fee)

        # Distribute the block fee
        fee_distribution = self.calculate_fee_distribution(block_fee)

        # Select a random wallet account as the miner
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

        # Select a random validator
        validator_node = self.select_validator(block)

        if not validator_node:
            logging.warning("No validator selected, assigning default validator.")
            validator_address = node.address  # Fallback to a default address
        else:
            # Check if validator_node is a Node object or a dictionary and access the address accordingly
            validator_address = validator_node.address if isinstance(validator_node, Node) else validator_node['address']

        # Create merkle root for present transactions
        for transaction in transactions:
            merkle_tree.add_transaction(str(transaction))  # Assuming transaction is a dict and needs to be stringified

        merkle_tree.create_tree()
        merkle_root = merkle_tree.get_merkle_root()

        # Continue constructing the new block with validator_address
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

            # The dynamic fee calculation is done within each handling method
            # Hence, we do not calculate the total fee here

            # Handle different transaction types
            if transaction_type == 'r':
                # Staking transaction
                processed_transaction = self.handle_staking_transaction(transaction)
            elif transaction_type == 'c':
                # Unstaking transaction
                processed_transaction = self.handle_patient_account_creation_transaction(transaction)
            elif transaction_type == 'd':
                # Unstaking transaction
                processed_transaction = self.handle_physician_account_creation_transaction(transaction)
            elif transaction_type == 'o':
                # Unstaking transaction
                processed_transaction = self.handle_unstaking_transaction(transaction)
            elif transaction_type == 'k':
                # Transfer transaction
                processed_transaction = self.handle_transfer_transaction(transaction)
            elif transaction_type == 'l':
                # Whitelist transaction
                processed_transaction = self.handle_join_whitelist_transaction(transaction)
            elif transaction_type == 'j':
                # Transfer transaction
                processed_transaction = self.handle_add_profile_transaction(transaction)
            elif transaction_type == 'u':
                # Transfer transaction
                processed_transaction = self.handle_add_user_created_community(transaction)
            elif transaction_type in ['h', 'x', 'm', 'pr']:
                # Fee payment transaction
                processed_transaction = self.handle_fee_payment_transaction(transaction)
            else:
                # Other types or default handling
                processed_transaction = self.handle_default_transaction(transaction)

            # Append the processed transaction to the list
            if processed_transaction:
                processed_transactions.append(processed_transaction)
                # Update total fee from the processed transaction
                total_fee += processed_transaction.get('fee', 0.0)

        return processed_transactions, total_fee

    def handle_patient_account_creation_transaction(self, transaction):
        try:
            fee_calculator = DynamicFeeCalculator()
            new_account_address = transaction['address']
            initial_balance = 0.0
            public_key = transaction['pub_key']
            signature = transaction['signature']

            # Prepare the data for fee calculation
            transaction_data = {
                'address': new_account_address,
                'balance': initial_balance,
                'sub_type': transaction['sub_type']
            }

            # Calculate the fee dynamically
            transaction_fee, transaction_hash = dynamic_fee_calculator.get_base_dynamic_fee(transaction_data, transaction['sub_type'])

            # Create a cleaned transaction for recording in the blockchain
            cleaned_transaction = {
                'address': new_account_address,
                'hash': transaction_hash,
                'r': transaction['r'],
                'sub_type': 'c',
                'type': transaction['type'],
                'when': str(datetime.now(timezone.utc))
            }

            logging.info(f"Processed account creation transaction for {new_account_address}")
            return cleaned_transaction

        except Exception as e:
            logging.error(f"Error processing account creation transaction A1: {e}")
            return None

    def handle_physician_account_creation_transaction(self, transaction):
        try:
            fee_calculator = DynamicFeeCalculator()
            new_account_address = transaction['address']
            initial_balance = 0.0
            public_key = transaction['pub_key']
            signature = transaction['signature']

            # Prepare the data for fee calculation
            transaction_data = {
                'address': new_account_address,
                'balance': initial_balance,
                'sub_type': transaction['sub_type']
            }

            # Calculate the fee dynamically
            transaction_fee, transaction_hash = dynamic_fee_calculator.get_base_dynamic_fee(transaction_data, transaction['sub_type'])

            # Create a cleaned transaction for recording in the blockchain
            cleaned_transaction = {
                'address': new_account_address,
                'hash': transaction_hash,
                'r': transaction['r'],
                'sub_type': 'd',
                'type': transaction['type'],
                'when': str(datetime.now(timezone.utc))
            }

            logging.info(f"Processed account creation transaction for {new_account_address}")
            return cleaned_transaction

        except Exception as e:
            logging.error(f"Error processing account creation transaction A1: {e}")
            return None

    def handle_staking_transaction(self, transaction):
        try:
            fee_calculator = DynamicFeeCalculator()
            sender_address = transaction['address']
            staking_amount = transaction['amount']
            min_term = transaction['min_term']
            pub_key = transaction['pub_key']
            signature = transaction.get('signature')

            # Prepare the data for fee calculation
            transaction_data = {
                'address': sender_address,
                'amount': staking_amount,
                'min_term': min_term,
                'pub_key': pub_key,
                'type': transaction['type']
            }

            # Calculate the fee dynamically
            transaction_fee, transaction_hash = dynamic_fee_calculator.get_base_dynamic_fee(transaction_data, transaction['type'])

            # Ensure necessary fields are present
            if not all([sender_address, staking_amount, min_term, pub_key, signature]):
                logging.error("Missing fields in staking transaction")
                return None

            # Verify the sender's balance
            sender_balance_info = self.wallet.get_account_balance(sender_address)
            if not sender_balance_info or sender_balance_info['balance_float'] < staking_amount + transaction_fee:
                logging.error("Insufficient balance for staking")
                return None

            # Prepare the transaction for signature verification
            transaction_for_verification = {
                'address': sender_address,
                'amount': staking_amount,
                'fee': transaction_fee,
                'hash': transaction_hash,
                'min_term': min_term,
                'pub_key': pub_key,
                'type': transaction['type']
            }

            # Verify the transaction signature
            if not crypto_utils.verify_transaction(transaction['pub_key'], transaction_for_verification, transaction['signature']):
                logging.error("Invalid signature in staking transaction")
                return None

            # Process the staking
            self.wallet.stake_coins(sender_address, staking_amount, min_term)

            # Create a cleaned transaction for recording in the blockchain
            processed_transaction = {
                'address': sender_address,
                'amount': staking_amount,
                'fee': transaction_fee,
                'hash': transaction_hash,
                'min_term': min_term,
                'stake_threshold': 3,  # Adjust as necessary
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

            # Prepare the data for fee calculation
            transaction_data = {
                'address': sender_address,
                'contract_id': contract_id,
                'pub_key': pub_key,
                'type': transaction['type']
            }

            # Calculate the fee dynamically
            transaction_fee, transaction_hash = dynamic_fee_calculator.get_base_dynamic_fee(transaction_data, transaction['type'])

            # Ensure necessary fields are present
            if not all([sender_address, contract_id, pub_key, signature]):
                logging.error("Missing fields in unstaking transaction")
                return None

            # Verify the sender's balance
            sender_balance_info = self.wallet.get_account_balance(sender_address)
            if not sender_balance_info or sender_balance_info['balance_float'] < transaction_fee:
                logging.error("Insufficient balance for unstaking")
                return None

            # Prepare the transaction for signature verification
            transaction_for_verification = {
                'address': sender_address,
                'contract_id': contract_id,
                'fee': transaction_fee,
                'hash': transaction_hash,
                'pub_key': pub_key,
                'type': transaction['type']
            }

            # Verify the transaction signature
            if not crypto_utils.verify_transaction(transaction['pub_key'], transaction_for_verification, transaction['signature']):
                logging.error("Invalid signature in unstaking transaction")
                return None

            # Process the unstaking
            self.wallet.unstake_coins(sender_address, contract_id)

            # Create a cleaned transaction for recording in the blockchain
            processed_transaction = {
                'address': sender_address,
                'contract_id': contract_id,
                'fee': transaction_fee,
                'hash': transaction_hash,
                'stake_threshold': 2,  # Adjust as necessary
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

            # Prepare the data for fee calculation
            transaction_data = {
                'sender': sender_address,
                'recipient': recipient_address,
                'amount': transfer_amount,
                'pub_key': pub_key,
                'type': transaction['type']
            }

            # Calculate the fee dynamically
            transaction_fee, transaction_hash = dynamic_fee_calculator.get_base_dynamic_fee(transaction_data, transaction['type'])

            # Ensure necessary fields are present
            if not all([sender_address, recipient_address, transfer_amount, pub_key, signature]):
                logging.error("Missing fields in transfer transaction")
                return None

            # Verify the sender's balance
            sender_balance_info = self.wallet.get_account_balance(sender_address)
            if not sender_balance_info or sender_balance_info['balance_float'] < transfer_amount + transaction_fee:
                logging.error("Insufficient balance for transfer")
                return None

            # Prepare the transaction for signature verification
            transaction_for_verification = {
                'sender': sender_address,
                'recipient': recipient_address,
                'amount': transfer_amount,
                'fee': transaction_fee,
                'hash': transaction_hash,
                'pub_key': pub_key,
                'type': transaction['type']
            }

            # Verify the transaction signature
            if not crypto_utils.verify_transaction(transaction['pub_key'], transaction_for_verification, transaction['signature']):
                logging.error("Invalid signature in transfer transaction")
                return None

            # Process the transfer
            self.wallet.transfer(sender_address, recipient_address, transfer_amount)

            # Create a cleaned transaction for recording in the blockchain
            processed_transaction = {
                'sender': sender_address,
                'recipient': recipient_address,
                'amount': transfer_amount,
                'fee': transaction_fee,
                'hash': transaction_hash,
                'stake_threshold': 2,  # Adjust as necessary
                'type': transaction['type'],
                'when': str(datetime.now(timezone.utc))
            }

            logging.info(f"Processed transfer transaction from {sender_address} to {recipient_address}")
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

            # Prepare the data for fee calculation
            transaction_data = {
                'from': payer_address,
                'fee': fee_amount,
                'pub_key': pub_key,
                'type': transaction['type']
            }

            # Calculate the fee dynamically
            calculated_fee, transaction_hash = dynamic_fee_calculator.get_base_dynamic_fee(transaction_data, transaction['type'])

            # Ensure necessary fields are present
            if not all([payer_address, fee_amount, pub_key, signature]):
                logging.error("Missing fields in fee payment transaction")
                return None

            # Verify the payer's balance
            payer_balance_info = self.wallet.get_account_balance(payer_address)
            if not payer_balance_info or payer_balance_info['balance_float'] < fee_amount + calculated_fee:
                logging.error("Insufficient balance for fee payment")
                return None

            # Prepare the transaction for signature verification
            transaction_for_verification = {
                'from': payer_address,
                'fee': calculated_fee,
                'hash': transaction_hash,
                'pub_key': pub_key,
                'type': transaction['type']
            }

            # Verify the transaction signature
            if not crypto_utils.verify_transaction(transaction['pub_key'], transaction_for_verification, transaction['signature']):
                logging.error("Invalid signature in fee payment transaction")
                return None

            # Process the fee payment
            self.wallet.pay_fee(payer_address, fee_amount)

            # Create a cleaned transaction for recording in the blockchain
            processed_transaction = {
                'from': payer_address,
                'fee': calculated_fee,
                'hash': transaction_hash,
                'stake_threshold': 2,  # Adjust as necessary
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

            # Prepare the data for fee calculation
            transaction_data = {
                'from': payer_address,
                'type': 'e'
            }

            # Calculate the fee dynamically
            calculated_fee, transaction_hash = dynamic_fee_calculator.get_base_dynamic_fee(transaction_data, transaction['type'])

            # Create a cleaned transaction for recording in the blockchain
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

    def handle_add_profile_transaction(self, transaction):
        try:
            sender_address = transaction['address']
            account_balance = coin.get_balance(sender_address)
            transaction_fee = transaction['fee']

            if transaction['signature'] and account_balance >= transaction['fee']:
                # Prepare the transaction for signature verification
                transaction_for_verification = {
                    'address': transaction['address'],
                    'avi': transaction['avi'],
                    'handle': transaction['handle'],
                    'joined': transaction['joined'],
                    'name': transaction['name'],
                    'sub_type': transaction['sub_type'],
                    'type': transaction['type']
                }

                verification_result = crypto_utils.verify_transaction(transaction['pub_key'], transaction_for_verification, transaction['signature'])

                if verification_result:

                    # Process the transaction
                    self.wallet.pay_fee(sender_address, transaction_fee)

                    # Create a cleaned transaction for recording in the blockchain
                    refined_transaction = {
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
                        'signature': transaction['signature'],
                        'sub_type': transaction['sub_type'],
                        'tags': transaction['tags'],
                        'type': transaction['type'],
                        'version': transaction['version']
                    }

                    logging.info(f"Processed handle_add_profile_transaction transaction for {sender_address}")
                    return refined_transaction
                else:
                    logging.error("Invalid signature in handle_add_profile_transaction transaction")
                    return None

            else:
                logging.error("Insufficient balance for transaction")
                return None

        except Exception as e:
            logging.error(f"Error processing handle_add_profile_transaction transaction: {e}")
            return None

    def calculate_fee_distribution(self, total_fee):
        fee_distribution = {}

        # Define fee percentages
        miner_percentage = 0.30  # 30% to the miner
        validator_percentage = 0.45  # 45% to the validator
        treasury_percentage = 0.25  # 25% to the treasury

        # Calculate fee shares
        fee_distribution['miner_share'] = total_fee * miner_percentage
        fee_distribution['validator_share'] = total_fee * validator_percentage
        fee_distribution['treasury_share'] = total_fee * treasury_percentage

        return fee_distribution

    def check_pending_transactions(self):
        cleaned_transactions = self.clean_and_verify_transactions()
        self.start_mining()

    def start_mining(self):
        self.create_new_block(self.transactions.cleaned_transactions)

    def clean_and_verify_transactions(self):
        new_transactions = transactions.batch_pending_transactions()
        cleaned_transactions = []

        for transaction in new_transactions:
            try:
                if transaction['sub_type'] == 'c':
                    # Processing patient account creation transactions
                    self.process_patient_account_creation_transaction(transaction)

                elif transaction['sub_type'] == 'd':
                    # Processing physician account creation transactions
                    self.process_physician_account_creation_transaction(transaction)

                elif transaction['type'] == 'o':
                    # Process other types of transactions
                    self.process_non_f_transaction(transaction)

                elif transaction['type'] == 'e':
                    # Process other types of transactions
                    self.process_f_transaction(transaction)
            except Exception as e:
                logging.error(f"Error processing transaction {transaction['type']}: {e}")

        return cleaned_transactions

    def process_patient_account_creation_transaction(self, transaction):
        # Verify that the transaction is of the correct type
        if transaction['type'] != 'c':
            logging.error(f"Invalid transaction type for account creation: {transaction['type']}")
            return

        try:
            # Extract necessary fields from the transaction
            address = transaction['address']
            type = transaction['type']
            timestamp = transaction['timestamp']
            role = transaction['r']

            # Validate the transaction data
            if not all([address, type]):
                logging.error("Incomplete account creation transaction data")
                return

            # Create a cleaned version of the transaction for the blockchain
            cleaned_transaction = {
                'address': address,
                'hash': transaction.get('hash'),
                'pub_key': transaction['pub_key'],
                'r': role,
                'signature': transaction['signature'],
                'sub_type': 'c',
                'type': transaction['type'],
                'role': transaction['r']
            }

            # Append the cleaned transaction to the list of processed transactions
            self.transactions.cleaned_transactions.append(cleaned_transaction)
            logging.info(f"Processed account creation transaction for {address}")

        except Exception as e:
            logging.error(f"Error processing account creation transaction A2: {e}")

    def process_physician_account_creation_transaction(self, transaction):
        # Verify that the transaction is of the correct type and intended for physicians
        if transaction['type'] != 'c' or transaction.get('r') != 'physician':
            logging.error(f"Invalid transaction type or role for account creation: {transaction['type']}, role: {transaction.get('r')}")
            return

        try:
            # Extract necessary fields from the transaction
            address = transaction['address']
            pub_key = transaction['pub_key']
            signature = transaction['signature']
            hash_value = transaction.get('hash')
            role = transaction['r']
            timestamp = str(datetime.now(timezone.utc))

            # Validate the transaction data
            if not all([address, pub_key, signature, role]):
                logging.error("Incomplete account creation transaction data for physician")
                return

            # Create a cleaned version of the transaction for the blockchain
            cleaned_transaction = {
                'address': address,
                'hash': hash_value,
                'pub_key': pub_key,
                'signature': signature,
                'sub_type': 'd',
                'type': 'c',
                'r': role,
                'timestamp': timestamp
            }

            # Append the cleaned transaction to the list of processed transactions
            self.transactions.cleaned_transactions.append(cleaned_transaction)
            logging.info(f"Processed account creation transaction for physician {address}")

        except Exception as e:
            logging.error(f"Error processing physician account creation transaction: {e}")

    def process_f_transaction(self, transaction):
        try:
            # Common fields for all transactions
            transaction_type = transaction.get('type')
            sender_address = transaction.get('address')
            transaction_fee = transaction.get('fee', 0.0)

            if not sender_address or transaction_fee is None:
                logging.error("Invalid transaction format.")
                return None

            cleaned_transaction = None  # Initialize to None

            # Process based on transaction type
            if transaction_type == 'e':
                sub_tx_type = transaction.get('sub_type')

                if sub_tx_type == 'p':
                    # Payment Transaction
                    amount = transaction.get('amount')
                    recipient_address = transaction.get('recipient')

                    # Verify and process the payment
                    if crypto_utils.verify_transaction(sender_address, recipient_address, amount):
                        self.wallet.transfer(sender_address, recipient_address, amount)
                        # Fee processing can be added here

                elif sub_tx_type == 'r':
                    # Staking Transaction
                    amount = transaction.get('amount')
                    min_term = transaction.get('min_term')

                    # Process staking
                    self.wallet.stake_coins(sender_address, amount, min_term)

                elif sub_tx_type == 'z':
                    # Unstaking Transaction
                    contract_id = transaction.get('contract_id')

                    # Process unstaking
                    self.wallet.unstake_coins(sender_address, contract_id)

            if cleaned_transaction:
                # Append only if cleaned_transaction is valid
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
            # Common fields for all transactions
            transaction_type = transaction.get('type')
            sender_address = transaction.get('address')
            transaction_fee = transaction.get('fee', 0.0)

            if not sender_address or transaction_fee is None:
                logging.error("Invalid transaction format.")
                return None

            cleaned_transaction = None  # Initialize to None

            # Process based on transaction type
            if transaction_type == 'o':
                sub_tx_type = transaction.get('sub_type')

                if sub_tx_type == 's':
                    # Post transaction
                    self.handle_post_transaction(transaction)

                elif sub_tx_type == 'j':
                    # Profile transaction
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
                # Append only if cleaned_transaction is valid
                transactions.cleaned_transactions.append(cleaned_transaction)
                logging.info(f"Processed transaction of type {transaction_type} for {sender_address}")
                return cleaned_transaction
            else:
                logging.warning(f"Unhandled or failed transaction type/subtype: {transaction_type}/{sub_tx_type}")
                return None

        except Exception as e:
            logging.error(f"Error processing transaction: {e}")
            return None

    def main_loop(self):
        while True:
            self.start_mining()
            self.consume_blocks()

    def get_latest_block(self) -> Block:
        return self.chain[-1]

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

    def add_transfer_transaction(self, address: str, amount: int, fee: Union[int, float], hash: str, pub_key: str, recipient: str, sender: str, signature: str, sub_type: str, type: str) -> Union[bool, str]:

        account_balance = coin.get_balance(address)

        cleaned_transaction = {
            'amount': amount,
            'fee': fee,
            'hash': hash,
            'pub_key': pub_key,
            'recipient': recipient,
            'sender': sender,
            'signature': signature,
            'sub_type': sub_type,
            'type': type
        }

        if cleaned_transaction['signature'] and account_balance >= fee:
            return cleaned_transaction

    def add_staking_transaction(self, address: str, amount: int, fee: Union[int, float], hash: str, min_term: Union[str, int], pub_key: str, signature: str, sub_type: str, type: str) -> Union[bool, str]:

        account_balance = coin.get_balance(address)

        cleaned_transaction = {
            'address': address,
            'amount': amount,
            'fee': fee,
            'hash': hash,
            'min_term': min_term,
            'pub_key': pub_key,
            'signature': signature,
            'sub_type': sub_type,
            'type': type,
        }

        if cleaned_transaction['signature'] and account_balance >= fee:
            return cleaned_transaction

    def add_unstaking_transaction(self, address: str, contract_id: str, fee: Union[int, float], hash: str, pub_key: str, signature: str, sub_type: str, type: str) -> Union[bool, str]:

        account_balance = coin.get_balance(address)

        cleaned_transaction = {
            'address': address,
            'contract_id': contract_id,
            'fee': fee,
            'hash': hash,
            'pub_key': pub_key,
            'signature': signature,
            'sub_type': sub_type,
            'type': type,
        }

        if cleaned_transaction['signature'] and account_balance >= fee:
            return cleaned_transaction

    def add_profile_transaction(self, address: str, avi: str, clubs: list, fee: Union[int, float], handle: str, hash: str, intro: str, joined: str, name: str, profile_type: str, pt: bool, pub_key: str, signature: str, sub_type: str, tags: list, version: int) -> Union[bool, str]:

        account_balance = coin.get_balance(address)

        cleaned_transaction = {
            'address': address,
            'avi': avi,
            'clubs': clubs,
            'fee': fee,
            'handle': handle,
            'hash': hash,
            'intro': intro,
            'joined': joined,
            'name': name,
            'profile_id': '0p' + str(secrets.token_hex(20)),
            'profile_type': profile_type,
            'pt': pt,
            'pt_id': '0pt' + str(secrets.token_hex(23)),
            'pub_key': pub_key,
            'signature': signature,
            'sub_type': sub_type,
            'tags': tags,
            'type': 'o',
            'version': version
        }

        if cleaned_transaction['signature'] and account_balance >= fee:
            return cleaned_transaction
        else:
            return "Error processing transaction, double check that you have enough OMC to process the transaction"

    def add_vendor_profile_transaction(self, address: str, avi: str, bio: str, business_address: str, business_name: str, cover: str, coords: dict, facilities: dict, fee: Union[int, float], gallery: list, handle: str, hash: str, hours: dict, name: str, profession: str, private_key: bytes, pt: bool, pub_key: str, qc: str, ratings: dict, services: list, schedule: list, signature: str, sub_type: str, tags: dict, vendor: bool, vendor_category: str, version: int) -> Union[bool, str]:

        account_balance = coin.get_balance(address)

        cleaned_transaction = {
            'address': address,
            'avi': avi,
            'bio': bio,
            'business_address': business_address,
            'business_name': business_name,
            'cover': cover,
            'coords': coords,
            'facilities': facilities,
            'fee': fee,
            'handle': handle,
            'hash': hash,
            'hours': hours,
            'name': name,
            'profession': profession,
            'pt': pt,
            'pt_id': '0pt' + str(secrets.token_hex(23)),
            'pub_key': pub_key,
            'qc': qc,
            'services': services,
            'signature': signature,
            'sub_type': sub_type,
            'type': 'h',
            'vendor': True,
            'vendor_category': vendor_category,
            'version': version
        }

        if cleaned_transaction['signature'] and account_balance >= fee:
            return cleaned_transaction
        else:
            return "Error processing transaction, double check that you have enough OMC to process the transaction"

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

# Create coin
coin = OMC()

account_manager = AccMngr()

# Staked coin
staked_coin = StakedOMC()

staking_manager = StakingMngr()

# Creating a Wallet
wallet = Wallet()

node = Node()

treasury = OMCTreasury()

staked_coin.treasury_account = treasury.treasury_account
coin.treasury_account = treasury.treasury_account

# Creating a Blockchain
blockchain = Blockchain(node, wallet, transactions, treasury, verifier)

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

@app.route('/trigger_sync', methods=['POST'])
@require_authentication
def trigger_sync():
    try:
        services = blockchain.discover_services("node")
        result = blockchain.check_chain_length_and_sync(services)
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

#Create new wallet from owned seed phrase
@app.route('/create_another_account', methods=['POST'])
@require_authentication
def generate_another_account_from_seed():

    data = request.get_json()
    m = data.get('i')
    logging.info(f"m is: {m}")
    o = blockchain.create_new_wallet_from_seed(m)

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

# Check website's permissions
@app.route('/check_permission', methods=['GET'])
def check_permission():
    """
    Flask endpoint to check permission for a given address and URL.

    Expected URL parameters:
    - address: The address to check.
    - url: The URL to check for permission.

    Returns:
    {
        "permission": true
    }
    """
    try:
        address = request.args.get('address')
        url = request.args.get('url')

        permission = wallet.check_permission_for_url(address, url)

        response = {
            "permission": permission
        }
    except Exception as e:
        response = {
            "error": str(e)
        }

    return jsonify(response)

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

#==== CHAIN MAINTENANCE ====#

# Getting the full Blockchain
@app.route('/get_chain', methods=['GET'])
def get_chain():
    response = {
        'chain': blockchain.chain,
        'length': len(blockchain.chain)
    }
    return jsonify(response), 200

# Check validators
@app.route('/check_validators', methods=['GET'])
@require_authentication
def check_validators():
    # Extracting the address attribute from each node
    node_addresses = [node.address for node in blockchain.nodes]

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
    for node in blockchain.nodes:
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
    if any((node.address if isinstance(node, Node) else node['address']) == json_['address'] for node in blockchain.nodes):
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
    blockchain.nodes.append(new_node)  # Only add if not already present
    blockchain.validators.append(new_node['address'])  # Manage this list separately if needed
    logging.info(f"Node {json_['address']} successfully added to the roster of nodes.")
    return jsonify({'message': f'Node {json_["address"]} added to roster of nodes'}), 201

# Return new block
@app.route('/check_new_block', methods=['GET'])
def check_new_block():
    nb = blockchain.create_new_block()
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

    # Check in blockchain.chain
    for block in blockchain.chain:
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
        if blockchain.validate_foreign_tx(address, hash, pub_key, tx, signature):
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
        if blockchain.validate_foreign_block(block):
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
    existing_node = next((node for node in blockchain.nodes if node.address == received_node_info['address']), None)

    if existing_node is None:
        # If the node does not exist, create a new Node instance and add it to the list
        new_node = received_node_info
        blockchain.nodes.append(new_node)
        blockchain.validators.append(new_node.address)
        logging.info(f"Added new node with address: {received_node_info['address']}")
    else:
        # If the node already exists, log that information
        logging.info(f"Node with address {existing_node.address} already exists and was not added again.")

    return jsonify({"status": "success"}), 200

# Route to get the chain length
@app.route('/get_chain_length', methods=['GET'])
def get_chain_length():
    chain_length = len(blockchain.chain)
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

    for block in blockchain.chain:
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
    init_date = blockchain.get_init_date()  # Call a method to retrieve the init_date
    return jsonify({"init_date": str(init_date)})

# Calculate tx hash
@app.route('/calculate_hash', methods=['POST'])
def hash_transaction():
    data = request.get_json()
    if not data:
        return jsonify({'error': 'No data provided'}), 400

    try:
        hash_result = crypto_utils.calculate_sha256_hash(data['tx'])
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

# Endpoint for receiving price data from the price feed
@app.route('/receive_price_data', methods=['POST'])
@require_authentication
def receive_price_data():
    received_price_data = request.json
    logging.info(f"Received price data for processing: {received_price_data}")

    try:
        price = received_price_data['price']
        coin.set_price(price)
        logging.info(f"Set new price: {price}")
    except KeyError:
        logging.error("Invalid data received. 'price' key is missing.")
        return jsonify({"status": "error", "message": "Invalid data format"}), 400

    return jsonify({"status": "success"}), 200

# Get OMC price
@app.route('/get_omc_price', methods=['POST'])
def get_omc_price():
    data = request.json
    if 'omc_amount' not in data:
        return jsonify({'error': 'Missing omc_amount in request'}), 400

    try:
        omc_amount = float(data['omc_amount'])
    except ValueError:
        return jsonify({'error': 'Invalid omc_amount value'}), 400

    # Let's assume you have a method in OMC class to get the current OMC to USD rate
    current_rate = coin.fetch_current_exchange_rate()  # This should return the current rate of OMC in USD

    usd_amount = omc_amount * current_rate
    return jsonify({'omc_amount': omc_amount, 'usd_amount': usd_amount})

# Transfer coins
@app.route('/transfer_coins', methods=['POST'])
@require_authentication
def transfer_coins():
    try:
        data = request.get_json()

        sender = data.get('from_address')
        recipient = data.get('to_address')

        amount = data.get('amount')
        fee = data.get('fee')
        hash = data.get('hash')
        pub_key = data.get('pub_key')
        signature = data.get('signature')
        sub_type = data.get('sub_type')
        type = data.get('type')

        if sender is None or recipient is None or amount is None:
            return jsonify({"error": "Invalid request data"}), 400

        if blockchain.add_transfer_transaction(amount, fee, hash, pub_key, recipient, sender, signature, sub_type, type):
            response = {
                'message': 'Transfer tx built successfully. It will be mined in the next block'}
            return jsonify(response), 200
        else:
            response = {'message': 'Failed to transfer coins'}
            return jsonify(response), 400

    except ValueError as e:
        return jsonify({'success': False, 'message': str(e)}), 400
    except Exception as e:
        return jsonify({'success': False, 'message': 'Internal Server Error'}), 500

# Locate specific transfer request
@app.route('/get_request/<request_id>', methods=['GET'])
def get_request(request_id):
    with coin.balance_lock:
        # Search for the request in the queue based on permission['id']
        requested_request = next((request_obj for request_obj in list(coin.request_queue.queue)
                                 if request_obj.permission['id'] == request_id), None)

        if requested_request:
            # Return the requested request as JSON
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

# Retrieve all unprocessed requests
@app.route('/get_requests', methods=['GET'])
def get_requests():
    with coin.balance_lock:
        # Filter requests with permission['processed'] set to None
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

# Endpoint to update request permissions
@app.route('/update_request_permissions/<request_id>', methods=['POST'])
def update_request_permissions(request_id):
    try:
        data = request.get_json()
        sender_pub = data['sender_pub']
        permission_sig = data['permission_sig']
        permission_approval = data['permission_approval']

        with coin.balance_lock:
            # Call the Coin class method to update request permissions
            coin.update_request_permissions(request_id, sender_pub, permission_sig, permission_approval)

        return jsonify({'success': 'Request permissions updated successfully'})
    except Exception as e:
        return jsonify({'error': str(e)}), 400

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
        node_address = blockchain.randomly_select_validator()
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

        if blockchain.add_staking_transaction(address, amount, fee, hash, pub_key, min_term, node_address, signature, sub_type, type):
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

        if blockchain.add_unstaking_transaction(address, amount, contract_id, fee, hash, pub_key, signature, sub_type, type):
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

    for activity in coin.other_activity_history:
        if activity['sender'] == address:
            other_activity_result -= activity['amount']
        if activity['recipient'] == address:
            other_activity_result += activity['amount']

    # Prepare the response
    response_data = {
        "address": address,
        "transfer_history": transfer_result,
        "minting_history": minting_result,
        "burning_history": burning_result,
        "other_activity_history": other_activity_result,
    }

    return jsonify(response_data), 200

#Get circulation figures for OMC
@app.route('/get_coin_economy', methods=['GET'])
def get_max_coin_economy():
    return jsonify(coin.report_coin_economy())

#==== BLOCK PROPAGATION OPS ====#

#receive new block
@app.route('/blocks/receive_block', methods=['POST'])
def receive_block_endpoint():
    received_block = request.get_json()  # Parse JSON data from the request

    if blockchain.receive_block(received_block):
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
    blockchain.add_block(block_data)
    return "Block added successfully"

# Endpoint for reaching consensus on a proposed block
@app.route('/blocks/consensus', methods=['POST'])
def reach_consensus():
    proposed_block = request.get_json()
    blockchain.reach_consensus(proposed_block)
    return "Consensus reached for the proposed block"

#==== TRANSACTIONS ====#

# Retrieve transaction to validate and vote on
@app.route('/transactions/receive_tx', methods=['POST'])
def receive_transaction():
    transaction = request.get_json()  # Parse JSON data from the request

    # Assume transaction is a dictionary with 'address', 'pub_key', 'new_tx', and 'signature'
    if blockchain.receive_tx(transaction['address'], transaction['hash'], transaction['pub_key'], transaction['new_tx'], transaction['signature']):
        return 'Transaction received and validateded successfully', 200
    else:
        response = {'message': 'Issue validating the received transaction'}
        return jsonify(response), 400

#==== USER OPERATIONS ====#

@app.route('/receive_price_data', methods=['POST'])
def receive_price_data():
    global latest_price_data
    data = request.get_json()
    if "price" in data:
        latest_price_data["price"] = data["price"]
        return jsonify({"message": "Price data received successfully"}), 200
    else:
        return jsonify({"message": "Invalid data format"}), 400

@app.route('/get_latest_price', methods=['GET'])
def get_latest_price():
    return jsonify(latest_price_data), 200

@app.route('/get_class_hashes', methods=['GET'])
def get_class_hashes():
    # Load class hashes from a secure source (e.g., a file, a secure database, etc.)
    class_hashes = {
        'coin': 'hash_of_OMC_class',
        'verifier': 'hash_of_Verifier_class',
        'crypto_utils': 'hash_of_CUtils_class',
        'fee_calculator': 'hash_of_DynamicFeeCalculator_class'
    }
    return jsonify(class_hashes)

#run it
if __name__ == '__main__':
    app.run(host='0.0.0.0', port=3400)
