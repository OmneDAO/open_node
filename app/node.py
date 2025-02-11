# node.py

import json
import hashlib
import logging
from datetime import datetime, timezone
import base64
import secrets
from typing import Optional
from mnemonic import Mnemonic
import ecdsa

class Node:
    def __init__(self, address: Optional[str] = None, stake_weight: int = 0, url: str = "http://node1.omne:3400",
                 version: str = "0.0.1", private_key: Optional[str] = None, public_key: Optional[str] = None,
                 signature: Optional[str] = None, steward: Optional[str] = None):
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
            mnemonic = self.generate_mnemonic()
            account = self.generate_account_from_mnemonic(mnemonic)
            self.address = account['address']
            self.private_key = account['private_key']
            self.public_key = account['pub_key']
            self.signature = None  # Will be set when signing data

            # Log or store the mnemonic securely
            logging.info(f"Node created with mnemonic: {mnemonic}")

    def generate_mnemonic(self) -> str:
        """
        Generate a mnemonic using BIP39 standard.
        """
        mnemo = Mnemonic("english")
        mnemonic = mnemo.generate(strength=128)  # Generates a 12-word mnemonic
        logging.info(f"Generated mnemonic for node: {mnemonic}")
        return mnemonic

    def generate_account_from_mnemonic(self, mnemonic: str, passphrase: str = "") -> dict:
        """
        Generate an account (private key, public key, address) from a mnemonic phrase.
        """
        seed_bytes = self.generate_seed(mnemonic, passphrase)
        private_key_bytes = hashlib.sha256(seed_bytes).digest()
        sk = ecdsa.SigningKey.from_string(private_key_bytes, curve=ecdsa.SECP256k1)
        vk = sk.get_verifying_key()
        public_key = vk.to_string('compressed').hex()

        address = self.generate_address_from_pub_key(public_key)

        return {
            'address': address,
            'pub_key': public_key,
            'private_key': sk.to_string().hex(),
            'mnemonic': mnemonic
        }

    def generate_seed(self, mnemonic: str, passphrase: str = "") -> bytes:
        """
        Generate seed using BIP39 standard.
        """
        mnemo = Mnemonic('english')
        return mnemo.to_seed(mnemonic, passphrase)

    def generate_address_from_pub_key(self, public_key: str) -> str:
        """
        Generate a blockchain address from a public key.
        """
        public_key_bytes = bytes.fromhex(public_key)
        address_hash = hashlib.sha256(public_key_bytes).hexdigest()
        return '0z' + address_hash[-40:]

    def is_hex(self, s: str) -> bool:
        """
        Validate if a string is in hexadecimal format.
        """
        try:
            int(s, 16)
            return True
        except ValueError:
            return False

    def sign_node_data(self, data: dict) -> Optional[str]:
        """
        Sign data using the node's private key.
        """
        if not self.private_key:
            logging.error("Private key not set. Cannot sign data.")
            return None

        try:
            sk = ecdsa.SigningKey.from_string(bytes.fromhex(self.private_key), curve=ecdsa.SECP256k1)
            data_str = json.dumps(data, sort_keys=True)
            data_hash = hashlib.sha256(data_str.encode('utf-8')).digest()
            signature = sk.sign(data_hash)
            return base64.b64encode(signature).decode('utf-8')
        except Exception as e:
            logging.error(f"Failed to sign data: {e}")
            return None

    def verify_node_signature(self, data: dict, signature: str) -> bool:
        """
        Verify signature using the node's public key.
        """
        if not self.public_key:
            logging.error("Public key not set. Cannot verify signature.")
            return False

        try:
            vk = ecdsa.VerifyingKey.from_string(bytes.fromhex(self.public_key), curve=ecdsa.SECP256k1)
            data_str = json.dumps(data, sort_keys=True)
            data_hash = hashlib.sha256(data_str.encode('utf-8')).digest()
            signature_bytes = base64.b64decode(signature)
            return vk.verify(signature_bytes, data_hash)
        except ecdsa.BadSignatureError:
            logging.error("Bad signature detected.")
            return False
        except Exception as e:
            logging.error(f"Failed to verify signature: {e}")
            return False

    def to_dict(self) -> dict:
        """
        Serialize the node to a dictionary.
        """
        return {
            'address': self.address,
            'stake_weight': self.stake_weight,
            'url': self.url,
            'version': self.version,
            'public_key': self.public_key,
            'signature': self.signature,
            'steward': self.steward
        }
