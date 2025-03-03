import logging
import json
import base64
import hashlib
from datetime import datetime, timezone, date
from typing import Any
from decimal import Decimal
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import ec  # for PEM keys

# Use the ecdsa library for hex‐encoded keys
from ecdsa import SigningKey, VerifyingKey, SECP256k1, BadSignatureError

# Define a DecimalEncoder if needed for JSON serialization.
class DecimalEncoder(json.JSONEncoder):
    def default(self, obj):
        if isinstance(obj, Decimal):
            return format(obj, 'f')  # Force fixed-point format
        return super().default(obj)

class CryptoUtils:
    """
    Provides cryptographic utilities for signing and verifying standard blockchain transactions.
    (PEM keys are reserved for VRF functions.)
    This module supports both PEM-formatted keys (via the cryptography library) and
    hex-encoded keys (via the ecdsa package). Standard transaction signing uses hex keys,
    while VRF-related functions can use PEM keys.
    """
    def __init__(self):
        self.logger = logging.getLogger('CryptoUtils')
        self.logger.setLevel(logging.INFO)
        handler = logging.StreamHandler()
        formatter = logging.Formatter('[%(asctime)s] [%(levelname)s] [%(name)s] %(message)s')
        handler.setFormatter(formatter)
        if not self.logger.handlers:
            self.logger.addHandler(handler)

    def load_private_key(self, private_key_str: str):
        """
        Loads an EC private key from a string. If the string starts with a PEM header,
        it is assumed to be PEM-formatted (for VRF functions); otherwise, it is treated as a hex-encoded key.
        """
        try:
            if private_key_str.startswith("-----BEGIN"):
                # PEM branch (cryptography library)
                private_key = serialization.load_pem_private_key(
                    private_key_str.encode('utf-8'),
                    password=None,
                    backend=default_backend()
                )
                if not isinstance(private_key, ec.EllipticCurvePrivateKey):
                    raise ValueError("Loaded key is not an EC private key.")
                self.logger.info("PEM-formatted private key loaded successfully.")
                return private_key
            else:
                # Hex-encoded branch (ecdsa package)
                private_key_bytes = bytes.fromhex(private_key_str)
                signing_key = SigningKey.from_string(private_key_bytes, curve=SECP256k1)
                self.logger.info("Hex-encoded private key loaded successfully.")
                return signing_key
        except Exception as e:
            self.logger.error(f"Failed to load private key: {e}")
            raise

    def load_public_key(self, public_key_str: str):
        """
        Loads an EC public key from a string. If the string starts with a PEM header,
        it is assumed to be PEM-formatted (for VRF functions); otherwise, it is treated as a hex-encoded key.
        """
        try:
            if public_key_str.startswith("-----BEGIN"):
                public_key = serialization.load_pem_public_key(
                    public_key_str.encode('utf-8'),
                    backend=default_backend()
                )
                if not isinstance(public_key, ec.EllipticCurvePublicKey):
                    raise ValueError("Loaded key is not an EC public key.")
                self.logger.info("PEM-formatted public key loaded successfully.")
                return public_key
            else:
                public_key_bytes = bytes.fromhex(public_key_str)
                verifying_key = VerifyingKey.from_string(public_key_bytes, curve=SECP256k1)
                self.logger.info("Hex-encoded public key loaded successfully.")
                return verifying_key
        except Exception as e:
            self.logger.error(f"Failed to load public key: {e}")
            raise

    def get_public_key_pem(self, private_key_str: str) -> str:
        """
        Extracts the public key from a given private key.
        For PEM-formatted keys, returns the public key in PEM format.
        For hex-encoded keys, returns the hex-encoded public key.
        """
        try:
            key_obj = self.load_private_key(private_key_str)
            if hasattr(key_obj, 'public_key'):
                public_key = key_obj.public_key()
                public_pem = public_key.public_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PublicFormat.SubjectPublicKeyInfo
                )
                public_pem_str = public_pem.decode('utf-8')
                self.logger.info("Public key extracted successfully from PEM key.")
                return public_pem_str
            else:
                verifying_key = key_obj.get_verifying_key()
                public_key_hex = verifying_key.to_string().hex()
                self.logger.info("Public key extracted successfully from hex key.")
                return public_key_hex
        except Exception as e:
            self.logger.error(f"Failed to extract public key: {e}")
            raise

    def sign_message(self, private_key: str, hash_hex: str) -> str:
        """
        Signs the provided SHA‑256 hash using the given private key.
        
        :param private_key: The private key as a string (PEM or hex).
        :param hash_hex: The SHA‑256 hash (hex string) of the canonical payload.
        :return: Base64-encoded signature.
        """
        try:
            key_obj = self.load_private_key(private_key)
            # Convert the hash to bytes.
            hash_bytes = bytes.fromhex(hash_hex)
            
            # Branch based on key type.
            if hasattr(key_obj, 'private_numbers'):
                # key_obj is a cryptography key.
                signature = key_obj.sign(hash_bytes, ec.ECDSA(hashes.SHA256()))
            else:
                # key_obj is an ecdsa.SigningKey (hex-encoded).
                signature = key_obj.sign(hash_bytes, hashfunc=hashlib.sha256)
            signature_b64 = base64.b64encode(signature).decode('utf-8')
            self.logger.info("Message signed successfully.")
            return signature_b64
        except Exception as e:
            self.logger.error(f"Failed to sign message: {e}")
            raise

    @staticmethod
    def verify_signature(public_key_str: str, transaction: dict, signature_base64: str) -> bool:
        """
        Verifies a signature against the transaction's canonical payload.
        
        This function reconstructs the canonical payload using only the following keys:
        "address", "balance", "type", "nonce", "timestamp", "withdrawals", "fee", "sender", "public_key".
        It then computes the SHA‑256 hash using compact separators, compares it to the stored 'hash' field,
        and then verifies that the signature (decoded from base64) is valid for this hash using the provided
        hex‑encoded public key.
        
        :param public_key_str: Hex-encoded public key.
        :param transaction: Transaction dictionary (must include a 'hash' key).
        :param signature_base64: Base64-encoded signature.
        :return: True if the signature is valid; False otherwise.
        """
        try:
            # If transaction is a string, parse it.
            if isinstance(transaction, str):
                transaction = json.loads(transaction)
            
            # Define the keys that form the canonical payload.
            keys_to_include = ["address", "balance", "type", "nonce", "timestamp", "withdrawals", "fee", "sender", "public_key"]
            canonical_tx = {k: transaction[k] for k in keys_to_include if k in transaction}
            
            # Build the canonical payload with compact separators.
            canonical_payload = json.dumps(canonical_tx, sort_keys=True, cls=DecimalEncoder, separators=(',', ':'))
            logging.info(f"Canonical payload for verification: {canonical_payload}")
            
            # Compute the SHA‑256 hash of the canonical payload.
            computed_hash = hashlib.sha256(canonical_payload.encode('utf-8')).hexdigest()
            
            # Compare the recomputed hash with the stored hash.
            stored_hash = transaction.get('hash')
            if stored_hash != computed_hash:
                logging.error("Recomputed hash does not match the stored transaction hash.")
                return False
            
            # Convert the public key from hex to bytes and create a verifying key.
            public_key_bytes = bytes.fromhex(public_key_str)
            verifying_key = VerifyingKey.from_string(public_key_bytes, curve=SECP256k1)
            
            # Decode the signature from base64.
            signature_bytes = base64.b64decode(signature_base64)
            
            # The message hash is the computed hash converted from hex to bytes.
            message_hash_bytes = bytes.fromhex(computed_hash)
            
            # Verify the signature.
            verifying_key.verify(signature_bytes, message_hash_bytes, hashfunc=hashlib.sha256)
            
            logging.info("Signature verification successful.")
            return True
        except BadSignatureError:
            logging.warning("Invalid signature.")
            return False
        except Exception as e:
            logging.error(f"Error during signature verification: {e}")
            return False

    def calculate_sha256_hash(self, transaction: dict) -> str:
        """
        Calculates the SHA-256 hash of a transaction (excluding its 'hash' field).
        
        :param transaction: The transaction dictionary.
        :return: The SHA-256 hash as a hexadecimal string.
        """
        transaction_copy = transaction.copy()
        transaction_copy.pop('hash', None)
        transaction_str = json.dumps(transaction_copy, sort_keys=True, cls=DecimalEncoder)
        return hashlib.sha256(transaction_str.encode('utf-8')).hexdigest()
