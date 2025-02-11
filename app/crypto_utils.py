import logging
import json
import base64
import hashlib
from typing import Any
from decimal import Decimal
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import ec  # for PEM keys

# Use the ecdsa library for hex‐encoded keys
from ecdsa import SigningKey, VerifyingKey, SECP256k1, BadSignatureError

# A JSON encoder that converts Decimals to strings.
class DecimalEncoder(json.JSONEncoder):
    def default(self, o):
        if isinstance(o, Decimal):
            return str(o)
        return super().default(o)

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

    def sign_message(self, private_key: str, message: Any) -> str:
        """
        Signs a message using the provided private key.
        For standard blockchain transactions the key is expected to be hex-encoded,
        but if a PEM key is provided the function uses cryptography's signing method.
        The message is assumed to be in canonical form (i.e. a dictionary with sorted keys)
        and is first serialized (using DecimalEncoder) then hashed using SHA-256. That hash is then signed.
        
        :param private_key: The private key as a string (PEM or hex).
        :param message: The message to sign (a dict or string, already in canonical form).
        :return: Base64-encoded signature.
        """
        try:
            key_obj = self.load_private_key(private_key)
            if isinstance(message, dict):
                message_str = json.dumps(message, sort_keys=True, cls=DecimalEncoder)
            elif isinstance(message, str):
                message_str = message
            else:
                message_str = str(message)
            # Compute the SHA-256 digest of the canonical message string.
            message_hash = hashlib.sha256(message_str.encode('utf-8')).digest()

            # Branch based on key type.
            if hasattr(key_obj, 'private_numbers'):
                # key_obj is a cryptography key
                signature = key_obj.sign(message_hash, ec.ECDSA(hashes.SHA256()))
            else:
                # key_obj is an ecdsa.SigningKey (hex-encoded)
                signature = key_obj.sign(message_hash, hashfunc=hashlib.sha256)
            signature_b64 = base64.b64encode(signature).decode('utf-8')
            self.logger.info("Message signed successfully.")
            return signature_b64
        except Exception as e:
            self.logger.error(f"Failed to sign message: {e}")
            raise

    def verify_signature(self, public_key: str, message: Any, signature_b64: str) -> bool:
        """
        Verifies a signature against the canonical message payload.
        Excludes the 'signature' and 'hash' keys from the message if present.
        
        :param public_key: The public key as a string (PEM or hex).
        :param message: The transaction data (as a dict or string, canonical form).
        :param signature_b64: The base64-encoded signature.
        :return: True if the signature is valid, False otherwise.
        """
        try:
            key_obj = self.load_public_key(public_key)
            if isinstance(message, dict):
                # Remove keys not part of the signed payload.
                payload = {k: message[k] for k in sorted(message) if k not in ['signature', 'hash']}
                message_str = json.dumps(payload, sort_keys=True, cls=DecimalEncoder)
            elif isinstance(message, str):
                message_str = message
            else:
                message_str = str(message)
            message_hash = hashlib.sha256(message_str.encode('utf-8')).digest()
            signature = base64.b64decode(signature_b64)
            if hasattr(key_obj, 'public_numbers'):
                # key_obj is a cryptography public key
                key_obj.verify(signature, message_hash, ec.ECDSA(hashes.SHA256()))
            else:
                key_obj.verify(signature, message_hash, hashfunc=hashlib.sha256)
            self.logger.info("Signature verification successful.")
            return True
        except BadSignatureError:
            self.logger.warning("Invalid signature.")
            return False
        except Exception as e:
            self.logger.error(f"Error during signature verification: {e}")
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
