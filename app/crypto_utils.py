import logging
import json
import base64
import hashlib
from datetime import datetime, timezone, date
from typing import Any, Dict
from decimal import Decimal
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import ec  # for PEM keys

# Use the ecdsa library for hex-encoded keys
from ecdsa import SigningKey, VerifyingKey, SECP256k1, BadSignatureError, util

class DecimalEncoder(json.JSONEncoder):
    """
    JSON encoder for converting Python Decimal objects to strings
    so they can be properly handled in canonical JSON.
    """
    def default(self, obj):
        if isinstance(obj, Decimal):
            return format(obj, 'f')  # fixed-point
        return super().default(obj)

class CryptoUtils:
    """
    Provides cryptographic utilities for signing and verifying standard blockchain transactions.
    - For hex-encoded keys (secp256k1): uses the ecdsa library
    - For PEM keys: uses cryptography.hazmat (reserved for VRF usage, etc.)
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
        Loads an EC private key from a string. 
        - If it starts with a PEM header => treat as PEM-formatted (cryptography).
        - Otherwise => treat as hex-encoded (ecdsa).
        """
        try:
            if private_key_str.startswith("-----BEGIN"):
                # PEM format
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
                # Hex-encoded raw private key
                private_key_bytes = bytes.fromhex(private_key_str)
                signing_key = SigningKey.from_string(private_key_bytes, curve=SECP256k1)
                self.logger.info("Hex-encoded private key loaded successfully.")
                return signing_key
        except Exception as e:
            self.logger.error(f"Failed to load private key: {e}")
            raise

    def load_public_key(self, public_key_str: str):
        """
        Loads an EC public key from a string. 
        - If it starts with PEM => treat as PEM (cryptography).
        - Otherwise => treat as hex-encoded (ecdsa).
        """
        try:
            if public_key_str.startswith("-----BEGIN"):
                # PEM format
                public_key = serialization.load_pem_public_key(
                    public_key_str.encode('utf-8'),
                    backend=default_backend()
                )
                if not isinstance(public_key, ec.EllipticCurvePublicKey):
                    raise ValueError("Loaded key is not an EC public key.")
                self.logger.info("PEM-formatted public key loaded successfully.")
                return public_key
            else:
                # Hex-encoded raw public key
                public_key_bytes = bytes.fromhex(public_key_str)
                verifying_key = VerifyingKey.from_string(public_key_bytes, curve=SECP256k1)
                self.logger.info("Hex-encoded public key loaded successfully.")
                return verifying_key
        except Exception as e:
            self.logger.error(f"Failed to load public key: {e}")
            raise

    def get_public_key_pem(self, private_key_str: str) -> str:
        """
        Extracts a public key from the given private key string.
        - If PEM => returns PEM public key.
        - If hex => returns hex public key.
        """
        try:
            key_obj = self.load_private_key(private_key_str)
            # If this is a PEM key, it will have a `public_key()` method
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
                # Must be a hex-based ecdsa key
                verifying_key = key_obj.get_verifying_key()
                public_key_hex = verifying_key.to_string().hex()
                self.logger.info("Public key extracted successfully from hex key.")
                return public_key_hex
        except Exception as e:
            self.logger.error(f"Failed to extract public key: {e}")
            raise
    
    def get_address_from_private_key(self, private_key_str: str) -> str:
        """
        Derives a blockchain address from the given private key.
        This is done by extracting the public key, computing its SHA-256 hash,
        and taking the first 40 hexadecimal characters with a prefix.
            
        :param private_key_str: The private key in hex or PEM format.
        :return: The derived address as a string.
        """
        try:
            # Get the public key using the existing method.
            public_key_str = self.get_public_key_pem(private_key_str)
                
            # Compute a SHA-256 hash of the public key.
            public_key_hash = hashlib.sha256(public_key_str.encode('utf-8')).hexdigest()
                
            # Derive the address by taking the first 40 hex digits and prefixing with "0z"
            address = "0z" + public_key_hash[:40]
            self.logger.info(f"Derived address: {address}")
            return address
        except Exception as e:
            self.logger.error(f"Failed to derive address from private key: {e}")
            raise

    def sign_transaction(self, private_key_hex: str, transaction_dict: Dict) -> str:
        """
        (Option A) Let the ecdsa library do the hashing. 
        Steps:
          1) Remove 'signature'/'hash' from the transaction.
          2) JSON-serialize with (sort_keys=True, separators=(',',':'), optional DecimalEncoder).
          3) Pass the resulting bytes to signing_key.sign(..., hashfunc=hashlib.sha256),
             so ecdsa does a single SHA-256 internally.
          4) Convert DER signature to base64 string.
        """
        try:
            # 1) Remove 'signature'/'hash'
            tx_copy = dict(transaction_dict)
            tx_copy.pop('signature', None)
            tx_copy.pop('hash', None)

            # 2) Build canonical JSON
            canonical_str = json.dumps(
                tx_copy,
                sort_keys=True,
                separators=(',', ':'),
                cls=DecimalEncoder
            )
            logging.info(f"[sign_transaction] canonical_str => {canonical_str}")

            # Raw message (not hashed here, ecdsa will do the hashing)
            payload_bytes = canonical_str.encode('utf-8')

            # 3) sign using ecdsa
            private_key_bytes = bytes.fromhex(private_key_hex)
            signing_key = SigningKey.from_string(private_key_bytes, curve=SECP256k1)
            # Pass the raw payload + specify hashfunc => ecdsa does exactly one sha256
            signature_der = signing_key.sign(
                payload_bytes,
                hashfunc=hashlib.sha256,
                sigencode=util.sigencode_der
            )

            signature_b64 = base64.b64encode(signature_der).decode('utf-8')
            self.logger.info("Transaction signed successfully.")
            return signature_b64

        except Exception as e:
            self.logger.error(f"Failed to sign transaction: {e}")
            raise

    @staticmethod
    def verify_transaction(pub_key_hex: str, transaction: Dict[str, Any], signature_base64: str) -> bool:
        """
        (Option B) We do the hashing manually, then call verify_digest().
        Steps:
        1) Remove 'signature'/'hash' from transaction.
        2) Canonical-serialize the remaining fields => JSON (sort_keys=True, no extra spaces).
        3) Compute SHA-256 digest of that string.
        4) Decode the signature from base64 => DER, then use verify_digest(...).
            This ensures we do NOT re-hash the digest internally.
        """
        try:
            # 1) Convert hex-encoded pubkey => VerifyingKey
            pub_key_bytes = bytes.fromhex(pub_key_hex)
            vk = VerifyingKey.from_string(pub_key_bytes, curve=SECP256k1)

            # 2) Make a copy to avoid mutating the original
            tx_copy = dict(transaction)
            tx_copy.pop('signature', None)
            tx_copy.pop('hash', None)

            # Canonical JSON
            transaction_str = json.dumps(
                tx_copy,
                sort_keys=True,
                separators=(',', ':'),
                cls=DecimalEncoder
            )
            logging.info(f"[verify_transaction] canonical_str => {transaction_str}")

            # 3) Manual SHA-256 => 32-byte digest
            digest = hashlib.sha256(transaction_str.encode('utf-8')).digest()

            # 4) decode signature from base64 => DER => verify the *digest*
            signature_der = base64.b64decode(signature_base64)
            vk.verify_digest(
                signature_der,
                digest,
                sigdecode=util.sigdecode_der  # no hashfunc => no double-hash
            )
            return True
        except BadSignatureError:
            return False
        except Exception:
            return False

    def calculate_sha256_hash(self, transaction: dict) -> str:
        """
        Utility to produce a local 'transaction hash' if needed.
        Excludes 'signature'/'hash' fields, uses the same canonical JSON approach
        but returns hex digest. This is just for reference or to store as a TX ID.
        """
        tx_copy = dict(transaction)
        tx_copy.pop('signature', None)
        tx_copy.pop('hash', None)

        transaction_str = json.dumps(
            tx_copy,
            sort_keys=True,
            separators=(',', ':'),
            cls=DecimalEncoder
        )
        return hashlib.sha256(transaction_str.encode('utf-8')).hexdigest()
