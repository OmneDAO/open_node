# crypto_utils.py

import logging
import json
from typing import Any
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, ec
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.backends import default_backend

class CryptoUtils:
    """
    Provides cryptographic utilities such as key generation, signature creation, and verification.
    """

    def __init__(self):
        self.logger = logging.getLogger('CryptoUtils')
        self.logger.setLevel(logging.INFO)
        handler = logging.StreamHandler()
        formatter = logging.Formatter('[%(asctime)s] [%(levelname)s] [%(name)s] %(message)s')
        handler.setFormatter(formatter)
        self.logger.addHandler(handler)

    def load_private_key(self, private_key_pem: str) -> ec.EllipticCurvePrivateKey:
        """
        Loads an EC private key from a PEM-formatted string.

        :param private_key_pem: PEM-formatted private key string.
        :return: EllipticCurvePrivateKey object.
        """
        try:
            private_key = serialization.load_pem_private_key(
                private_key_pem.encode(),
                password=None,
                backend=default_backend()
            )
            if not isinstance(private_key, ec.EllipticCurvePrivateKey):
                raise ValueError("Loaded key is not an EC private key.")
            self.logger.info("Private key loaded successfully.")
            return private_key
        except Exception as e:
            self.logger.error(f"Failed to load private key: {e}")
            raise

    def load_public_key(self, public_key_pem: str) -> ec.EllipticCurvePublicKey:
        """
        Loads an EC public key from a PEM-formatted string.

        :param public_key_pem: PEM-formatted public key string.
        :return: EllipticCurvePublicKey object.
        """
        try:
            public_key = serialization.load_pem_public_key(
                public_key_pem.encode(),
                backend=default_backend()
            )
            if not isinstance(public_key, ec.EllipticCurvePublicKey):
                raise ValueError("Loaded key is not an EC public key.")
            self.logger.info("Public key loaded successfully.")
            return public_key
        except Exception as e:
            self.logger.error(f"Failed to load public key: {e}")
            raise

    def sign_message(self, private_key_pem: str, message: Any) -> str:
        """
        Signs a message using the provided EC private key.

        :param private_key_pem: PEM-formatted private key string.
        :param message: The message to sign (can be a string or dict).
        :return: Signature as a hexadecimal string.
        """
        try:
            private_key = self.load_private_key(private_key_pem)
            if isinstance(message, dict):
                message_bytes = json.dumps(message, sort_keys=True).encode()
            elif isinstance(message, str):
                message_bytes = message.encode()
            else:
                message_bytes = bytes(message)

            signature = private_key.sign(
                message_bytes,
                ec.ECDSA(hashes.SHA256())
            )
            signature_hex = signature.hex()
            self.logger.info("Message signed successfully.")
            return signature_hex
        except Exception as e:
            self.logger.error(f"Failed to sign message: {e}")
            raise

    def verify_signature(self, public_key_pem: str, message: Any, signature_hex: str) -> bool:
        """
        Verifies a signature against the provided message and public key.

        :param public_key_pem: PEM-formatted public key string.
        :param message: The original message that was signed.
        :param signature_hex: Signature as a hexadecimal string.
        :return: True if the signature is valid, False otherwise.
        """
        try:
            public_key = self.load_public_key(public_key_pem)
            if isinstance(message, dict):
                message_bytes = json.dumps(message, sort_keys=True).encode()
            elif isinstance(message, str):
                message_bytes = message.encode()
            else:
                message_bytes = bytes(message)

            signature = bytes.fromhex(signature_hex)

            public_key.verify(
                signature,
                message_bytes,
                ec.ECDSA(hashes.SHA256())
            )
            self.logger.info("Signature verification successful.")
            return True
        except InvalidSignature:
            self.logger.warning("Invalid signature.")
            return False
        except Exception as e:
            self.logger.error(f"Error during signature verification: {e}")
            return False

    def get_public_key_pem(self, private_key_pem: str) -> str:
        """
        Extracts the public key from a given private key.

        :param private_key_pem: PEM-formatted private key string.
        :return: PEM-formatted public key string.
        """
        try:
            private_key = self.load_private_key(private_key_pem)
            public_key = private_key.public_key()
            public_pem = public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            )
            public_pem_str = public_pem.decode()
            self.logger.info("Public key extracted successfully.")
            return public_pem_str
        except Exception as e:
            self.logger.error(f"Failed to extract public key: {e}")
            raise
