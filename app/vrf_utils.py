# vrf_utils.py

import logging
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.exceptions import InvalidSignature

class VRFUtils:
    def __init__(self, private_key_pem: str, password: bytes = None):
        try:
            self.private_key = self.load_private_key(private_key_pem, password)
            self.public_key = self.private_key.public_key()
            logging.info("VRFUtils: Private key loaded successfully.")
        except Exception as e:
            logging.critical(f"VRFUtils: Failed to load private key: {e}")
            raise

    def load_private_key(self, pem: str, password: bytes = None):
        return serialization.load_pem_private_key(
            pem.encode(),
            password=password,
        )

    def prove(self, alpha: str) -> bytes:
        """
        Generates a VRF proof for the given alpha.

        :param alpha: The input data in hexadecimal string format.
        :return: The VRF proof as bytes.
        """
        try:
            logging.debug(f"VRFUtils: Starting proof generation for alpha: {alpha}")
            alpha_bytes = bytes.fromhex(alpha)
            signature = self.private_key.sign(
                alpha_bytes,
                ec.ECDSA(hashes.SHA256())
            )
            logging.debug(f"VRFUtils: Proof generation successful for alpha: {alpha}")
            return signature
        except Exception as e:
            logging.error(f"VRFUtils: Failed to generate proof for alpha {alpha}: {e}")
            raise

    def vrf_verify(self, alpha: str, proof: bytes, public_key_pem: str) -> bool:
        """
        Verifies a VRF proof for the given alpha using the provided public key.

        :param alpha: The input data in hexadecimal string format.
        :param proof: The VRF proof as bytes.
        :param public_key_pem: The public key of the validator in PEM format.
        :return: True if the proof is valid, False otherwise.
        """
        try:
            logging.debug(f"VRFUtils: Starting proof verification for alpha: {alpha} with provided proof.")
            # Load the public key from PEM
            public_key = serialization.load_pem_public_key(public_key_pem.encode())

            # Convert alpha from hex to bytes
            alpha_bytes = bytes.fromhex(alpha)

            # Verify the signature
            public_key.verify(
                proof,
                alpha_bytes,
                ec.ECDSA(hashes.SHA256())
            )
            logging.debug("VRFUtils: Proof verification successful.")
            return True
        except InvalidSignature:
            logging.warning("VRFUtils: Invalid signature. Proof verification failed.")
            return False
        except Exception as e:
            logging.error(f"VRFUtils: Error during proof verification: {e}")
            return False
