# key_management.py

import boto3
from typing import Tuple

class KeyManager:
    """
    Manages cryptographic key operations using AWS KMS.
    """

    def __init__(self, kms_client, key_id: str):
        self.kms_client = kms_client
        self.key_id = key_id

    def get_public_key_pem(self) -> bytes:
        """
        Retrieves the public key from AWS KMS.

        :return: PEM-encoded public key.
        """
        response = self.kms_client.get_public_key(KeyId=self.key_id)
        public_key = response['PublicKey']
        return public_key

    def sign(self, data: bytes) -> bytes:
        """
        Signs data using AWS KMS.

        :param data: Data to sign.
        :return: Signature bytes.
        """
        response = self.kms_client.sign(
            KeyId=self.key_id,
            Message=data,
            MessageType='RAW',
            SigningAlgorithm='ECDSA_SHA_256'
        )
        return response['Signature']

    def verify(self, data: bytes, signature: bytes) -> bool:
        """
        Verifies a signature using AWS KMS.

        :param data: Original data.
        :param signature: Signature to verify.
        :return: True if valid, False otherwise.
        """
        response = self.kms_client.verify(
            KeyId=self.key_id,
            Message=data,
            MessageType='RAW',
            Signature=signature,
            SigningAlgorithm='ECDSA_SHA_256'
        )
        return response['SignatureValid']
