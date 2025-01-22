# generate_pem_key.py

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
import os

def generate_pem_private_key(password: bytes = None, filename: str = "omne_node_vrf_key.pem"):
    """
    Generates an EC private key and saves it in PEM format.
    
    :param password: Optional password to encrypt the PEM file.
    :param filename: The filename to save the PEM key.
    """
    # Generate the private key
    private_key = ec.generate_private_key(ec.SECP256R1())

    # Define encryption algorithm
    if password:
        encryption_algorithm = serialization.BestAvailableEncryption(password)
    else:
        encryption_algorithm = serialization.NoEncryption()

    # Serialize the private key to PEM format
    pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,  # or PKCS8
        encryption_algorithm=encryption_algorithm
    )

    # Save the PEM key to a file
    with open(filename, 'wb') as pem_out:
        pem_out.write(pem)
    
    print(f"PEM-encoded private key saved to {filename}")

    return pem

if __name__ == "__main__":
    # Optional: Generate an encrypted PEM key with a password
    # Replace 'your_password_here' with a secure password
    # password = b'your_password_here'
    # pem_key = generate_pem_private_key(password=password)

    # Generate an unencrypted PEM key
    pem_key = generate_pem_private_key()
