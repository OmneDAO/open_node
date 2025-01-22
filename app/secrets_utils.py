# secrets_utils.py

import logging

def get_secret(secret_name: str) -> str:
    """
    Reads the secret from the /run/secrets directory.

    :param secret_name: Name of the secret.
    :return: The secret value as a string.
    """
    secret_path = f"/run/secrets/{secret_name}"
    try:
        with open(secret_path, 'r') as secret_file:
            secret = secret_file.read().strip()
            logging.debug(f"Secret '{secret_name}' successfully read.")
            return secret
    except FileNotFoundError:
        logging.error(f"Secret '{secret_name}' not found at {secret_path}.")
        raise
    except Exception as e:
        logging.error(f"Error reading secret '{secret_name}': {e}")
        raise
