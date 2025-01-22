# alpha_generator.py

import hashlib
import time
import logging

class AlphaGenerator:
    """
    Generates dynamic alpha values based on the latest block hash and current timestamp.
    """

    def __init__(self, blockchain):
        """
        Initializes the AlphaGenerator with a reference to the blockchain.

        :param blockchain: Instance of the Blockchain class.
        """
        self.blockchain = blockchain
        self.logger = logging.getLogger('AlphaGenerator')

    def generate_alpha(self, round_number: int) -> str:
        """
        Generates a unique alpha for the given consensus round.

        :param round_number: The current consensus round number.
        :return: A hexadecimal string representing the alpha.
        """
        try:
            latest_block = self.blockchain.get_latest_block()
            if latest_block:
                block_hash = latest_block.hash  # Assuming 'hash' is a hexadecimal string
            else:
                # Handle the genesis block scenario
                block_hash = '0' * 64  # Example: 64 zeros for genesis
                self.logger.info("No previous blocks found. Using default block hash for genesis alpha.")

            current_time = str(time.time())
            combined = f"{block_hash}-{current_time}"
            alpha = hashlib.sha256(combined.encode('utf-8')).hexdigest()
            self.logger.debug(f"AlphaGenerator: Generated alpha: {alpha}")
            return alpha
        except Exception as e:
            self.logger.error(f"AlphaGenerator: Failed to generate alpha: {e}")
            raise
