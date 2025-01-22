# ~/app/utils.py

import logging
import os
import secrets
import time
import hashlib
from datetime import datetime, timezone

from qiskit import QuantumCircuit, transpile, assemble
from qiskit.visualization import plot_histogram
from qiskit_aer import Aer
from qiskit_aer import AerSimulator

class QuantumUtils:
    @staticmethod
    def quantum_random_bytes(num_bytes, retry_attempts=3, retry_delay=1):
        for attempt in range(retry_attempts):
            try:
                logging.debug("Attempting to generate random bytes using os.urandom.")
                random_bytes = os.urandom(num_bytes)
                if random_bytes:
                    logging.debug(f"Generated random bytes using os.urandom: {random_bytes.hex()}")
                    return random_bytes
                else:
                    raise ValueError("No random bytes generated using os.urandom")
            except Exception as e:
                logging.error(f"Error in quantum_random_bytes using os.urandom on attempt {attempt + 1}: {e}")

            try:
                logging.debug("Falling back to generate random bytes using secrets.token_bytes.")
                random_bytes = secrets.token_bytes(num_bytes)
                if random_bytes:
                    logging.debug(f"Generated random bytes using secrets.token_bytes: {random_bytes.hex()}")
                    return random_bytes
                else:
                    raise ValueError("No random bytes generated using secrets.token_bytes")
            except Exception as e:
                logging.error(f"Error in quantum_random_bytes using secrets.token_bytes on attempt {attempt + 1}: {e}")

            logging.warning(f"Retrying random byte generation in {retry_delay} seconds...")
            time.sleep(retry_delay)

        logging.critical("Failed to generate random bytes with both os.urandom and secrets.token_bytes after multiple attempts.")
        raise ValueError("Failed to generate random bytes with both os.urandom and secrets.token_bytes after multiple attempts.")

    @staticmethod
    def quantum_random_int(max_value):
        if max_value < 0:
            raise ValueError("max_value must be non-negative")
        
        try:
            bits_needed = max_value.bit_length()
            num_bytes = (bits_needed + 7) // 8
            logging.debug(f"Number of bytes needed: {num_bytes}")

            while True:
                random_bytes = QuantumUtils.quantum_random_bytes(num_bytes)
                random_int = int.from_bytes(random_bytes, 'big')
                if random_int <= max_value:
                    break

            logging.debug(f"Quantum random int: {random_int} for max value: {max_value}")
            return random_int
        except Exception as e:
            logging.error(f"Error in quantum_random_int: {e}")
            raise

    @staticmethod
    def quantum_resistant_hash(data):
        try:
            data_bin = ''.join(format(ord(i), '08b') for i in data)
            n = len(data_bin)
            qubit_limit = 29  # Adjust based on the simulator's maximum capability
            hash_result = ''

            for i in range(0, n, qubit_limit):
                chunk = data_bin[i:i+qubit_limit]
                chunk_len = len(chunk)
                qc = QuantumCircuit(chunk_len)
                qc.h(range(chunk_len))

                for j in range(chunk_len-1):
                    qc.cx(j, j+1)

                qc.measure_all()

                simulator = AerSimulator()
                transpiled_qc = transpile(qc, simulator)
                result = simulator.run(transpiled_qc, shots=1).result()
                counts = result.get_counts()
                measured_data = max(counts, key=counts.get)
                hash_result += measured_data

            quantum_hash = hashlib.sha256(hash_result.encode()).hexdigest()
            logging.debug(f"Quantum resistant hash: {quantum_hash}")
            return quantum_hash

        except Exception as e:
            logging.error(f"Error in quantum_resistant_hash: {e}")
            raise
