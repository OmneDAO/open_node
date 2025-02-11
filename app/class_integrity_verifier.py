# class_integrity_verifier.py

import logging
import hashlib
import inspect
import requests
from typing import Dict, Type

class ClassIntegrityVerifier:
    """
    Verifies the integrity of critical classes by comparing their hashes against known values from a trusted source.
    """

    # URL to fetch known good class hashes
    HASH_API_URL = "https://trusted-source.omne.io/class-hashes.json"  # Update to your actual trusted source

    # Dictionary to hold classes to verify: name -> class type
    classes_to_verify: Dict[str, Type] = {}

    @classmethod
    def set_classes_to_verify(cls, classes: Dict[str, Type]) -> None:
        """
        Sets the classes that need to be verified.

        :param classes: Dictionary mapping class names to class types.
        """
        cls.classes_to_verify = classes
        logging.info(f"Classes to verify set: {list(classes.keys())}")

    @classmethod
    def compute_class_hash(cls, class_type: Type) -> str:
        """
        Computes the SHA-256 hash of the class's source code.

        :param class_type: The class to hash.
        :return: Hexadecimal SHA-256 hash string.
        """
        try:
            source = inspect.getsource(class_type)
            source_bytes = source.encode('utf-8')
            class_hash = hashlib.sha256(source_bytes).hexdigest()
            logging.debug(f"Computed hash for class {class_type.__name__}: {class_hash}")
            return class_hash
        except Exception as e:
            logging.error(f"Failed to compute hash for class {class_type.__name__}: {e}")
            return ""

    @classmethod
    def fetch_known_hashes(cls) -> Dict[str, str]:
        """
        Fetches the known good hashes from the trusted HASH_API_URL.

        :return: Dictionary mapping class names to their known good hashes.
        """
        try:
            response = requests.get(cls.HASH_API_URL, timeout=10)
            if response.status_code == 200:
                known_hashes = response.json()
                logging.info(f"Fetched known hashes from {cls.HASH_API_URL}")
                return known_hashes
            else:
                logging.error(f"Failed to fetch known hashes: HTTP {response.status_code}")
                return {}
        except Exception as e:
            logging.error(f"Error fetching known hashes: {e}")
            return {}

    @classmethod
    def verify_class_integrity(cls) -> bool:
        """
        Verifies the integrity of all set classes by comparing their hashes.

        :return: True if all classes pass verification, False otherwise.
        """
        if not cls.classes_to_verify:
            logging.warning("No classes set for integrity verification.")
            return True  # Nothing to verify

        known_hashes = cls.fetch_known_hashes()
        if not known_hashes:
            logging.error("No known hashes available for verification.")
            return False

        all_verified = True
        for class_name, class_type in cls.classes_to_verify.items():
            computed_hash = cls.compute_class_hash(class_type)
            known_hash = known_hashes.get(class_name)

            if not known_hash:
                logging.error(f"No known hash found for class {class_name}.")
                all_verified = False
                continue

            if computed_hash != known_hash:
                logging.critical(f"Integrity verification failed for class {class_name}. "
                                 f"Expected: {known_hash}, Computed: {computed_hash}")
                all_verified = False
            else:
                logging.info(f"Integrity verification passed for class {class_name}.")

        return all_verified
