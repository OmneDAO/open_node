import hashlib
import json

class LightProofVerifier:
    """
    Verifies light-client proofs for parameter roots.
    """

    @staticmethod
    def verify_proof(root_hash: str, key: str, proof: list, expected_value: str) -> bool:
        """
        Verify a Merkle-Patricia proof for a given key and value.

        Args:
            root_hash (str): The root hash of the trie.
            key (str): The key to verify.
            proof (list): The proof nodes.
            expected_value (str): The expected value for the key.

        Returns:
            bool: True if the proof is valid, False otherwise.
        """
        try:
            computed_hash = LightProofVerifier._compute_proof_hash(key, proof)
            return computed_hash == root_hash and proof[-1] == expected_value
        except Exception as e:
            print(f"Proof verification failed: {e}")
            return False

    @staticmethod
    def _compute_proof_hash(key: str, proof: list) -> str:
        """
        Compute the hash from the proof nodes.

        Args:
            key (str): The key to verify.
            proof (list): The proof nodes.

        Returns:
            str: The computed hash.
        """
        current_hash = hashlib.sha256(key.encode()).hexdigest()
        for node in proof:
            current_hash = hashlib.sha256((current_hash + node).encode()).hexdigest()
        return current_hash

# Example usage
if __name__ == "__main__":
    root = "abc123"  # Example root hash
    key = "param_key"
    proof = ["node1", "node2", "expected_value"]
    expected_value = "expected_value"

    verifier = LightProofVerifier()
    is_valid = verifier.verify_proof(root, key, proof, expected_value)
    print(f"Proof valid: {is_valid}")