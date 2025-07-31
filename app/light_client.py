import hashlib
from typing import Dict, Any

class LightClientVerifier:
    """
    A utility class to verify IBC-like light-client proofs for cross-chain communication.
    """

    @staticmethod
    def verify_proof(proof: Dict[str, Any], expected_root: str) -> bool:
        """
        Verify a light-client proof against the expected root.

        Args:
            proof: The proof data, including the Merkle path and leaf value.
            expected_root: The expected Merkle root to verify against.

        Returns:
            bool: True if the proof is valid, False otherwise.
        """
        try:
            current_hash = proof["leaf"]

            for node in proof["path"]:
                if node["position"] == "left":
                    current_hash = hashlib.sha256((node["hash"] + current_hash).encode()).hexdigest()
                elif node["position"] == "right":
                    current_hash = hashlib.sha256((current_hash + node["hash"]).encode()).hexdigest()
                else:
                    raise ValueError("Invalid node position in proof")

            return current_hash == expected_root
        except Exception as e:
            print(f"Proof verification failed: {e}")
            return False

# Example usage
if __name__ == "__main__":
    proof = {
        "leaf": "abc123",
        "path": [
            {"position": "left", "hash": "def456"},
            {"position": "right", "hash": "789abc"}
        ]
    }
    expected_root = "some_expected_root_hash"

    is_valid = LightClientVerifier.verify_proof(proof, expected_root)
    print(f"Proof valid: {is_valid}")