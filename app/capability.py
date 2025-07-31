import secrets
from typing import Dict, Any

class Capability:
    """
    Represents an explicit permission or capability that can be passed between objects.
    """

    def __init__(self, name: str, attributes: Dict[str, Any] = None):
        """
        Initialize a capability with a name and optional attributes.

        Args:
            name: The name of the capability (e.g., "allow_transfer").
            attributes: Additional attributes associated with the capability.
        """
        self.name = name
        self.attributes = attributes or {}
        self.token = secrets.token_hex(32)  # Generate a 256-bit unforgeable token

    def validate(self, required_name: str, required_attributes: Dict[str, Any] = None) -> bool:
        """
        Validate the capability against required attributes.

        Args:
            required_name: The required name of the capability.
            required_attributes: The required attributes to match.

        Returns:
            bool: True if the capability is valid, False otherwise.
        """
        if self.name != required_name:
            return False

        if required_attributes:
            for key, value in required_attributes.items():
                if self.attributes.get(key) != value:
                    return False

        return True

# Example usage
if __name__ == "__main__":
    cap = Capability("allow_transfer", {"max_amount": 100})
    print("Capability token:", cap.token)
    print("Validation result:", cap.validate("allow_transfer", {"max_amount": 100}))