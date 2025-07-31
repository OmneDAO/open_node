# canonicalization.py
import json
from typing import Dict, Any

def canonicalize_transaction(transaction: Dict[str, Any]) -> str:
    """
    Converts a transaction into a canonical JSON string.
    All values (including nested ones) are converted to strings and keys are sorted.
    This ensures that signing and verification use the exact same payload.
    """
    # Define the keys we want to include – include "data" as a key.
    canonical_keys = [
        "sender", "type", "nonce", "timestamp",
        "fee", "public_key", "confirmations", "data"
    ]
    if "amount" in transaction:
        canonical_keys.append("amount")
    elif "balance" in transaction:
        canonical_keys.append("balance")
    
    # Build a new dictionary using only the canonical keys.
    canonical_data = {}
    for key in sorted(set(canonical_keys)):
        if key not in transaction:
            continue
        if key == "data":
            # Recursively process nested data
            canonical_data["data"] = _canonicalize_nested(transaction["data"])
        else:
            # Convert scalar values to strings
            canonical_data[key] = str(transaction[key])
    
    # Return the compact JSON representation.
    return json.dumps(canonical_data, sort_keys=True, separators=(',', ':'))

def _canonicalize_nested(obj: Any) -> Any:
    """
    Recursively converts all scalar values to strings in nested dictionaries/lists.
    """
    if isinstance(obj, dict):
        return {k: _canonicalize_nested(obj[k]) for k in sorted(obj.keys())}
    elif isinstance(obj, list):
        return [_canonicalize_nested(item) for item in obj]
    else:
        return str(obj)
