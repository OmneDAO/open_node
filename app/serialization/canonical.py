from typing import Any, Dict, Union
import json
from decimal import Decimal
from datetime import datetime

class CanonicalSerializer:
    @staticmethod
    def serialize(transaction: Dict[str, Any]) -> str:
        """
        Serialize a transaction to canonical JSON format.
        
        Args:
            transaction: The transaction to serialize
            
        Returns:
            str: The canonical JSON string
        """
        tx_copy = dict(transaction)
        tx_copy.pop('signature', None)
        tx_copy.pop('hash', None)
        return CanonicalSerializer._to_canonical_json(tx_copy)

    @staticmethod
    def _to_canonical_json(obj: Any) -> str:
        """
        Convert an object to canonical JSON string.
        
        Args:
            obj: The object to convert
            
        Returns:
            str: The canonical JSON string
        """
        if obj is None or not isinstance(obj, (dict, list)):
            if isinstance(obj, Decimal):
                return format(obj, 'f')
            if isinstance(obj, datetime):
                return obj.isoformat()
            return json.dumps(obj)

        if isinstance(obj, list):
            elements = [CanonicalSerializer._to_canonical_json(el) for el in obj]
            return f"[{','.join(elements)}]"

        # Handle nested objects and arrays in transaction data
        entries = []
        for key in sorted(obj.keys()):
            val = obj[key]
            if key == 'data' and isinstance(val, dict):
                # Special handling for transaction data
                entries.append(f"{json.dumps(key)}:{CanonicalSerializer._to_canonical_json(val)}")
            else:
                entries.append(f"{json.dumps(key)}:{CanonicalSerializer._to_canonical_json(val)}")
        return f"{{{','.join(entries)}}}" 