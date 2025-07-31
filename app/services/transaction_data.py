from typing import Dict, Any, Callable
from datetime import datetime, timezone
import re
import logging

class TransactionDataService:
    @staticmethod
    def create_transaction_data(data: Dict[str, Any] = None) -> Dict[str, Any]:
        """
        Creates a transaction data object with any custom fields.
        
        Args:
            data: Optional custom data to include
            
        Returns:
            Dict[str, Any]: The transaction data
        """
        base_data = {
            '_version': '1.0',
            '_timestamp': datetime.now(timezone.utc).isoformat()
        }
        if data:
            base_data.update(data)
        return base_data

    @staticmethod
    def search_transaction_data(
        transaction: Dict[str, Any],
        search_criteria: Dict[str, Any]
    ) -> bool:
        """
        Searches transaction data for specific values.
        
        Args:
            transaction: The transaction to search
            search_criteria: Key-value pairs to search for
            
        Returns:
            bool: True if all criteria match, False otherwise
        """
        return all(
            TransactionDataService._match_criteria(
                transaction['data'].get(key),
                value
            )
            for key, value in search_criteria.items()
        )

    @staticmethod
    def _match_criteria(data_value: Any, search_value: Any) -> bool:
        """
        Matches a data value against a search criterion.
        
        Args:
            data_value: The value from the transaction data
            search_value: The value to search for
            
        Returns:
            bool: True if the values match, False otherwise
        """
        if isinstance(search_value, re.Pattern):
            return bool(search_value.search(str(data_value)))
        return data_value == search_value

    @staticmethod
    def iterate_transaction_data(
        transaction: Dict[str, Any],
        callback: Callable[[str, Any], None]
    ) -> None:
        """
        Iterates over transaction data fields.
        
        Args:
            transaction: The transaction to iterate
            callback: Function to call for each data field
        """
        for key, value in transaction['data'].items():
            callback(key, value) 