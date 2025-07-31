"""
Error Handling and Validation System for Open Omne Node
Provides comprehensive error handling, validation, and graceful degradation.
"""

import logging
import traceback
import time
from typing import Any, Dict, List, Optional, Callable, Union, Type
from decimal import Decimal, InvalidOperation
from functools import wraps
from enum import Enum


class ErrorSeverity(Enum):
    """Error severity levels"""
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class OpenNodeError(Exception):
    """Base exception for Open Omne Node errors"""
    
    def __init__(self, message: str, severity: ErrorSeverity = ErrorSeverity.MEDIUM, 
                 error_code: Optional[str] = None, context: Optional[Dict] = None):
        super().__init__(message)
        self.message = message
        self.severity = severity
        self.error_code = error_code or self.__class__.__name__
        self.context = context or {}
        self.timestamp = time.time()


class ConfigurationError(OpenNodeError):
    """Configuration-related errors"""
    pass


class NetworkError(OpenNodeError):
    """Network communication errors"""
    pass


class ConsensusError(OpenNodeError):
    """Consensus mechanism errors"""
    pass


class TransactionError(OpenNodeError):
    """Transaction processing errors"""
    pass


class ValidationError(OpenNodeError):
    """Data validation errors"""
    pass


class StorageError(OpenNodeError):
    """Storage backend errors"""
    pass


class StakingError(OpenNodeError):
    """Staking-related errors"""
    pass


class NodeInitializationError(OpenNodeError):
    """Node initialization errors"""
    pass


class ErrorHandler:
    """Centralized error handling and logging for Open Omne Node"""
    
    def __init__(self, logger: Optional[logging.Logger] = None):
        self.logger = logger or logging.getLogger(__name__)
        self.error_count = {}
        self.error_history = []
        self.max_history_size = 1000
    
    def handle_error(self, error: Exception, context: Optional[Dict] = None, 
                    reraise: bool = False) -> Optional[Dict]:
        """Handle an error with appropriate logging and context"""
        
        # Create error info with context
        if isinstance(error, OpenNodeError):
            context = context or error.context or {}
        else:
            context = context or {}
            
        error_info = {
            'type': type(error).__name__,
            'message': str(error),
            'context': context,
            'timestamp': time.time(),
            'traceback': traceback.format_exc()
        }
        
        # Add to error history
        self.error_history.append(error_info)
        if len(self.error_history) > self.max_history_size:
            self.error_history.pop(0)
        
        # Count error types
        error_type = type(error).__name__
        self.error_count[error_type] = self.error_count.get(error_type, 0) + 1
        
        # Determine severity and log appropriately
        if isinstance(error, OpenNodeError):
            severity = error.severity
            error_code = error.error_code
        else:
            severity = ErrorSeverity.MEDIUM
            error_code = error_type
        
        # Log based on severity
        if severity == ErrorSeverity.CRITICAL:
            self.logger.critical(f"CRITICAL ERROR [{error_code}]: {error.message if isinstance(error, OpenNodeError) else str(error)}", 
                               extra={'context': context, 'error_info': error_info})
        elif severity == ErrorSeverity.HIGH:
            self.logger.error(f"HIGH ERROR [{error_code}]: {error.message if isinstance(error, OpenNodeError) else str(error)}", 
                            extra={'context': context, 'error_info': error_info})
        elif severity == ErrorSeverity.MEDIUM:
            self.logger.warning(f"MEDIUM ERROR [{error_code}]: {error.message if isinstance(error, OpenNodeError) else str(error)}", 
                              extra={'context': context, 'error_info': error_info})
        else:
            self.logger.info(f"LOW ERROR [{error_code}]: {error.message if isinstance(error, OpenNodeError) else str(error)}", 
                           extra={'context': context, 'error_info': error_info})
        
        if reraise:
            raise error
        
        return error_info
    
    def get_error_summary(self) -> Dict:
        """Get summary of errors encountered"""
        return {
            'total_errors': len(self.error_history),
            'error_counts': self.error_count.copy(),
            'recent_errors': self.error_history[-10:] if self.error_history else []
        }


class Validator:
    """Data validation utilities for Open Omne Node"""
    
    @staticmethod
    def validate_address(address: str) -> bool:
        """Validate an Omne address format (0z followed by 40 hex chars)"""
        if not isinstance(address, str):
            return False
        
        address = address.strip()
        return (len(address) == 42 and 
                address.startswith('0z') and
                all(c in '0123456789abcdefABCDEF' for c in address[2:]))
    
    @staticmethod
    def validate_hash(hash_value: str, expected_length: int = 64) -> bool:
        """Validate a hash format"""
        if not isinstance(hash_value, str):
            return False
        
        return len(hash_value) == expected_length and all(c in '0123456789abcdef' for c in hash_value.lower())
    
    @staticmethod
    def validate_amount(amount: Union[str, Decimal, int, float]) -> Optional[Decimal]:
        """Validate and convert amount to Decimal"""
        try:
            if isinstance(amount, str):
                amount = amount.strip()
            
            decimal_amount = Decimal(str(amount))
            
            if decimal_amount < 0:
                raise ValidationError("Amount cannot be negative")
            
            return decimal_amount
        except (InvalidOperation, ValueError) as e:
            raise ValidationError(f"Invalid amount format: {amount}")
    
    @staticmethod
    def validate_timestamp(timestamp: Union[int, float]) -> bool:
        """Validate timestamp"""
        try:
            timestamp = float(timestamp)
            # Check if timestamp is reasonable (between 2020 and 2050)
            return 1577836800 <= timestamp <= 2524608000  # 2020-01-01 to 2050-01-01
        except (ValueError, TypeError):
            return False
    
    @staticmethod
    def validate_steward_address(steward_address: str) -> bool:
        """Validate steward address specifically for open nodes"""
        if not steward_address:
            return False
        
        return Validator.validate_address(steward_address)
    
    @staticmethod
    def validate_node_id(node_id: str) -> bool:
        """Validate node ID format"""
        if not isinstance(node_id, str):
            return False
        
        # Node ID should be a base64-like string of reasonable length
        return 6 <= len(node_id) <= 32 and node_id.replace('=', '').isalnum()
    
    @staticmethod
    def validate_transaction_fields(transaction: Dict) -> List[str]:
        """Validate transaction fields and return list of missing/invalid fields"""
        required_fields = ['hash', 'timestamp', 'sender', 'fee', 'signature', 'public_key']
        errors = []
        
        for field in required_fields:
            if field not in transaction:
                errors.append(f"Missing required field: {field}")
            elif transaction[field] is None:
                errors.append(f"Field cannot be null: {field}")
            elif isinstance(transaction[field], str) and not transaction[field].strip():
                errors.append(f"Field cannot be empty: {field}")
        
        # Validate specific fields
        if 'hash' in transaction and not Validator.validate_hash(transaction['hash']):
            errors.append("Invalid hash format")
        
        if 'sender' in transaction and not Validator.validate_address(transaction['sender']):
            errors.append("Invalid sender address format")
        
        if 'timestamp' in transaction and not Validator.validate_timestamp(transaction['timestamp']):
            errors.append("Invalid timestamp")
        
        if 'fee' in transaction:
            try:
                fee = Validator.validate_amount(transaction['fee'])
                if fee <= 0:
                    errors.append("Fee must be positive")
            except ValidationError:
                errors.append("Invalid fee format")
        
        return errors
    
    @staticmethod
    def validate_block_fields(block: Dict) -> List[str]:
        """Validate block fields and return list of missing/invalid fields"""
        required_fields = ['hash', 'previous_hash', 'timestamp', 'transactions', 'nonce']
        errors = []
        
        for field in required_fields:
            if field not in block:
                errors.append(f"Missing required field: {field}")
        
        # Validate specific fields
        if 'hash' in block and not Validator.validate_hash(block['hash']):
            errors.append("Invalid block hash format")
        
        if 'previous_hash' in block and not Validator.validate_hash(block['previous_hash']):
            errors.append("Invalid previous hash format")
        
        if 'timestamp' in block and not Validator.validate_timestamp(block['timestamp']):
            errors.append("Invalid block timestamp")
        
        if 'transactions' in block and not isinstance(block['transactions'], list):
            errors.append("Transactions must be a list")
        
        return errors
    
    @staticmethod
    def validate_staking_agreement(agreement: Dict) -> List[str]:
        """Validate staking agreement fields"""
        required_fields = ['staker_address', 'stake_amount', 'node_address', 'min_term_days']
        errors = []
        
        for field in required_fields:
            if field not in agreement:
                errors.append(f"Missing required field: {field}")
        
        # Validate specific fields
        if 'staker_address' in agreement and not Validator.validate_address(agreement['staker_address']):
            errors.append("Invalid staker address format")
        
        if 'node_address' in agreement and not Validator.validate_address(agreement['node_address']):
            errors.append("Invalid node address format")
        
        if 'stake_amount' in agreement:
            try:
                amount = Validator.validate_amount(agreement['stake_amount'])
                if amount <= 0:
                    errors.append("Stake amount must be positive")
            except ValidationError:
                errors.append("Invalid stake amount format")
        
        if 'min_term_days' in agreement:
            try:
                term = int(agreement['min_term_days'])
                if term <= 0:
                    errors.append("Minimum term must be positive")
            except (ValueError, TypeError):
                errors.append("Invalid minimum term format")
        
        return errors


def with_error_handling(reraise: bool = False, default_return: Any = None):
    """Decorator for automatic error handling"""
    def decorator(func: Callable):
        @wraps(func)
        def wrapper(*args, **kwargs):
            try:
                return func(*args, **kwargs)
            except Exception as e:
                # Try to get error handler from the first argument (usually self)
                error_handler = None
                if args and hasattr(args[0], 'error_handler'):
                    error_handler = args[0].error_handler
                elif args and hasattr(args[0], '_error_handler'):
                    error_handler = args[0]._error_handler
                
                if error_handler:
                    error_handler.handle_error(e, {
                        'function': func.__name__,
                        'args': str(args)[1:] if args else '',  # Skip self
                        'kwargs': str(kwargs)
                    }, reraise=reraise)
                else:
                    logging.error(f"Error in {func.__name__}: {e}")
                    if reraise:
                        raise
                
                return default_return
        return wrapper
    return decorator


def retry_on_error(max_retries: int = 3, delay: float = 1.0, backoff: float = 2.0):
    """Decorator for retrying operations on specific errors"""
    def decorator(func: Callable):
        @wraps(func)
        def wrapper(*args, **kwargs):
            last_exception = None
            current_delay = delay
            
            for attempt in range(max_retries + 1):
                try:
                    return func(*args, **kwargs)
                except (NetworkError, StorageError) as e:
                    last_exception = e
                    if attempt < max_retries:
                        logging.warning(f"Attempt {attempt + 1} failed for {func.__name__}: {e}. Retrying in {current_delay}s...")
                        time.sleep(current_delay)
                        current_delay *= backoff
                    else:
                        logging.error(f"All {max_retries + 1} attempts failed for {func.__name__}")
                        raise
                except Exception as e:
                    # Don't retry on non-retryable errors
                    raise
            
            # This should never be reached, but just in case
            raise last_exception
        return wrapper
    return decorator
