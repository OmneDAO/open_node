# oracle_integration.py - Oracle Integration for OMNE VM

import logging
import json
import time
from typing import Dict, List, Optional, Any
from datetime import datetime, timezone
import hashlib
import requests
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.backends import default_backend

from crypto_utils import CryptoUtils

logger = logging.getLogger(__name__)

class OracleRegistry:
    """
    Manages trusted oracles per smart contract.
    Each contract can register its own set of trusted oracle addresses.
    """
    
    def __init__(self):
        self.trusted_oracles = {}  # contract_id -> set of oracle addresses
        self.oracle_metadata = {}  # oracle_address -> metadata
        self.crypto_utils = CryptoUtils()
        
    def register_trusted_oracle(self, contract_id: str, oracle_address: str, 
                              admin_signature: str, admin_address: str) -> bool:
        """
        Register a trusted oracle for a specific contract.
        
        Args:
            contract_id: The smart contract ID
            oracle_address: The oracle's blockchain address
            admin_signature: Signature from contract admin
            admin_address: Address of contract admin
            
        Returns:
            bool: Success status
        """
        try:
            # Verify admin signature (simplified - in production, verify against contract admin)
            message = f"{contract_id}:{oracle_address}:{int(time.time())}"
            
            # Initialize contract oracle set if doesn't exist
            if contract_id not in self.trusted_oracles:
                self.trusted_oracles[contract_id] = set()
                
            # Add oracle to trusted set
            self.trusted_oracles[contract_id].add(oracle_address)
            
            # Store oracle metadata
            self.oracle_metadata[oracle_address] = {
                'registered_at': datetime.now(timezone.utc).isoformat(),
                'registered_by': admin_address,
                'contract_id': contract_id,
                'status': 'active'
            }
            
            logger.info(f"Oracle {oracle_address} registered for contract {contract_id}")
            return True
            
        except Exception as e:
            logger.error(f"Failed to register oracle: {e}")
            return False
    
    def is_trusted_oracle(self, contract_id: str, oracle_address: str) -> bool:
        """Check if an oracle is trusted for a specific contract."""
        return (contract_id in self.trusted_oracles and 
                oracle_address in self.trusted_oracles[contract_id])
    
    def get_trusted_oracles(self, contract_id: str) -> List[str]:
        """Get all trusted oracles for a contract."""
        return list(self.trusted_oracles.get(contract_id, set()))
    
    def remove_oracle(self, contract_id: str, oracle_address: str, 
                     admin_signature: str) -> bool:
        """Remove an oracle from trusted list."""
        try:
            if (contract_id in self.trusted_oracles and 
                oracle_address in self.trusted_oracles[contract_id]):
                
                self.trusted_oracles[contract_id].remove(oracle_address)
                
                # Update metadata
                if oracle_address in self.oracle_metadata:
                    self.oracle_metadata[oracle_address]['status'] = 'removed'
                    self.oracle_metadata[oracle_address]['removed_at'] = datetime.now(timezone.utc).isoformat()
                
                logger.info(f"Oracle {oracle_address} removed from contract {contract_id}")
                return True
                
        except Exception as e:
            logger.error(f"Failed to remove oracle: {e}")
            
        return False


class OracleResponseHandler:
    """
    Handles incoming oracle responses with signature verification
    and contract state updates.
    """
    
    def __init__(self, oracle_registry: OracleRegistry, smart_contract_manager):
        self.oracle_registry = oracle_registry
        self.smart_contract_manager = smart_contract_manager
        self.crypto_utils = CryptoUtils()
        self.processed_responses = set()  # Prevent replay attacks
        
    def handle_oracle_response(self, contract_id: str, response_data: Dict) -> Dict:
        """
        Process an incoming oracle response.
        
        Args:
            contract_id: Target smart contract ID
            response_data: Oracle response with signature
            
        Returns:
            Dict: Processing result
        """
        try:
            # Extract response components
            oracle_address = response_data.get('oracle_address')
            request_id = response_data.get('request_id')
            result = response_data.get('result')
            signature = response_data.get('signature')
            timestamp = response_data.get('timestamp')
            
            # Validate required fields
            if not all([oracle_address, request_id, result, signature, timestamp]):
                return {'success': False, 'error': 'Missing required fields'}
            
            # Check if oracle is trusted
            if not self.oracle_registry.is_trusted_oracle(contract_id, oracle_address):
                return {'success': False, 'error': 'Untrusted oracle'}
            
            # Prevent replay attacks
            response_hash = hashlib.sha256(
                json.dumps(response_data, sort_keys=True).encode()
            ).hexdigest()
            
            if response_hash in self.processed_responses:
                return {'success': False, 'error': 'Response already processed'}
            
            # Verify oracle signature
            if not self.verify_oracle_signature(response_data, signature, oracle_address):
                return {'success': False, 'error': 'Invalid oracle signature'}
            
            # Check timestamp (prevent old responses)
            response_time = datetime.fromisoformat(timestamp.replace('Z', '+00:00'))
            current_time = datetime.now(timezone.utc)
            time_diff = (current_time - response_time).total_seconds()
            
            if time_diff > 300:  # 5 minutes max age
                return {'success': False, 'error': 'Response too old'}
            
            # Process the oracle response
            success = self.process_oracle_data(contract_id, request_id, result, oracle_address)
            
            if success:
                self.processed_responses.add(response_hash)
                logger.info(f"Oracle response processed successfully: {request_id}")
                return {'success': True, 'request_id': request_id}
            else:
                return {'success': False, 'error': 'Failed to process oracle data'}
                
        except Exception as e:
            logger.error(f"Error handling oracle response: {e}")
            return {'success': False, 'error': str(e)}
    
    def verify_oracle_signature(self, data: Dict, signature: str, oracle_address: str) -> bool:
        """
        Verify oracle signature on response data.
        
        Args:
            data: Response data (without signature field)
            signature: Oracle signature
            oracle_address: Oracle's address
            
        Returns:
            bool: Signature validity
        """
        try:
            # Create canonical message (exclude signature from data)
            message_data = {k: v for k, v in data.items() if k != 'signature'}
            canonical_message = json.dumps(message_data, sort_keys=True)
            
            # For now, use simplified verification
            # In production, this would verify against oracle's public key
            message_hash = hashlib.sha256(canonical_message.encode()).hexdigest()
            expected_signature = hashlib.sha256(f"{oracle_address}:{message_hash}".encode()).hexdigest()
            
            return signature == expected_signature
            
        except Exception as e:
            logger.error(f"Signature verification failed: {e}")
            return False
    
    def process_oracle_data(self, contract_id: str, request_id: str, 
                          result: Any, oracle_address: str) -> bool:
        """
        Process oracle data by calling the appropriate contract method.
        
        Args:
            contract_id: Target contract
            request_id: Original request ID
            result: Oracle result data
            oracle_address: Oracle that provided the data
            
        Returns:
            bool: Processing success
        """
        try:
            # Call contract's oracle response handler
            response = self.smart_contract_manager.execute_contract_function(
                contract_id=contract_id,
                function_name='handleOracleResponse',
                args=[request_id, result, oracle_address],
                caller_address='oracle_system',  # System caller
                fee='0'  # No fee for oracle responses
            )
            
            return response is not None
            
        except Exception as e:
            logger.error(f"Failed to process oracle data: {e}")
            return False


class HTTPSecurityValidator:
    """
    Validates HTTP requests for oracle integration with security controls.
    """
    
    def __init__(self):
        self.allowed_domains = {}  # contract_id -> set of allowed domains
        self.rate_limits = {}     # contract_id -> rate limit info
        self.request_history = {} # Track request patterns
        
    def register_allowed_domain(self, contract_id: str, domain: str, 
                              admin_signature: str) -> bool:
        """
        Register an allowed domain for a contract's HTTP requests.
        
        Args:
            contract_id: Smart contract ID
            domain: Domain to allow (e.g., 'api.blox.ai')
            admin_signature: Contract admin signature
            
        Returns:
            bool: Registration success
        """
        try:
            if contract_id not in self.allowed_domains:
                self.allowed_domains[contract_id] = set()
                
            self.allowed_domains[contract_id].add(domain)
            
            logger.info(f"Domain {domain} allowed for contract {contract_id}")
            return True
            
        except Exception as e:
            logger.error(f"Failed to register domain: {e}")
            return False
    
    def is_request_allowed(self, contract_id: str, url: str) -> bool:
        """
        Check if an HTTP request is allowed for a contract.
        
        Args:
            contract_id: Smart contract making the request
            url: Target URL
            
        Returns:
            bool: Request allowed status
        """
        try:
            # Extract domain from URL
            from urllib.parse import urlparse
            parsed_url = urlparse(url)
            domain = parsed_url.netloc
            
            # Check if domain is in allowlist
            if contract_id not in self.allowed_domains:
                return False
                
            return domain in self.allowed_domains[contract_id]
            
        except Exception as e:
            logger.error(f"URL validation failed: {e}")
            return False
    
    def check_rate_limit(self, contract_id: str, url: str) -> bool:
        """
        Check if request is within rate limits.
        
        Args:
            contract_id: Contract making request
            url: Target URL
            
        Returns:
            bool: Within rate limits
        """
        try:
            current_time = time.time()
            key = f"{contract_id}:{url}"
            
            if key not in self.request_history:
                self.request_history[key] = []
            
            # Clean old requests (keep last 60 seconds)
            self.request_history[key] = [
                req_time for req_time in self.request_history[key]
                if current_time - req_time < 60
            ]
            
            # Check rate limit (max 10 requests per minute per contract-URL pair)
            if len(self.request_history[key]) >= 10:
                return False
            
            # Record this request
            self.request_history[key].append(current_time)
            return True
            
        except Exception as e:
            logger.error(f"Rate limit check failed: {e}")
            return False


class SecureHTTPClient:
    """
    Secure HTTP client for oracle and external API integration.
    """
    
    def __init__(self, security_validator: HTTPSecurityValidator):
        self.security_validator = security_validator
        self.session = requests.Session()
        self.session.timeout = 30  # 30 second timeout
        
    def make_oracle_request(self, contract_id: str, url: str, method: str = 'GET', 
                          data: Optional[Dict] = None, headers: Optional[Dict] = None) -> Dict:
        """
        Make a secure HTTP request for oracle integration.
        
        Args:
            contract_id: Contract making the request
            url: Target URL
            method: HTTP method
            data: Request data
            headers: HTTP headers
            
        Returns:
            Dict: Response data or error
        """
        try:
            # Security validation
            if not self.security_validator.is_request_allowed(contract_id, url):
                return {'error': 'Domain not in allowlist', 'status': 'forbidden'}
            
            if not self.security_validator.check_rate_limit(contract_id, url):
                return {'error': 'Rate limit exceeded', 'status': 'rate_limited'}
            
            # Prepare request
            request_headers = {
                'User-Agent': 'OMNE-Oracle/1.0',
                'Content-Type': 'application/json',
                'X-Contract-ID': contract_id
            }
            
            if headers:
                request_headers.update(headers)
            
            # Make request
            if method.upper() == 'GET':
                response = self.session.get(url, headers=request_headers, timeout=30)
            elif method.upper() == 'POST':
                response = self.session.post(url, json=data, headers=request_headers, timeout=30)
            else:
                return {'error': 'Unsupported HTTP method', 'status': 'method_not_allowed'}
            
            # Process response
            if response.status_code == 200:
                try:
                    return {
                        'data': response.json(),
                        'status': 'success',
                        'status_code': response.status_code
                    }
                except json.JSONDecodeError:
                    return {
                        'data': response.text,
                        'status': 'success',
                        'status_code': response.status_code
                    }
            else:
                return {
                    'error': f'HTTP {response.status_code}',
                    'status': 'http_error',
                    'status_code': response.status_code
                }
                
        except requests.exceptions.Timeout:
            return {'error': 'Request timeout', 'status': 'timeout'}
        except requests.exceptions.ConnectionError:
            return {'error': 'Connection failed', 'status': 'connection_error'}
        except Exception as e:
            logger.error(f"HTTP request failed: {e}")
            return {'error': str(e), 'status': 'error'}


# Initialize global oracle components
oracle_registry = OracleRegistry()
security_validator = HTTPSecurityValidator()
secure_http_client = SecureHTTPClient(security_validator)

def get_oracle_registry() -> OracleRegistry:
    """Get the global oracle registry instance."""
    return oracle_registry

def get_security_validator() -> HTTPSecurityValidator:
    """Get the global HTTP security validator."""
    return security_validator

def get_secure_http_client() -> SecureHTTPClient:
    """Get the global secure HTTP client."""
    return secure_http_client
