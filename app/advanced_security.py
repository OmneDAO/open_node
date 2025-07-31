"""
Advanced Security System for Open Omne Node
Provides enhanced security features including key management, rotation, and monitoring.
"""

import os
import json
import logging
import hashlib
import secrets
import time
from typing import Dict, List, Optional, Any, Tuple
from datetime import datetime, timedelta
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import ec, rsa, padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import base64
import threading

from error_handling import OpenNodeError, ErrorSeverity


class SecurityError(OpenNodeError):
    """Security-related errors"""
    pass


class KeyManager:
    """Advanced key management system"""
    
    def __init__(self, data_directory: str = "./data/security"):
        self.data_directory = data_directory
        self.logger = logging.getLogger(__name__)
        self._keys = {}
        self._key_metadata = {}
        self._lock = threading.RLock()
        
        # Ensure security directory exists
        os.makedirs(self.data_directory, exist_ok=True)
    
    def generate_ec_key_pair(self, key_name: str, curve=ec.SECP256K1()) -> Tuple[str, str]:
        """Generate a new EC key pair"""
        try:
            with self._lock:
                # Generate private key
                private_key = ec.generate_private_key(curve, default_backend())
                public_key = private_key.public_key()
                
                # Serialize keys
                private_pem = private_key.private_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PrivateFormat.PKCS8,
                    encryption_algorithm=serialization.NoEncryption()
                ).decode('utf-8')
                
                public_pem = public_key.public_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PublicFormat.SubjectPublicKeyInfo
                ).decode('utf-8')
                
                # Store keys
                self._store_key_pair(key_name, private_pem, public_pem, 'ec')
                
                self.logger.info(f"Generated EC key pair: {key_name}")
                return private_pem, public_pem
                
        except Exception as e:
            raise SecurityError(f"Failed to generate EC key pair '{key_name}': {e}", 
                              severity=ErrorSeverity.HIGH)
    
    def generate_rsa_key_pair(self, key_name: str, key_size: int = 2048) -> Tuple[str, str]:
        """Generate a new RSA key pair"""
        try:
            with self._lock:
                # Generate private key
                private_key = rsa.generate_private_key(
                    public_exponent=65537,
                    key_size=key_size,
                    backend=default_backend()
                )
                public_key = private_key.public_key()
                
                # Serialize keys
                private_pem = private_key.private_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PrivateFormat.PKCS8,
                    encryption_algorithm=serialization.NoEncryption()
                ).decode('utf-8')
                
                public_pem = public_key.public_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PublicFormat.SubjectPublicKeyInfo
                ).decode('utf-8')
                
                # Store keys
                self._store_key_pair(key_name, private_pem, public_pem, 'rsa')
                
                self.logger.info(f"Generated RSA key pair: {key_name}")
                return private_pem, public_pem
                
        except Exception as e:
            raise SecurityError(f"Failed to generate RSA key pair '{key_name}': {e}", 
                              severity=ErrorSeverity.HIGH)
    
    def _store_key_pair(self, key_name: str, private_key: str, public_key: str, key_type: str):
        """Store key pair with metadata"""
        metadata = {
            'key_name': key_name,
            'key_type': key_type,
            'created_at': time.time(),
            'last_rotated': time.time(),
            'rotation_count': 0,
            'status': 'active'
        }
        
        # Store in memory
        self._keys[key_name] = {
            'private_key': private_key,
            'public_key': public_key
        }
        self._key_metadata[key_name] = metadata
        
        # Store to disk (encrypted)
        key_file = os.path.join(self.data_directory, f"{key_name}_keys.json")
        metadata_file = os.path.join(self.data_directory, f"{key_name}_metadata.json")
        
        # Encrypt keys before storing
        encrypted_data = self._encrypt_key_data({
            'private_key': private_key,
            'public_key': public_key
        })
        
        with open(key_file, 'w') as f:
            json.dump(encrypted_data, f)
        
        with open(metadata_file, 'w') as f:
            json.dump(metadata, f)
    
    def load_key_pair(self, key_name: str) -> Optional[Tuple[str, str]]:
        """Load key pair from storage"""
        try:
            with self._lock:
                # Check memory first
                if key_name in self._keys:
                    key_data = self._keys[key_name]
                    return key_data['private_key'], key_data['public_key']
                
                # Load from disk
                key_file = os.path.join(self.data_directory, f"{key_name}_keys.json")
                metadata_file = os.path.join(self.data_directory, f"{key_name}_metadata.json")
                
                if not os.path.exists(key_file) or not os.path.exists(metadata_file):
                    return None
                
                # Load encrypted keys
                with open(key_file, 'r') as f:
                    encrypted_data = json.load(f)
                
                with open(metadata_file, 'r') as f:
                    metadata = json.load(f)
                
                # Decrypt keys
                key_data = self._decrypt_key_data(encrypted_data)
                
                # Store in memory
                self._keys[key_name] = key_data
                self._key_metadata[key_name] = metadata
                
                return key_data['private_key'], key_data['public_key']
                
        except Exception as e:
            self.logger.error(f"Failed to load key pair '{key_name}': {e}")
            return None
    
    def rotate_key(self, key_name: str) -> bool:
        """Rotate an existing key"""
        try:
            with self._lock:
                # Check if key exists
                if key_name not in self._key_metadata:
                    if not self.load_key_pair(key_name):
                        raise SecurityError(f"Key '{key_name}' not found", 
                                          severity=ErrorSeverity.MEDIUM)
                
                metadata = self._key_metadata[key_name]
                key_type = metadata['key_type']
                
                # Generate new key pair
                if key_type == 'ec':
                    private_key, public_key = self.generate_ec_key_pair(f"{key_name}_new")
                elif key_type == 'rsa':
                    private_key, public_key = self.generate_rsa_key_pair(f"{key_name}_new")
                else:
                    raise SecurityError(f"Unknown key type: {key_type}", 
                                      severity=ErrorSeverity.MEDIUM)
                
                # Update metadata
                metadata['last_rotated'] = time.time()
                metadata['rotation_count'] += 1
                
                # Replace old key with new key
                self._keys[key_name] = {
                    'private_key': private_key,
                    'public_key': public_key
                }
                self._key_metadata[key_name] = metadata
                
                # Remove temporary key
                if f"{key_name}_new" in self._keys:
                    del self._keys[f"{key_name}_new"]
                if f"{key_name}_new" in self._key_metadata:
                    del self._key_metadata[f"{key_name}_new"]
                
                # Save to disk
                self._store_key_pair(key_name, private_key, public_key, key_type)
                
                self.logger.info(f"Rotated key: {key_name}")
                return True
                
        except Exception as e:
            raise SecurityError(f"Failed to rotate key '{key_name}': {e}", 
                              severity=ErrorSeverity.HIGH)
    
    def _encrypt_key_data(self, data: Dict[str, str]) -> Dict[str, str]:
        """Encrypt key data for storage"""
        try:
            # Generate random key and IV
            key = secrets.token_bytes(32)  # 256-bit key
            iv = secrets.token_bytes(16)   # 128-bit IV
            
            # Encrypt data
            cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
            encryptor = cipher.encryptor()
            
            # Serialize and pad data
            json_data = json.dumps(data).encode('utf-8')
            padding_length = 16 - (len(json_data) % 16)
            padded_data = json_data + bytes([padding_length]) * padding_length
            
            encrypted_data = encryptor.update(padded_data) + encryptor.finalize()
            
            # Store key securely (in production, use HSM or secure key store)
            key_hash = hashlib.sha256(key).hexdigest()
            
            return {
                'encrypted_data': base64.b64encode(encrypted_data).decode('utf-8'),
                'iv': base64.b64encode(iv).decode('utf-8'),
                'key_hash': key_hash,
                'encryption_method': 'AES-256-CBC'
            }
            
        except Exception as e:
            raise SecurityError(f"Failed to encrypt key data: {e}", 
                              severity=ErrorSeverity.CRITICAL)
    
    def _decrypt_key_data(self, encrypted_data: Dict[str, str]) -> Dict[str, str]:
        """Decrypt key data from storage"""
        try:
            # For this implementation, we'll use a simple key derivation
            # In production, retrieve key from HSM or secure key store
            
            # This is a simplified implementation - in production use proper key management
            derived_key = hashlib.sha256(b"omne_node_encryption_key").digest()
            
            iv = base64.b64decode(encrypted_data['iv'])
            data = base64.b64decode(encrypted_data['encrypted_data'])
            
            # Decrypt data
            cipher = Cipher(algorithms.AES(derived_key), modes.CBC(iv), backend=default_backend())
            decryptor = cipher.decryptor()
            
            decrypted_padded = decryptor.update(data) + decryptor.finalize()
            
            # Remove padding
            padding_length = decrypted_padded[-1]
            decrypted_data = decrypted_padded[:-padding_length]
            
            return json.loads(decrypted_data.decode('utf-8'))
            
        except Exception as e:
            raise SecurityError(f"Failed to decrypt key data: {e}", 
                              severity=ErrorSeverity.CRITICAL)
    
    def list_keys(self) -> List[Dict[str, Any]]:
        """List all managed keys"""
        with self._lock:
            keys_info = []
            for key_name, metadata in self._key_metadata.items():
                keys_info.append({
                    'key_name': key_name,
                    'key_type': metadata['key_type'],
                    'created_at': metadata['created_at'],
                    'last_rotated': metadata['last_rotated'],
                    'rotation_count': metadata['rotation_count'],
                    'status': metadata['status']
                })
            return keys_info


class SecurityMonitor:
    """Security monitoring and alerting system"""
    
    def __init__(self):
        self.logger = logging.getLogger(__name__)
        self._security_events = []
        self._failed_attempts = {}
        self._lock = threading.RLock()
        self.max_failed_attempts = 5
        self.lockout_duration = 300  # 5 minutes
    
    def log_security_event(self, event_type: str, details: Dict[str, Any], severity: str = 'info'):
        """Log a security event"""
        with self._lock:
            event = {
                'timestamp': time.time(),
                'event_type': event_type,
                'details': details,
                'severity': severity
            }
            self._security_events.append(event)
            
            # Log based on severity
            log_message = f"Security Event [{event_type}]: {details}"
            if severity == 'critical':
                self.logger.critical(log_message)
            elif severity == 'warning':
                self.logger.warning(log_message)
            else:
                self.logger.info(log_message)
    
    def record_failed_attempt(self, identifier: str, attempt_type: str):
        """Record a failed authentication/authorization attempt"""
        with self._lock:
            current_time = time.time()
            
            if identifier not in self._failed_attempts:
                self._failed_attempts[identifier] = {
                    'count': 0,
                    'first_attempt': current_time,
                    'last_attempt': current_time,
                    'locked_until': None
                }
            
            attempts = self._failed_attempts[identifier]
            attempts['count'] += 1
            attempts['last_attempt'] = current_time
            
            # Check if should be locked out
            if attempts['count'] >= self.max_failed_attempts:
                attempts['locked_until'] = current_time + self.lockout_duration
                
                self.log_security_event(
                    'account_lockout',
                    {
                        'identifier': identifier,
                        'attempt_type': attempt_type,
                        'failed_attempts': attempts['count'],
                        'locked_until': attempts['locked_until']
                    },
                    'warning'
                )
    
    def is_locked_out(self, identifier: str) -> bool:
        """Check if an identifier is currently locked out"""
        with self._lock:
            if identifier not in self._failed_attempts:
                return False
            
            attempts = self._failed_attempts[identifier]
            if attempts['locked_until'] is None:
                return False
            
            if time.time() < attempts['locked_until']:
                return True
            
            # Lockout expired, reset
            del self._failed_attempts[identifier]
            return False
    
    def clear_failed_attempts(self, identifier: str):
        """Clear failed attempts for an identifier"""
        with self._lock:
            if identifier in self._failed_attempts:
                del self._failed_attempts[identifier]
    
    def get_security_summary(self) -> Dict[str, Any]:
        """Get security monitoring summary"""
        with self._lock:
            recent_events = [e for e in self._security_events if e['timestamp'] > time.time() - 3600]  # Last hour
            
            return {
                'total_events': len(self._security_events),
                'recent_events': len(recent_events),
                'critical_events': len([e for e in recent_events if e['severity'] == 'critical']),
                'warning_events': len([e for e in recent_events if e['severity'] == 'warning']),
                'locked_accounts': len([k for k, v in self._failed_attempts.items() 
                                      if v['locked_until'] and time.time() < v['locked_until']]),
                'recent_failed_attempts': sum(v['count'] for v in self._failed_attempts.values()),
                'last_event': self._security_events[-1] if self._security_events else None
            }


class SecurityManager:
    """Main security management system"""
    
    def __init__(self, data_directory: str = "./data/security"):
        self.data_directory = data_directory
        self.key_manager = KeyManager(data_directory)
        self.security_monitor = SecurityMonitor()
        self.logger = logging.getLogger(__name__)
        
        # Security configuration
        self.config = {
            'key_rotation_interval': 30 * 24 * 3600,  # 30 days
            'security_audit_interval': 24 * 3600,     # 24 hours
            'enable_security_monitoring': True,
            'require_key_rotation': True
        }
    
    def initialize(self):
        """Initialize security system"""
        try:
            # Ensure security directory exists
            os.makedirs(self.data_directory, exist_ok=True)
            
            # Load existing keys
            self._load_existing_keys()
            
            # Start security monitoring
            if self.config['enable_security_monitoring']:
                self._start_security_monitoring()
            
            self.logger.info("Security system initialized")
            return True
            
        except Exception as e:
            raise SecurityError(f"Failed to initialize security system: {e}", 
                              severity=ErrorSeverity.CRITICAL)
    
    def _load_existing_keys(self):
        """Load existing keys from storage"""
        try:
            for filename in os.listdir(self.data_directory):
                if filename.endswith('_metadata.json'):
                    key_name = filename.replace('_metadata.json', '')
                    self.key_manager.load_key_pair(key_name)
            
            self.logger.info(f"Loaded {len(self.key_manager.list_keys())} existing keys")
            
        except Exception as e:
            self.logger.warning(f"Failed to load existing keys: {e}")
    
    def _start_security_monitoring(self):
        """Start security monitoring background task"""
        def monitoring_loop():
            while True:
                try:
                    self._check_key_rotation_needed()
                    self._audit_security()
                    time.sleep(3600)  # Check every hour
                except Exception as e:
                    self.logger.error(f"Error in security monitoring: {e}")
                    time.sleep(60)  # Wait 1 minute on error
        
        monitoring_thread = threading.Thread(target=monitoring_loop, daemon=True)
        monitoring_thread.start()
        self.logger.info("Security monitoring started")
    
    def _check_key_rotation_needed(self):
        """Check if any keys need rotation"""
        if not self.config['require_key_rotation']:
            return
        
        current_time = time.time()
        rotation_interval = self.config['key_rotation_interval']
        
        for key_info in self.key_manager.list_keys():
            if current_time - key_info['last_rotated'] > rotation_interval:
                self.logger.warning(f"Key '{key_info['key_name']}' needs rotation")
                
                # Auto-rotate if configured
                try:
                    self.key_manager.rotate_key(key_info['key_name'])
                    self.security_monitor.log_security_event(
                        'key_rotated',
                        {'key_name': key_info['key_name'], 'auto_rotated': True},
                        'info'
                    )
                except Exception as e:
                    self.security_monitor.log_security_event(
                        'key_rotation_failed',
                        {'key_name': key_info['key_name'], 'error': str(e)},
                        'warning'
                    )
    
    def _audit_security(self):
        """Perform security audit"""
        try:
            # Check file permissions
            self._check_file_permissions()
            
            # Check for suspicious activity
            summary = self.security_monitor.get_security_summary()
            if summary['critical_events'] > 0:
                self.logger.warning(f"Found {summary['critical_events']} critical security events in the last hour")
            
        except Exception as e:
            self.logger.error(f"Security audit failed: {e}")
    
    def _check_file_permissions(self):
        """Check security-related file permissions"""
        try:
            # Check that security directory has proper permissions
            security_dir_stat = os.stat(self.data_directory)
            permissions = oct(security_dir_stat.st_mode)[-3:]
            
            if permissions != '700':  # Should be owner-only
                self.security_monitor.log_security_event(
                    'insecure_permissions',
                    {'path': self.data_directory, 'permissions': permissions},
                    'warning'
                )
        except Exception as e:
            self.logger.warning(f"Failed to check file permissions: {e}")
    
    def get_security_status(self) -> Dict[str, Any]:
        """Get comprehensive security status"""
        return {
            'key_manager': {
                'total_keys': len(self.key_manager.list_keys()),
                'keys': self.key_manager.list_keys()
            },
            'security_monitoring': self.security_monitor.get_security_summary(),
            'configuration': self.config.copy()
        }
