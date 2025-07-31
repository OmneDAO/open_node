"""
Comprehensive Test Suite for Open Omne Node Infrastructure
Tests all production-ready components and systems.
"""

import pytest
import os
import tempfile
import shutil
import time
import threading
from decimal import Decimal
from unittest.mock import patch, MagicMock

# Import the modules we're testing
from config_manager import OpenNodeConfigManager, OpenNodeConfig
from error_handling import (
    ErrorHandler, Validator, OpenNodeError, ConfigurationError,
    NetworkError, ValidationError, with_error_handling, retry_on_error
)
from storage_abstraction import (
    StorageManager, MemoryStorageBackend, FileStorageBackend,
    BlockStorage, TransactionStorage
)
from performance_monitor import (
    PerformanceMonitor, MetricsCollector, HealthChecker, 
    PerformanceMetrics, TimedOperation
)
from advanced_security import (
    SecurityManager, KeyManager, SecurityMonitor, SecurityError
)


class TestOpenNodeConfigManager:
    """Test configuration management system"""
    
    def setup_method(self):
        """Setup for each test"""
        # Clear environment variables
        self.env_vars_to_clear = [
            'STEWARD_ADDRESS', 'NODE_ID', 'OMNE_NETWORK_PORT',
            'OMNE_STORAGE_BACKEND', 'OMNE_LOG_LEVEL'
        ]
        self.original_env = {}
        for var in self.env_vars_to_clear:
            self.original_env[var] = os.environ.get(var)
            if var in os.environ:
                del os.environ[var]
    
    def teardown_method(self):
        """Cleanup after each test"""
        # Restore environment variables
        for var, value in self.original_env.items():
            if value is not None:
                os.environ[var] = value
            elif var in os.environ:
                del os.environ[var]
    
    def test_config_requires_steward_address(self):
        """Test that steward address is required"""
        with pytest.raises(ValueError, match="STEWARD_ADDRESS is required"):
            OpenNodeConfigManager()
    
    def test_config_validates_steward_address_format(self):
        """Test steward address format validation"""
        os.environ['STEWARD_ADDRESS'] = 'invalid_address'
        with pytest.raises(ValueError, match="Invalid steward address format"):
            OpenNodeConfigManager()
    
    def test_config_with_valid_steward_address(self):
        """Test configuration with valid steward address"""
        os.environ['STEWARD_ADDRESS'] = '0z' + '1234567890abcdef' * 2 + '12345678'
        
        config_manager = OpenNodeConfigManager()
        assert config_manager.config.steward_address.startswith('0z')
        assert len(config_manager.config.steward_address) == 42
    
    def test_config_environment_variable_loading(self):
        """Test loading configuration from environment variables"""
        os.environ.update({
            'STEWARD_ADDRESS': '0z' + '1234567890abcdef' * 2 + '12345678',
            'PORT_NUMBER': '3500',
            'OMNE_STORAGE_BACKEND': 'memory',
            'OMNE_LOG_LEVEL': 'DEBUG',
            'NODE_ENV': 'development'
        })
        
        config_manager = OpenNodeConfigManager()
        
        assert config_manager.config.network_port == 3500
        assert config_manager.config.storage_backend == 'memory'
        assert config_manager.config.log_level == 'DEBUG'
        assert config_manager.config.debug_mode == True
    
    def test_production_readiness_check(self):
        """Test production readiness validation"""
        os.environ.update({
            'STEWARD_ADDRESS': '0z' + '1234567890abcdef' * 2 + '12345678',
            'OMNE_STORAGE_BACKEND': 'memory',
            'OMNE_LOG_LEVEL': 'DEBUG'
        })
        
        config_manager = OpenNodeConfigManager()
        assert not config_manager.is_production_ready()  # Memory storage + debug
        
        # Set production-ready values
        config_manager.config.storage_backend = 'file'
        config_manager.config.log_level = 'INFO'
        config_manager.config.debug_mode = False
        assert config_manager.is_production_ready()
    
    def test_config_summary(self):
        """Test configuration summary generation"""
        os.environ['STEWARD_ADDRESS'] = '0z' + '1234567890abcdef' * 2 + '12345678'
        
        config_manager = OpenNodeConfigManager()
        summary = config_manager.get_summary()
        
        assert 'steward_address' in summary
        assert 'network_port' in summary
        assert 'storage_backend' in summary
        assert 'production_ready' in summary


class TestErrorHandling:
    """Test error handling system"""
    
    def test_error_handler_initialization(self):
        """Test error handler initialization"""
        handler = ErrorHandler()
        assert handler.error_count == {}
        assert handler.error_history == []
    
    def test_error_handling_with_custom_error(self):
        """Test handling custom OpenNodeError"""
        handler = ErrorHandler()
        
        error = ConfigurationError("Test config error", context={'config_key': 'test'})
        error_info = handler.handle_error(error)
        
        assert error_info['type'] == 'ConfigurationError'
        assert error_info['message'] == 'Test config error'
        assert error_info['context']['config_key'] == 'test'
        assert handler.error_count['ConfigurationError'] == 1
    
    def test_error_handling_with_standard_error(self):
        """Test handling standard Python errors"""
        handler = ErrorHandler()
        
        error = ValueError("Test value error")
        error_info = handler.handle_error(error)
        
        assert error_info['type'] == 'ValueError'
        assert error_info['message'] == 'Test value error'
        assert handler.error_count['ValueError'] == 1
    
    def test_error_summary(self):
        """Test error summary generation"""
        handler = ErrorHandler()
        
        # Generate some errors
        handler.handle_error(ValueError("Error 1"))
        handler.handle_error(ConfigurationError("Error 2"))
        handler.handle_error(ValueError("Error 3"))
        
        summary = handler.get_error_summary()
        
        assert summary['total_errors'] == 3
        assert summary['error_counts']['ValueError'] == 2
        assert summary['error_counts']['ConfigurationError'] == 1
        assert len(summary['recent_errors']) == 3
    
    def test_validator_address_validation(self):
        """Test address validation"""
        # Valid address
        assert Validator.validate_address('0z' + '1234567890abcdef' * 2 + '12345678')
        
        # Invalid addresses
        assert not Validator.validate_address('invalid')
        assert not Validator.validate_address('0x1234567890abcdef12345678')  # Wrong prefix
        assert not Validator.validate_address('0z123')  # Too short
        assert not Validator.validate_address(None)
        assert not Validator.validate_address(123)
    
    def test_validator_amount_validation(self):
        """Test amount validation"""
        # Valid amounts
        assert Validator.validate_amount('100.5') == Decimal('100.5')
        assert Validator.validate_amount(100) == Decimal('100')
        assert Validator.validate_amount(Decimal('50.25')) == Decimal('50.25')
        
        # Invalid amounts
        with pytest.raises(ValidationError):
            Validator.validate_amount('-10')  # Negative
        
        with pytest.raises(ValidationError):
            Validator.validate_amount('invalid')  # Non-numeric
    
    def test_error_handling_decorator(self):
        """Test error handling decorator"""
        handler = ErrorHandler()
        
        class TestClass:
            def __init__(self):
                self.error_handler = handler
            
            @with_error_handling(default_return="error_occurred")
            def failing_method(self):
                raise ValueError("Test error")
            
            @with_error_handling(reraise=True)
            def reraise_method(self):
                raise ValueError("Test error")
        
        test_obj = TestClass()
        
        # Test default return on error
        result = test_obj.failing_method()
        assert result == "error_occurred"
        assert handler.error_count['ValueError'] == 1
        
        # Test reraise
        with pytest.raises(ValueError):
            test_obj.reraise_method()
    
    def test_retry_decorator(self):
        """Test retry decorator"""
        attempt_count = 0
        
        @retry_on_error(max_retries=2, delay=0.1)
        def failing_function():
            nonlocal attempt_count
            attempt_count += 1
            if attempt_count < 3:
                raise NetworkError("Network failure")
            return "success"
        
        result = failing_function()
        assert result == "success"
        assert attempt_count == 3


class TestStorageAbstraction:
    """Test storage abstraction system"""
    
    def setup_method(self):
        """Setup for each test"""
        self.temp_dir = tempfile.mkdtemp()
    
    def teardown_method(self):
        """Cleanup after each test"""
        if os.path.exists(self.temp_dir):
            shutil.rmtree(self.temp_dir)
    
    def test_memory_storage_backend(self):
        """Test memory storage backend"""
        backend = MemoryStorageBackend()
        
        # Test initialization
        assert backend.initialize() == True
        
        # Test store and retrieve
        assert backend.store('key1', {'data': 'value1'}) == True
        assert backend.retrieve('key1') == {'data': 'value1'}
        
        # Test exists
        assert backend.exists('key1') == True
        assert backend.exists('nonexistent') == False
        
        # Test list keys
        backend.store('key2', 'value2')
        keys = backend.list_keys()
        assert 'key1' in keys
        assert 'key2' in keys
        
        # Test delete
        assert backend.delete('key1') == True
        assert backend.exists('key1') == False
        
        # Test clear all
        assert backend.clear_all() == True
        assert len(backend.list_keys()) == 0
    
    def test_file_storage_backend(self):
        """Test file storage backend"""
        backend = FileStorageBackend(self.temp_dir)
        
        # Test initialization
        assert backend.initialize() == True
        
        # Test store and retrieve
        test_data = {'amount': Decimal('100.5'), 'text': 'test'}
        assert backend.store('test_key', test_data) == True
        
        retrieved = backend.retrieve('test_key')
        assert retrieved['amount'] == Decimal('100.5')
        assert retrieved['text'] == 'test'
        
        # Test file exists
        assert backend.exists('test_key') == True
        
        # Test get info
        info = backend.get_info()
        assert info['type'] == 'file'
        assert info['initialized'] == True
        assert info['file_count'] == 1
    
    def test_storage_manager(self):
        """Test storage manager"""
        # Test memory backend
        manager = StorageManager('memory')
        assert manager.initialize() == True
        
        # Test file backend
        file_manager = StorageManager('file', data_directory=self.temp_dir)
        assert file_manager.initialize() == True
        
        # Test invalid backend
        with pytest.raises(Exception):
            StorageManager('invalid_backend')
    
    def test_block_storage(self):
        """Test specialized block storage"""
        manager = StorageManager('memory')
        manager.initialize()
        
        block_storage = BlockStorage(manager)
        
        # Test store block
        block_data = {
            'hash': '1234567890abcdef' * 4,
            'index': 1,
            'transactions': [],
            'timestamp': time.time()
        }
        
        assert block_storage.store_block(block_data) == True
        
        # Test retrieve by hash
        retrieved = block_storage.get_block_by_hash(block_data['hash'])
        assert retrieved['hash'] == block_data['hash']
        assert retrieved['index'] == 1
        
        # Test retrieve by index
        retrieved = block_storage.get_block_by_index(1)
        assert retrieved['hash'] == block_data['hash']
        
        # Test latest block
        latest = block_storage.get_latest_block()
        assert latest['hash'] == block_data['hash']
    
    def test_transaction_storage(self):
        """Test specialized transaction storage"""
        manager = StorageManager('memory')
        manager.initialize()
        
        tx_storage = TransactionStorage(manager)
        
        # Test store transaction
        tx_data = {
            'hash': 'abcdef1234567890' * 4,
            'sender': '0z' + '1234567890abcdef' * 2 + '12345678',
            'amount': Decimal('50.0'),
            'timestamp': time.time()
        }
        
        assert tx_storage.store_transaction(tx_data) == True
        
        # Test retrieve transaction
        retrieved = tx_storage.get_transaction(tx_data['hash'])
        assert retrieved['hash'] == tx_data['hash']
        assert retrieved['amount'] == Decimal('50.0')
        
        # Test get transactions by sender
        txs = tx_storage.get_transactions_by_sender(tx_data['sender'])
        assert len(txs) == 1
        assert txs[0]['hash'] == tx_data['hash']


class TestPerformanceMonitor:
    """Test performance monitoring system"""
    
    def test_metrics_collector(self):
        """Test metrics collection"""
        collector = MetricsCollector()
        
        # Test counter increment
        collector.increment_counter('test_counter', 5)
        assert collector.get_counter('test_counter') == 5
        
        collector.increment_counter('test_counter')
        assert collector.get_counter('test_counter') == 6
        
        # Test response time recording
        collector.record_response_time(1.5)
        collector.record_response_time(2.0)
        assert collector.get_average_response_time() == 1.75
        
        # Test timer
        collector.start_timer('test_operation')
        time.sleep(0.1)
        elapsed = collector.stop_timer('test_operation')
        assert elapsed >= 0.1
    
    @patch('performance_monitor.psutil')
    def test_system_metrics_collection(self, mock_psutil):
        """Test system metrics collection"""
        # Mock psutil functions
        mock_psutil.cpu_percent.return_value = 45.5
        mock_psutil.virtual_memory.return_value = MagicMock(percent=60.0)
        mock_psutil.disk_usage.return_value = MagicMock(percent=75.0)
        mock_psutil.net_connections.return_value = [1, 2, 3]  # 3 connections
        
        collector = MetricsCollector()
        metrics = collector.collect_system_metrics()
        
        assert metrics['cpu_usage'] == 45.5
        assert metrics['memory_usage'] == 60.0
        assert metrics['disk_usage'] == 75.0
        assert metrics['network_connections'] == 3
    
    def test_health_checker(self):
        """Test health checking system"""
        collector = MetricsCollector()
        health_checker = HealthChecker(collector)
        
        # Register a test health check
        def test_check():
            return {'healthy': True, 'status': 'OK'}
        
        health_checker.register_health_check('test_check', test_check, critical=True)
        
        # Run health checks
        results = health_checker.run_health_checks()
        
        assert results['overall_healthy'] == True
        assert 'test_check' in results['checks']
        assert results['checks']['test_check']['healthy'] == True
        assert results['checks']['test_check']['critical'] == True
    
    def test_timed_operation(self):
        """Test timed operation context manager"""
        collector = MetricsCollector()
        
        with TimedOperation(collector, 'test_operation'):
            time.sleep(0.1)
        
        # Should have recorded response time
        avg_time = collector.get_average_response_time()
        assert avg_time >= 0.1


class TestAdvancedSecurity:
    """Test advanced security system"""
    
    def setup_method(self):
        """Setup for each test"""
        self.temp_dir = tempfile.mkdtemp()
    
    def teardown_method(self):
        """Cleanup after each test"""
        if os.path.exists(self.temp_dir):
            shutil.rmtree(self.temp_dir)
    
    def test_key_manager_initialization(self):
        """Test key manager initialization"""
        key_manager = KeyManager(self.temp_dir)
        assert os.path.exists(self.temp_dir)
    
    def test_ec_key_generation(self):
        """Test EC key generation"""
        key_manager = KeyManager(self.temp_dir)
        
        private_key, public_key = key_manager.generate_ec_key_pair('test_key')
        
        assert private_key.startswith('-----BEGIN PRIVATE KEY-----')
        assert public_key.startswith('-----BEGIN PUBLIC KEY-----')
        
        # Test key loading
        loaded_private, loaded_public = key_manager.load_key_pair('test_key')
        assert loaded_private == private_key
        assert loaded_public == public_key
    
    def test_rsa_key_generation(self):
        """Test RSA key generation"""
        key_manager = KeyManager(self.temp_dir)
        
        private_key, public_key = key_manager.generate_rsa_key_pair('rsa_test_key')
        
        assert private_key.startswith('-----BEGIN PRIVATE KEY-----')
        assert public_key.startswith('-----BEGIN PUBLIC KEY-----')
    
    def test_key_rotation(self):
        """Test key rotation"""
        key_manager = KeyManager(self.temp_dir)
        
        # Generate initial key
        original_private, original_public = key_manager.generate_ec_key_pair('rotation_test')
        
        # Rotate key
        assert key_manager.rotate_key('rotation_test') == True
        
        # Load rotated key
        new_private, new_public = key_manager.load_key_pair('rotation_test')
        
        # Should be different from original
        assert new_private != original_private
        assert new_public != original_public
    
    def test_key_listing(self):
        """Test key listing"""
        key_manager = KeyManager(self.temp_dir)
        
        # Generate some keys
        key_manager.generate_ec_key_pair('key1')
        key_manager.generate_rsa_key_pair('key2')
        
        keys = key_manager.list_keys()
        assert len(keys) == 2
        
        key_names = [k['key_name'] for k in keys]
        assert 'key1' in key_names
        assert 'key2' in key_names
    
    def test_security_monitor(self):
        """Test security monitoring"""
        monitor = SecurityMonitor()
        
        # Test security event logging
        monitor.log_security_event('test_event', {'detail': 'test'}, 'info')
        
        summary = monitor.get_security_summary()
        assert summary['total_events'] == 1
        assert summary['recent_events'] == 1
        
        # Test failed attempt recording
        monitor.record_failed_attempt('test_user', 'login')
        assert not monitor.is_locked_out('test_user')  # First attempt
        
        # Record multiple failed attempts
        for _ in range(5):
            monitor.record_failed_attempt('test_user', 'login')
        
        assert monitor.is_locked_out('test_user')  # Should be locked out
    
    def test_security_manager_initialization(self):
        """Test security manager initialization"""
        security_manager = SecurityManager(self.temp_dir)
        assert security_manager.initialize() == True
        
        status = security_manager.get_security_status()
        assert 'key_manager' in status
        assert 'security_monitoring' in status
        assert 'configuration' in status


class TestIntegration:
    """Integration tests for the complete system"""
    
    def setup_method(self):
        """Setup for integration tests"""
        self.temp_dir = tempfile.mkdtemp()
        os.environ['STEWARD_ADDRESS'] = '0z' + '1234567890abcdef' * 2 + '12345678'
    
    def teardown_method(self):
        """Cleanup after integration tests"""
        if os.path.exists(self.temp_dir):
            shutil.rmtree(self.temp_dir)
        if 'STEWARD_ADDRESS' in os.environ:
            del os.environ['STEWARD_ADDRESS']
    
    def test_complete_node_setup(self):
        """Test complete node setup with all components"""
        # Initialize configuration
        config_manager = OpenNodeConfigManager()
        assert config_manager.config.steward_address is not None
        
        # Initialize storage
        storage_manager = StorageManager('file', data_directory=self.temp_dir)
        assert storage_manager.initialize() == True
        
        # Initialize performance monitoring
        perf_monitor = PerformanceMonitor()
        assert perf_monitor is not None
        
        # Initialize security
        security_manager = SecurityManager(self.temp_dir)
        assert security_manager.initialize() == True
        
        # Test that all components work together
        assert config_manager.is_production_ready() == False  # Debug mode
        assert storage_manager.get_backend_info()['type'] == 'file'
        assert len(security_manager.get_security_status()['key_manager']['keys']) == 0
    
    def test_error_handling_integration(self):
        """Test error handling across components"""
        error_handler = ErrorHandler()
        
        # Test storage error handling
        try:
            storage_manager = StorageManager('invalid_backend')
        except Exception as e:
            error_info = error_handler.handle_error(e)
            assert error_info['type'] in ['StorageError', 'Exception']
        
        # Test configuration error handling
        try:
            os.environ['STEWARD_ADDRESS'] = 'invalid'
            config_manager = OpenNodeConfigManager()
        except Exception as e:
            error_info = error_handler.handle_error(e)
            assert error_info['type'] == 'ValueError'
        finally:
            os.environ['STEWARD_ADDRESS'] = '0z' + '1234567890abcdef' * 2 + '12345678'
    
    def test_performance_monitoring_integration(self):
        """Test performance monitoring with other components"""
        perf_monitor = PerformanceMonitor(collection_interval=1)
        
        # Start monitoring
        perf_monitor.start_monitoring()
        
        # Simulate some operations
        perf_monitor.record_block_processed()
        perf_monitor.record_transaction_processed()
        perf_monitor.record_consensus_round()
        
        # Get metrics
        metrics = perf_monitor.get_current_metrics()
        assert metrics.blocks_processed >= 1
        assert metrics.transactions_processed >= 1
        assert metrics.consensus_rounds >= 1
        
        # Stop monitoring
        perf_monitor.stop_monitoring()


if __name__ == "__main__":
    pytest.main(["-v", __file__])
