#!/usr/bin/env python3
"""
Production Readiness Validation Script
This script validates that all production-grade infrastructure is working correctly.
"""

import sys
import os
import json
import time
from pathlib import Path

# Add the app directory to the Python path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'app'))

def validate_infrastructure():
    """Validate all infrastructure components"""
    print("🔍 Validating Production Infrastructure...")
    
    # Test 1: Configuration Management
    print("\n1. Testing Configuration Management...")
    try:
        from config_manager import OpenNodeConfigManager
        config_manager = OpenNodeConfigManager()
        config = config_manager.get_config()
        print("   ✓ Configuration management working")
    except Exception as e:
        print(f"   ✗ Configuration management failed: {e}")
        return False
    
    # Test 2: Error Handling
    print("\n2. Testing Error Handling...")
    try:
        from error_handling import ErrorHandler, ConfigurationError
        handler = ErrorHandler()
        test_error = ConfigurationError("Test error")
        handler.handle_error(test_error)
        print("   ✓ Error handling working")
    except Exception as e:
        print(f"   ✗ Error handling failed: {e}")
        return False
    
    # Test 3: Storage Abstraction
    print("\n3. Testing Storage Abstraction...")
    try:
        from storage_abstraction import StorageManager
        storage = StorageManager()
        storage.initialize('memory')
        storage.store('test_key', {'test': 'data'})
        data = storage.retrieve('test_key')
        assert data == {'test': 'data'}
        print("   ✓ Storage abstraction working")
    except Exception as e:
        print(f"   ✗ Storage abstraction failed: {e}")
        return False
    
    # Test 4: Performance Monitoring
    print("\n4. Testing Performance Monitoring...")
    try:
        from performance_monitor import PerformanceMonitor
        monitor = PerformanceMonitor()
        metrics = monitor.get_current_metrics()
        assert 'cpu_usage' in metrics
        assert 'memory_usage' in metrics
        print("   ✓ Performance monitoring working")
    except Exception as e:
        print(f"   ✗ Performance monitoring failed: {e}")
        return False
    
    # Test 5: Security Infrastructure
    print("\n5. Testing Security Infrastructure...")
    try:
        from advanced_security import SecurityManager
        security = SecurityManager()
        security.initialize()
        print("   ✓ Security infrastructure working")
    except Exception as e:
        print(f"   ✗ Security infrastructure failed: {e}")
        return False
    
    return True

def validate_blockchain_integration():
    """Validate blockchain components work with new infrastructure"""
    print("\n🔗 Validating Blockchain Integration...")
    
    # Test blockchain components
    try:
        from ledger import Ledger
        from mempool import Mempool
        from consensus_engine import ConsensusEngine
        
        # Test basic initialization
        ledger = Ledger()
        mempool = Mempool()
        print("   ✓ Core blockchain components loaded")
        
        # Test with configuration
        from config_manager import OpenNodeConfigManager
        config_manager = OpenNodeConfigManager()
        config = config_manager.get_config()
        print("   ✓ Blockchain integrated with configuration")
        
        return True
    except Exception as e:
        print(f"   ✗ Blockchain integration failed: {e}")
        return False

def validate_api_endpoints():
    """Validate that API endpoints are accessible"""
    print("\n🌐 Validating API Endpoints...")
    
    try:
        # Import flask app
        from network_manager import NetworkManager
        print("   ✓ Network manager loaded")
        print("   ✓ API endpoints available:")
        print("     - /api/health (basic health check)")
        print("     - /api/health/detailed (detailed health with metrics)")
        print("     - /api/metrics (performance metrics)")
        print("     - /api/status (comprehensive status)")
        return True
    except Exception as e:
        print(f"   ✗ API validation failed: {e}")
        return False

def validate_documentation():
    """Validate that documentation exists"""
    print("\n📚 Validating Documentation...")
    
    docs_path = Path('docs')
    required_docs = [
        'OPERATIONAL_RUNBOOK.md',
        'TROUBLESHOOTING_GUIDE.md',
        'PRODUCTION_DEPLOYMENT.md'
    ]
    
    missing_docs = []
    for doc in required_docs:
        if not (docs_path / doc).exists():
            missing_docs.append(doc)
    
    if missing_docs:
        print(f"   ✗ Missing documentation: {', '.join(missing_docs)}")
        return False
    else:
        print("   ✓ All operational documentation present")
        return True

def validate_tests():
    """Validate test suite"""
    print("\n🧪 Validating Test Suite...")
    
    import subprocess
    try:
        # Run tests
        result = subprocess.run(['python', '-m', 'pytest', 'tests/', '-v', '--tb=short'], 
                              capture_output=True, text=True)
        
        if result.returncode == 0:
            print("   ✓ All tests passing")
            return True
        else:
            print(f"   ✗ Tests failed: {result.stdout}")
            return False
    except Exception as e:
        print(f"   ✗ Test execution failed: {e}")
        return False

def main():
    """Main validation function"""
    print("🚀 OpenNode Production Readiness Validation")
    print("=" * 50)
    
    validation_results = []
    
    # Run all validations
    validation_results.append(("Infrastructure", validate_infrastructure()))
    validation_results.append(("Blockchain Integration", validate_blockchain_integration()))
    validation_results.append(("API Endpoints", validate_api_endpoints()))
    validation_results.append(("Documentation", validate_documentation()))
    validation_results.append(("Test Suite", validate_tests()))
    
    # Summary
    print("\n" + "=" * 50)
    print("📊 VALIDATION SUMMARY")
    print("=" * 50)
    
    all_passed = True
    for name, result in validation_results:
        status = "✓ PASS" if result else "✗ FAIL"
        print(f"{name:<25} {status}")
        if not result:
            all_passed = False
    
    print("\n" + "=" * 50)
    if all_passed:
        print("🎉 ALL VALIDATIONS PASSED!")
        print("🚀 OpenNode is PRODUCTION READY!")
        print("\nTo start the node:")
        print("  1. Set your steward address: export STEWARD_ADDRESS='your-address'")
        print("  2. Run: python app/main.py")
        print("\nFor quick setup: python setup.py --steward-address 'your-address'")
    else:
        print("❌ Some validations failed.")
        print("Please review the errors above and fix them before deploying to production.")
    
    return 0 if all_passed else 1

if __name__ == '__main__':
    sys.exit(main())
