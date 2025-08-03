#!/usr/bin/env python3
"""
Test script to verify that open_node has all the essential functionality
for running as a validator node without genesis/treasury capabilities.
"""

import sys
import os
import importlib.util

def test_import(module_name, file_path=None):
    """Test if a module can be imported successfully"""
    try:
        if file_path:
            spec = importlib.util.spec_from_file_location(module_name, file_path)
            module = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(module)
        else:
            importlib.import_module(module_name)
        print(f"✅ {module_name} - Import successful")
        return True
    except Exception as e:
        print(f"❌ {module_name} - Import failed: {e}")
        return False

def main():
    print("🔍 Testing Open Node Functionality\n")
    
    # Add the app directory to Python path
    app_path = os.path.join(os.path.dirname(__file__), 'app')
    sys.path.insert(0, app_path)
    
    # Test critical imports for validator functionality
    critical_modules = [
        'network_manager',
        'ledger',
        'consensus_engine', 
        'mempool',
        'omc',
        'account_manager',
        'staking',
        'staked_omc',
        'block',
        'crypto_utils',
        'vrf_utils',
        'verifier',
        'node',
        'class_integrity_verifier',
        'validator_registration',
        'validator_initializer',
        'config_manager',
        'error_handling',
        'performance_monitor',
        'advanced_security'
    ]
    
    print("🧪 Testing Core Module Imports:")
    success_count = 0
    
    for module in critical_modules:
        if test_import(module):
            success_count += 1
    
    print(f"\n📊 Results: {success_count}/{len(critical_modules)} modules imported successfully")
    
    # Test specific functionality
    print("\n🔧 Testing Specific Functionality:")
    
    try:
        from network_manager import NetworkManager
        from ledger import Ledger
        from consensus_engine import ConsensusEngine
        from class_integrity_verifier import ClassIntegrityVerifier
        
        # Test if critical methods exist
        tests = [
            (hasattr(NetworkManager, '_initialize_blueprints'), "NetworkManager has blueprint initialization"),
            (hasattr(Ledger, 'finalize_block'), "Ledger has finalize_block method"),
            (hasattr(ConsensusEngine, 'start_consensus_routine'), "ConsensusEngine has consensus routine"),
            (hasattr(ClassIntegrityVerifier, 'verify_class_integrity'), "ClassIntegrityVerifier has verification"),
        ]
        
        for test, description in tests:
            if test:
                print(f"✅ {description}")
            else:
                print(f"❌ {description}")
                
    except Exception as e:
        print(f"❌ Error testing functionality: {e}")
    
    # Test return type fixes
    print("\n🔄 Testing Return Type Fixes:")
    try:
        from ledger import Ledger
        import inspect
        
        # Check finalize_block return type annotation
        sig = inspect.signature(Ledger.finalize_block)
        return_annotation = sig.return_annotation
        
        if return_annotation == bool:
            print("✅ Ledger.finalize_block returns bool (fixed)")
        else:
            print(f"❌ Ledger.finalize_block returns {return_annotation} (should be bool)")
            
    except Exception as e:
        print(f"❌ Error testing return types: {e}")
    
    print("\n🏁 Open Node Validation Complete!")
    
    if success_count == len(critical_modules):
        print("🌟 All critical modules are available - Open Node should be fully functional!")
        return True
    else:
        print("⚠️ Some modules missing - Review import errors above")
        return False

if __name__ == "__main__":
    main()
