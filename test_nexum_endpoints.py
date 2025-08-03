#!/usr/bin/env python3
"""
Test script for OMNE Open Node Nexum Compliance Endpoints

This script tests the three required API endpoints for nexum validation:
- /api/node/class_hashes - Class integrity verification
- /api/node/info - Node information
- /api/node/capabilities - Node capabilities

Usage:
    python test_nexum_endpoints.py [node_url]

Example:
    python test_nexum_endpoints.py http://localhost:5000
"""

import requests
import json
import sys
from typing import Dict, Any

def test_endpoint(base_url: str, endpoint: str) -> Dict[str, Any]:
    """Test a single API endpoint"""
    url = f"{base_url}{endpoint}"
    
    try:
        print(f"\n🔍 Testing: {url}")
        response = requests.get(url, timeout=10)
        
        print(f"   Status: {response.status_code}")
        
        if response.status_code == 200:
            data = response.json()
            print(f"   ✅ Success")
            return {"success": True, "data": data, "url": url}
        else:
            print(f"   ❌ Failed - HTTP {response.status_code}")
            print(f"   Response: {response.text}")
            return {"success": False, "status": response.status_code, "url": url}
            
    except requests.exceptions.RequestException as e:
        print(f"   ❌ Connection Error: {e}")
        return {"success": False, "error": str(e), "url": url}

def validate_class_hashes_response(data: Dict[str, Any]) -> bool:
    """Validate class_hashes endpoint response structure"""
    required_fields = ['class_hashes', 'total_classes', 'node_version']
    
    for field in required_fields:
        if field not in data:
            print(f"   ⚠️  Missing required field: {field}")
            return False
    
    if not isinstance(data['class_hashes'], dict):
        print(f"   ⚠️  class_hashes should be a dictionary")
        return False
        
    # Check for critical classes required by nexum
    critical_classes = ['Block', 'Ledger', 'ConsensusEngine', 'NetworkManager']
    missing_classes = []
    
    for cls in critical_classes:
        if cls not in data['class_hashes']:
            missing_classes.append(cls)
    
    if missing_classes:
        print(f"   ⚠️  Missing critical classes: {missing_classes}")
        return False
    
    print(f"   ✅ Valid structure with {len(data['class_hashes'])} classes")
    return True

def validate_info_response(data: Dict[str, Any]) -> bool:
    """Validate node info endpoint response structure"""
    required_fields = ['node_id', 'version', 'node_type']
    
    for field in required_fields:
        if field not in data:
            print(f"   ⚠️  Missing required field: {field}")
            return False
    
    print(f"   ✅ Valid structure - Node ID: {data['node_id']}, Version: {data['version']}")
    return True

def validate_capabilities_response(data: Dict[str, Any]) -> bool:
    """Validate capabilities endpoint response structure"""
    required_fields = ['capabilities']
    
    for field in required_fields:
        if field not in data:
            print(f"   ⚠️  Missing required field: {field}")
            return False
    
    if not isinstance(data['capabilities'], dict):
        print(f"   ⚠️  capabilities should be a dictionary")
        return False
    
    # Check for critical capabilities required by nexum
    critical_caps = ['consensus', 'validation', 'smart_contracts']
    missing_caps = []
    
    for cap in critical_caps:
        if cap not in data['capabilities']:
            missing_caps.append(cap)
        elif not data['capabilities'][cap]:
            print(f"   ⚠️  Critical capability '{cap}' is disabled")
    
    if missing_caps:
        print(f"   ⚠️  Missing critical capabilities: {missing_caps}")
        return False
    
    enabled_count = sum(1 for v in data['capabilities'].values() if v)
    print(f"   ✅ Valid structure with {enabled_count} capabilities enabled")
    return True

def main():
    # Get node URL from command line or use default
    if len(sys.argv) > 1:
        base_url = sys.argv[1].rstrip('/')
    else:
        base_url = "http://localhost:5000"
    
    print(f"🚀 Testing OMNE Open Node Nexum Compliance")
    print(f"   Target: {base_url}")
    print(f"   Testing 3 required endpoints...")
    
    # Test endpoints
    endpoints = [
        ('/api/node/class_hashes', validate_class_hashes_response),
        ('/api/node/info', validate_info_response),
        ('/api/node/capabilities', validate_capabilities_response)
    ]
    
    results = []
    all_passed = True
    
    for endpoint, validator in endpoints:
        result = test_endpoint(base_url, endpoint)
        results.append(result)
        
        if result.get('success'):
            # Validate response structure
            if not validator(result['data']):
                all_passed = False
        else:
            all_passed = False
    
    # Summary
    print(f"\n📊 Test Summary:")
    print(f"   Target Node: {base_url}")
    
    success_count = sum(1 for r in results if r.get('success'))
    print(f"   Endpoints Tested: {len(results)}")
    print(f"   Successful: {success_count}")
    print(f"   Failed: {len(results) - success_count}")
    
    if all_passed:
        print(f"\n🎉 ALL TESTS PASSED - Node is Nexum compliant!")
        print(f"   This node can be submitted for network validation.")
    else:
        print(f"\n❌ SOME TESTS FAILED - Node needs fixes before validation.")
        print(f"   Review the errors above and fix the issues.")
    
    # Detailed results
    if '--verbose' in sys.argv or '-v' in sys.argv:
        print(f"\n📝 Detailed Results:")
        for i, result in enumerate(results):
            endpoint = endpoints[i][0]
            print(f"\n   Endpoint: {endpoint}")
            if result.get('success'):
                print(f"   Response: {json.dumps(result['data'], indent=2)}")
            else:
                print(f"   Error: {result.get('error', 'HTTP error')}")
    
    return 0 if all_passed else 1

if __name__ == "__main__":
    exit_code = main()
    sys.exit(exit_code)
