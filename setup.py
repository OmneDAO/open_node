#!/usr/bin/env python3
"""
Quick setup script for OpenNode
This script helps users set up an OpenNode instance with minimal configuration.
"""

import os
import sys
import argparse
from pathlib import Path

def main():
    parser = argparse.ArgumentParser(description='Setup OpenNode for production use')
    parser.add_argument('--steward-address', 
                       required=True,
                       help='The steward wallet address for this node')
    parser.add_argument('--port', 
                       type=int, 
                       default=5000,
                       help='Port to run the node on (default: 5000)')
    parser.add_argument('--storage-type', 
                       choices=['memory', 'file', 'database'],
                       default='file',
                       help='Storage backend type (default: file)')
    parser.add_argument('--environment', 
                       choices=['development', 'production'],
                       default='production',
                       help='Environment mode (default: production)')
    parser.add_argument('--check-only', 
                       action='store_true',
                       help='Only check configuration, don\'t run')
    
    args = parser.parse_args()
    
    # Set up environment file
    env_file = Path('app/.env')
    env_content = f"""# OpenNode Configuration
STEWARD_ADDRESS={args.steward_address}
PORT={args.port}
STORAGE_TYPE={args.storage_type}
ENVIRONMENT={args.environment}
NODE_TYPE=open_node
DEBUG={"true" if args.environment == "development" else "false"}

# Security settings
ENABLE_SECURITY_MONITORING=true
KEY_ROTATION_INTERVAL=86400

# Performance settings
ENABLE_PERFORMANCE_MONITORING=true
METRICS_COLLECTION_INTERVAL=60

# Logging
LOG_LEVEL=INFO
LOG_FORMAT=structured
"""
    
    with open(env_file, 'w') as f:
        f.write(env_content)
    
    print(f"✓ Configuration written to {env_file}")
    print(f"✓ Steward address: {args.steward_address}")
    print(f"✓ Port: {args.port}")
    print(f"✓ Storage: {args.storage_type}")
    print(f"✓ Environment: {args.environment}")
    
    if args.check_only:
        print("\n📋 Configuration check complete!")
        print("To start the node, run: python app/main.py")
        return
    
    # Ask if user wants to start the node
    print("\n🚀 Configuration complete!")
    start_now = input("Start the node now? (y/N): ").lower().strip()
    
    if start_now in ['y', 'yes']:
        print("Starting OpenNode...")
        os.chdir('app')
        os.system('python main.py')
    else:
        print("To start the node later, run: python app/main.py")

if __name__ == '__main__':
    main()
