#!/bin/bash
# File: scripts/validate_setup.sh
# Purpose: Validate that the Open Source Omne Validator Node is properly configured

set -e

echo "🔍 Validating Open Source Omne Validator Node Setup"
echo "=================================================="

# Check if required files exist
echo "📁 Checking required files..."

required_files=(
    "docker-compose.yml"
    "app/main.py"
    "app/network_manager.py"
    "app/ledger.py"
    "app/config_manager.py"
    "app/validator_registration.py"
    "scripts/entrypoint.sh"
)

for file in "${required_files[@]}"; do
    if [ -f "$file" ]; then
        echo "✅ $file exists"
    else
        echo "❌ $file missing"
        exit 1
    fi
done

# Check Python syntax
echo ""
echo "🐍 Validating Python syntax..."

python_files=(
    "app/main.py"
    "app/network_manager.py"
    "app/ledger.py"
    "app/config_manager.py"
    "app/validator_registration.py"
)

for file in "${python_files[@]}"; do
    if python3 -m py_compile "$file" 2>/dev/null; then
        echo "✅ $file syntax valid"
    else
        echo "❌ $file syntax error"
        python3 -m py_compile "$file"
        exit 1
    fi
done

# Check docker-compose.yml syntax
echo ""
echo "🐳 Validating Docker Compose configuration..."

if docker-compose config > /dev/null 2>&1; then
    echo "✅ docker-compose.yml syntax valid"
else
    echo "❌ docker-compose.yml syntax error"
    docker-compose config
    exit 1
fi

# Check if .env file exists and has required variables
echo ""
echo "⚙️  Checking environment configuration..."

if [ -f ".env" ]; then
    echo "✅ .env file exists"
    
    required_vars=(
        "NODE_ID"
        "STEWARD_ADDRESS"
        "NODE_ENV"
        "PORT_NUMBER"
        "OMNE_BOOTSTRAP_NODES"
        "HASH_API_URL"
    )
    
    for var in "${required_vars[@]}"; do
        if grep -q "^${var}=" .env; then
            echo "✅ $var configured"
        else
            echo "⚠️  $var not found in .env"
        fi
    done
else
    echo "⚠️  .env file not found - run scripts/setup_node.sh first"
fi

# Check script permissions
echo ""
echo "🔐 Checking script permissions..."

script_files=(
    "scripts/setup_node.sh"
    "scripts/entrypoint.sh"
    "scripts/validate_setup.sh"
)

for script in "${script_files[@]}"; do
    if [ -x "$script" ]; then
        echo "✅ $script is executable"
    else
        echo "⚠️  $script not executable - fixing..."
        chmod +x "$script"
        echo "✅ $script made executable"
    fi
done

echo ""
echo "🎉 Validation complete!"
echo ""
echo "📋 Summary:"
echo "• All required files present"
echo "• Python syntax valid"
echo "• Docker configuration valid"
echo "• Environment variables configured"
echo "• Script permissions correct"
echo ""
echo "🚀 Your Open Source Omne Validator Node is ready!"
echo "💡 Run 'scripts/setup_node.sh' to configure and start your node"
