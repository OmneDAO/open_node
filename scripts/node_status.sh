#!/bin/bash
# File: scripts/node_status.sh
# Purpose: Check the status of the Open Source Omne Validator Node

set -e

echo "📊 Open Source Omne Validator Node Status"
echo "========================================"

# Check if .env file exists and load variables
if [ -f ".env" ]; then
    export $(grep -v '^#' .env | xargs)
    echo "✅ Configuration loaded from .env"
else
    echo "❌ .env file not found. Run 'scripts/setup_node.sh' first."
    exit 1
fi

# Check Docker container status
echo ""
echo "🐳 Docker Container Status:"

if docker-compose ps | grep -q "Up"; then
    echo "✅ Container is running"
    CONTAINER_NAME=$(docker-compose ps --services)
    CONTAINER_STATUS=$(docker-compose ps | grep "$CONTAINER_NAME" | awk '{print $4}')
    echo "   Status: $CONTAINER_STATUS"
else
    echo "❌ Container is not running"
    echo "💡 Start with: docker-compose up -d"
    exit 1
fi

# Check node health endpoint
echo ""
echo "🌐 Node Health Check:"

if [ -z "$PORT_NUMBER" ]; then
    PORT_NUMBER=3400
fi

HEALTH_URL="http://localhost:${PORT_NUMBER}/api/health"

if curl -s "$HEALTH_URL" > /dev/null 2>&1; then
    echo "✅ Node is responding on port $PORT_NUMBER"
    
    # Get health details
    HEALTH_RESPONSE=$(curl -s "$HEALTH_URL")
    echo "   Response: $HEALTH_RESPONSE"
else
    echo "❌ Node is not responding on port $PORT_NUMBER"
    echo "⏳ Node may still be starting up..."
fi

# Check recent logs for errors
echo ""
echo "📋 Recent Log Summary:"

RECENT_LOGS=$(docker-compose logs --tail=20 2>/dev/null | grep -E "(ERROR|CRITICAL|✅|❌)" | tail -5)

if [ -n "$RECENT_LOGS" ]; then
    echo "$RECENT_LOGS"
else
    echo "⚠️  No recent error or success messages found"
fi

# Display configuration summary
echo ""
echo "⚙️  Configuration Summary:"
echo "   Node ID: ${NODE_ID:-Not set}"
echo "   Steward: ${STEWARD_ADDRESS:-Not set}"
echo "   Environment: ${NODE_ENV:-Not set}"
echo "   Port: ${PORT_NUMBER:-3400}"
echo "   Bootstrap: ${OMNE_BOOTSTRAP_NODES:-Not set}"

# Check if node is participating in consensus
echo ""
echo "🔄 Validator Status:"

if curl -s "$HEALTH_URL" > /dev/null 2>&1; then
    # Try to get validator info if available
    VALIDATOR_INFO=$(curl -s "http://localhost:${PORT_NUMBER}/api/peer/peers" 2>/dev/null || echo "")
    
    if [ -n "$VALIDATOR_INFO" ]; then
        echo "✅ Node is connected to network"
        echo "   Peer connections available"
    else
        echo "⚠️  Node may still be connecting to network"
    fi
else
    echo "❌ Cannot check validator status - node not responding"
fi

echo ""
echo "🔧 Management Commands:"
echo "   View logs: docker-compose logs -f"
echo "   Restart node: docker-compose restart"
echo "   Stop node: docker-compose down"
echo "   Update config: ./scripts/setup_node.sh"
echo "   Full validation: ./scripts/validate_setup.sh"
