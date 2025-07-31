# Open Omne Node - Troubleshooting Guide

## 🔍 Quick Diagnostics

### Health Check Commands
```bash
# Overall system health
curl http://localhost:3401/api/health

# Detailed diagnostics
curl http://localhost:3401/api/diagnostics/full

# Performance metrics
curl http://localhost:3401/api/performance/current

# Error summary
curl http://localhost:3401/api/errors/summary
```

### Log Analysis
```bash
# View live logs
docker-compose logs -f node.omne.open

# Search for errors
docker-compose logs node.omne.open | grep ERROR

# Check last 100 lines
docker-compose logs --tail=100 node.omne.open

# Filter by log level
docker-compose logs node.omne.open | grep "CRITICAL\|ERROR\|WARNING"
```

## 🚨 Common Issues and Solutions

### 1. Node Won't Start

#### Symptoms
- Docker container exits immediately
- "STEWARD_ADDRESS not set" error
- Port binding errors

#### Solutions

**Missing Steward Address**:
```bash
# Set the required environment variable
export STEWARD_ADDRESS=0z1234567890abcdef1234567890abcdef12345678
docker-compose up -d
```

**Invalid Steward Address Format**:
```bash
# Verify format: must start with '0z' and be exactly 42 characters
echo $STEWARD_ADDRESS | grep -E '^0z[0-9a-fA-F]{40}$'
```

**Port Already in Use**:
```bash
# Check what's using the port
sudo lsof -i :3401

# Kill process or change port
export OPEN_HOST_PORT=3402
docker-compose up -d
```

**Insufficient Permissions**:
```bash
# Fix data directory permissions
sudo chown -R $(whoami):$(whoami) ./data
chmod 755 ./data
```

### 2. Network Connectivity Issues

#### Symptoms
- No peer connections
- Cannot sync blockchain
- Network timeouts

#### Solutions

**Check Network Status**:
```bash
# View network peers
curl http://localhost:3401/api/network/peers

# Check connectivity
curl http://localhost:3401/api/network/status

# Test external connectivity
docker exec node.omne.open ping -c 3 8.8.8.8
```

**Firewall Configuration**:
```bash
# Allow node port through firewall
sudo ufw allow 3401

# Check Docker network
docker network ls
docker network inspect omne_node_eaies-net
```

**DNS Resolution Issues**:
```bash
# Test DNS resolution
docker exec node.omne.open nslookup omne.io

# Use alternative DNS
echo "nameserver 8.8.8.8" | sudo tee /etc/resolv.conf
```

### 3. Performance Issues

#### Symptoms
- Slow response times
- High CPU/memory usage
- Consensus timeouts

#### Solutions

**Resource Monitoring**:
```bash
# Check container resources
docker stats node.omne.open

# System resources
top
df -h
free -m
```

**Optimize Configuration**:
```bash
# Reduce transaction pool size
export OMNE_MAX_TRANSACTION_POOL_SIZE=5000

# Increase timeouts
export OMNE_TRANSACTION_TIMEOUT=7200

# Switch to file storage if using memory
export OMNE_STORAGE_BACKEND=file
```

**Database Optimization**:
```bash
# Clean old data
curl -X POST http://localhost:3401/api/maintenance/cleanup

# Compact storage
curl -X POST http://localhost:3401/api/storage/compact
```

### 4. Consensus Participation Problems

#### Symptoms
- Not participating in consensus
- Missing consensus rounds
- Block validation failures

#### Solutions

**Check Consensus Status**:
```bash
# View consensus participation
curl http://localhost:3401/api/consensus/participation

# Check validator status
curl http://localhost:3401/api/validator/status

# Review recent consensus rounds
curl http://localhost:3401/api/consensus/recent
```

**Synchronization Issues**:
```bash
# Check blockchain sync status
curl http://localhost:3401/api/blockchain/sync

# Force resync if needed
curl -X POST http://localhost:3401/api/blockchain/resync

# Check block height
curl http://localhost:3401/api/blockchain/height
```

**Key Management Issues**:
```bash
# Verify validator keys
curl http://localhost:3401/api/security/keys/status

# Regenerate keys if corrupted
curl -X POST http://localhost:3401/api/security/keys/regenerate
```

### 5. Storage Backend Issues

#### Symptoms
- Storage initialization failures
- Data corruption errors
- Backup/restore failures

#### Solutions

**Memory Storage Issues**:
```bash
# Check memory usage
free -m

# Switch to file storage
export OMNE_STORAGE_BACKEND=file
export OMNE_DATA_DIRECTORY=/var/omne/data
```

**File Storage Issues**:
```bash
# Check disk space
df -h

# Verify permissions
ls -la /var/omne/data

# Fix permissions
sudo chown -R omne:omne /var/omne/data
chmod 755 /var/omne/data
```

**Data Corruption**:
```bash
# Verify data integrity
curl http://localhost:3401/api/storage/verify

# Restore from backup
docker-compose down
tar -xzf backup_file.tar.gz -C ./
docker-compose up -d
```

### 6. Security and Key Management Issues

#### Symptoms
- Key generation failures
- Security warnings
- Authentication errors

#### Solutions

**Key Generation Problems**:
```bash
# Check security status
curl http://localhost:3401/api/security/status

# Regenerate keys
rm app/.env
docker-compose restart node.omne.open
```

**Permission Issues**:
```bash
# Fix security directory permissions
chmod 700 data/security
chown -R $(whoami) data/security
```

**Certificate Issues**:
```bash
# Check SSL configuration
openssl x509 -in /path/to/cert.crt -text -noout

# Generate self-signed certificate for testing
openssl req -x509 -newkey rsa:4096 -keyout key.pem -out cert.pem -days 365 -nodes
```

## 🔧 Advanced Troubleshooting

### Debug Mode
```bash
# Enable debug logging
export OMNE_LOG_LEVEL=DEBUG
export OMNE_DEBUG_MODE=true
docker-compose restart node.omne.open

# View debug logs
docker-compose logs -f node.omne.open | grep DEBUG
```

### Performance Profiling
```bash
# Get detailed performance report
curl http://localhost:3401/api/performance/detailed

# Memory usage analysis
docker exec node.omne.open cat /proc/meminfo

# CPU usage analysis
docker exec node.omne.open cat /proc/loadavg
```

### Network Analysis
```bash
# Check network interfaces
docker exec node.omne.open ip addr show

# Test connectivity to peers
docker exec node.omne.open netstat -an | grep 3400

# Check routing
docker exec node.omne.open ip route
```

### Database Debugging
```bash
# Check storage backend status
curl http://localhost:3401/api/storage/status

# List stored keys
curl http://localhost:3401/api/storage/keys

# Verify data integrity
curl http://localhost:3401/api/storage/verify
```

## 📋 Diagnostic Data Collection

### System Information
```bash
# Collect system info
uname -a > diagnostic_info.txt
docker version >> diagnostic_info.txt
docker-compose version >> diagnostic_info.txt
free -m >> diagnostic_info.txt
df -h >> diagnostic_info.txt
```

### Node Configuration
```bash
# Export current configuration
curl http://localhost:3401/api/config/export > node_config.json

# Environment variables
env | grep OMNE > environment.txt
env | grep STEWARD >> environment.txt
env | grep NODE >> environment.txt
```

### Logs and Metrics
```bash
# Export recent logs
docker-compose logs --since="1h" node.omne.open > recent_logs.txt

# Export performance metrics
curl http://localhost:3401/api/metrics/export > metrics.json

# Export error summary
curl http://localhost:3401/api/errors/export > errors.json
```

### Network Information
```bash
# Export network status
curl http://localhost:3401/api/network/export > network_status.json

# Export peer information
curl http://localhost:3401/api/peers/export > peers.json

# Export consensus information
curl http://localhost:3401/api/consensus/export > consensus.json
```

## 🛠️ Recovery Procedures

### Complete Node Reset
```bash
# 1. Stop the node
docker-compose down

# 2. Backup current data (optional)
tar -czf backup_$(date +%Y%m%d_%H%M%S).tar.gz data/

# 3. Clean data directory
rm -rf data/*

# 4. Reset configuration
rm app/.env

# 5. Restart node (will regenerate keys and resync)
docker-compose up -d

# 6. Monitor startup
docker-compose logs -f node.omne.open
```

### Partial Recovery
```bash
# 1. Stop consensus only
curl -X POST http://localhost:3401/api/consensus/stop

# 2. Clear mempool
curl -X POST http://localhost:3401/api/mempool/clear

# 3. Restart consensus
curl -X POST http://localhost:3401/api/consensus/start
```

### Blockchain Resync
```bash
# 1. Stop consensus
curl -X POST http://localhost:3401/api/consensus/stop

# 2. Clear blockchain data
curl -X POST http://localhost:3401/api/blockchain/clear

# 3. Start resync
curl -X POST http://localhost:3401/api/blockchain/resync

# 4. Monitor sync progress
curl http://localhost:3401/api/blockchain/sync/status
```

## 📞 Getting Support

### Before Contacting Support

1. **Collect diagnostic information**:
   ```bash
   curl http://localhost:3401/api/diagnostics/full > full_diagnostics.json
   ```

2. **Check recent error logs**:
   ```bash
   docker-compose logs --since="24h" node.omne.open | grep ERROR > error_logs.txt
   ```

3. **Verify configuration**:
   ```bash
   curl http://localhost:3401/api/config/validate > config_validation.json
   ```

### Support Channels

1. **Community Discord**: Join #open-node-support channel
2. **GitHub Issues**: Create issue with diagnostic information
3. **Documentation**: Check latest docs and FAQ
4. **Email Support**: Include diagnostic files in email

### Information to Include

- Node version and configuration
- Operating system and Docker version
- Error messages and logs
- Steps to reproduce the issue
- Diagnostic report from the node
- Network environment details

---

*This troubleshooting guide covers the most common issues encountered when running an Open Omne Node. For issues not covered here, please consult the community support channels.*
