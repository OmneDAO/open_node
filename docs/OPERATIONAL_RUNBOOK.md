# Open Omne Node - Operational Runbook

## 🚀 Quick Start Guide

### Prerequisites
- Python 3.11+
- Docker and Docker Compose
- At least 4GB RAM and 10GB disk space
- Valid Omne wallet address (starts with `0z`)

### Basic Setup (Plug and Play)

1. **Clone and Setup**:
   ```bash
   git clone <repository>
   cd open_node
   chmod +x scripts/setup_node.sh
   ```

2. **Configure Your Node**:
   ```bash
   ./scripts/setup_node.sh
   ```
   - Enter your wallet address when prompted
   - Select environment (development/staging/production)
   - Script will generate unique node ID and configure ports

3. **Start the Node**:
   ```bash
   docker-compose up -d
   ```

4. **Verify Operation**:
   ```bash
   # Check node health
   curl http://localhost:3401/api/health
   
   # View logs
   docker-compose logs -f
   ```

## 📊 Monitoring & Health Checks

### Built-in Health Endpoints
```bash
# Overall health status
curl http://localhost:3401/api/health

# Performance metrics
curl http://localhost:3401/api/metrics

# Security status
curl http://localhost:3401/api/security/status

# Configuration summary
curl http://localhost:3401/api/config/summary
```

### Key Metrics to Monitor
1. **Consensus Participation Rate** - Should be >95%
2. **Block Validation Success** - Should be >99%
3. **Network Connectivity** - Active peer connections
4. **Staking Agreement Status** - Active stakes and rewards
5. **System Resources** - CPU, Memory, Disk usage

### Performance Monitoring
```bash
# Get detailed performance report
curl http://localhost:3401/api/performance/report

# Check recent errors
curl http://localhost:3401/api/errors/summary

# View consensus statistics
curl http://localhost:3401/api/consensus/stats
```

## 🔧 Configuration Management

### Environment Variables Reference
```bash
# Required Configuration
STEWARD_ADDRESS=0z1234567890abcdef1234567890abcdef12345678  # Your wallet address

# Network Configuration
PORT_NUMBER=3401                    # Node's network port
NODE_ID=N2RlNmY0                  # Unique node identifier
NODE_ROLE=validator                # validator or observer

# Storage Configuration
OMNE_STORAGE_BACKEND=file          # file, memory, or mongodb
OMNE_DATA_DIRECTORY=./data         # Data storage location

# Performance Configuration
OMNE_MAX_BLOCK_SIZE=1000000        # Maximum block size (1MB)
OMNE_MAX_TRANSACTION_POOL_SIZE=10000  # Transaction pool limit
OMNE_TRANSACTION_TIMEOUT=3600      # Transaction timeout (1 hour)

# Logging Configuration
OMNE_LOG_LEVEL=INFO                # DEBUG, INFO, WARNING, ERROR, CRITICAL
OMNE_LOG_FILE=/var/log/omne/node.log  # Log file location

# Security Configuration
OMNE_ENABLE_SSL=false              # Enable SSL/TLS
OMNE_SSL_CERT_PATH=/path/to/cert   # SSL certificate path
OMNE_SSL_KEY_PATH=/path/to/key     # SSL private key path

# Development Configuration
NODE_ENV=production                # development, staging, production
OMNE_DEBUG_MODE=false              # Enable debug mode

# Consensus Configuration
OMNE_RANDAO_COMMIT_DURATION=60     # RANDAO commit phase duration
OMNE_RANDAO_REVEAL_DURATION=60     # RANDAO reveal phase duration
OMNE_POEF_DIFFICULTY=4             # Proof of Effort difficulty
```

### Configuration Profiles

#### Development Profile
```bash
export STEWARD_ADDRESS=0z1234567890abcdef1234567890abcdef12345678
export NODE_ENV=development
export OMNE_STORAGE_BACKEND=memory
export OMNE_LOG_LEVEL=DEBUG
export OMNE_DEBUG_MODE=true
```

#### Production Profile
```bash
export STEWARD_ADDRESS=0z1234567890abcdef1234567890abcdef12345678
export NODE_ENV=production
export OMNE_STORAGE_BACKEND=file
export OMNE_DATA_DIRECTORY=/var/omne/data
export OMNE_LOG_LEVEL=INFO
export OMNE_ENABLE_SSL=true
export OMNE_LOG_FILE=/var/log/omne/node.log
```

## 🔄 Operational Procedures

### Starting the Node

1. **Docker Deployment (Recommended)**:
   ```bash
   # Start with docker-compose
   docker-compose up -d
   
   # Check status
   docker-compose ps
   
   # View logs
   docker-compose logs -f node.omne.open
   ```

2. **Direct Python Deployment**:
   ```bash
   # Install dependencies
   pip install -r requirements_open.txt
   
   # Set environment variables
   export STEWARD_ADDRESS=0z1234567890abcdef1234567890abcdef12345678
   export PORT_NUMBER=3401
   
   # Start node
   python app/main_production.py
   ```

### Network Participation

1. **Joining the Network**:
   - Node automatically discovers and connects to network peers
   - Downloads and syncs blockchain state
   - Begins participating in consensus once synced

2. **Validator Operations**:
   - Validates incoming blocks and transactions
   - Participates in consensus rounds
   - Proposes blocks when selected as leader

3. **Staking Operations**:
   - Receives and processes staking agreements
   - Manages staker rewards distribution
   - Handles stake withdrawals and term completions

### Backup Procedures

```bash
# Backup node data
docker exec node.omne.open tar -czf /tmp/node_backup_$(date +%Y%m%d_%H%M%S).tar.gz /app/data

# Copy backup to host
docker cp node.omne.open:/tmp/node_backup_*.tar.gz ./backups/

# Backup configuration
cp docker-compose.yml ./backups/
cp -r scripts ./backups/
```

### Recovery Procedures

```bash
# Stop node
docker-compose down

# Restore data
docker run --rm -v $(pwd)/data:/data alpine tar -xzf /backup/node_backup_*.tar.gz -C /

# Restart node
docker-compose up -d

# Verify recovery
curl http://localhost:3401/api/health
```

## 🚨 Emergency Procedures

### Node Becomes Unresponsive

1. **Check system resources**:
   ```bash
   docker stats node.omne.open
   docker exec node.omne.open top
   ```

2. **Check logs for errors**:
   ```bash
   docker-compose logs --tail=100 node.omne.open
   ```

3. **Restart services**:
   ```bash
   docker-compose restart node.omne.open
   ```

4. **Full reset if needed**:
   ```bash
   docker-compose down
   docker-compose up -d
   ```

### Consensus Participation Issues

1. **Check network connectivity**:
   ```bash
   curl http://localhost:3401/api/network/peers
   curl http://localhost:3401/api/consensus/status
   ```

2. **Verify configuration**:
   ```bash
   curl http://localhost:3401/api/config/validate
   ```

3. **Check blockchain sync status**:
   ```bash
   curl http://localhost:3401/api/blockchain/status
   ```

### Performance Degradation

1. **Monitor system metrics**:
   ```bash
   curl http://localhost:3401/api/performance/current
   ```

2. **Check for errors**:
   ```bash
   curl http://localhost:3401/api/errors/recent
   ```

3. **Optimize configuration**:
   - Reduce transaction pool size
   - Adjust consensus parameters
   - Consider switching storage backend

## 📈 Scaling and Optimization

### Performance Tuning

1. **Storage Optimization**:
   - Use SSD storage for better I/O performance
   - Consider MongoDB for high-throughput operations
   - Regular data directory cleanup

2. **Network Optimization**:
   - Ensure stable internet connection
   - Configure firewall rules for required ports
   - Use dedicated IP if possible

3. **Resource Allocation**:
   ```yaml
   # docker-compose.yml adjustments
   deploy:
     resources:
       limits:
         cpus: "4.0"      # Increase CPU allocation
         memory: "8G"     # Increase memory allocation
   ```

### Security Hardening

1. **Enable SSL/TLS**:
   ```bash
   export OMNE_ENABLE_SSL=true
   export OMNE_SSL_CERT_PATH=/path/to/certificate.crt
   export OMNE_SSL_KEY_PATH=/path/to/private.key
   ```

2. **Key Rotation**:
   ```bash
   # Keys are automatically rotated every 30 days
   # Manual rotation:
   curl -X POST http://localhost:3401/api/security/rotate-keys
   ```

3. **Access Control**:
   - Use firewall to restrict API access
   - Implement API authentication if needed
   - Monitor security logs regularly

## 📞 Support and Troubleshooting

### Common Issues

1. **"STEWARD_ADDRESS not set" Error**:
   - Ensure environment variable is properly set
   - Verify address format (must start with '0z' and be 42 characters)

2. **Network Connection Issues**:
   - Check firewall settings
   - Verify port availability
   - Ensure internet connectivity

3. **Storage Backend Errors**:
   - Verify data directory permissions
   - Check disk space availability
   - Consider switching to different backend

### Getting Help

1. **Check node logs**:
   ```bash
   docker-compose logs -f
   ```

2. **Generate diagnostic report**:
   ```bash
   curl http://localhost:3401/api/diagnostics/report > diagnostic_report.json
   ```

3. **Community Support**:
   - Join Omne Discord community
   - Submit issues to GitHub repository
   - Check documentation and FAQ

### Maintenance Schedule

#### Daily
- Check node health status
- Monitor consensus participation
- Review error logs
- Verify network connectivity

#### Weekly
- Analyze performance metrics
- Check security status
- Update configuration if needed
- Test backup procedures

#### Monthly
- Full system backup
- Performance optimization review
- Security audit
- Update documentation

---

*This runbook covers the essential operations for running a production-ready Open Omne Node. For additional support, consult the community documentation or reach out to the development team.*
