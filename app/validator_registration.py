#!/usr/bin/env python3
"""
validator_registration.py - Validator Registration and Network Join Process

This module handles the process for an open node to:
1. Connect to existing network via bootstrap nodes
2. Request to join as a validator through staking
3. Go through network verification process
4. Become an active validator in the OMNE network

This ensures open_node acts as a regular validator that joins existing networks
rather than creating genesis blocks or launching new networks.
"""

import logging
import requests
import time
import threading
from decimal import Decimal
from typing import List, Dict, Optional, Tuple
from datetime import datetime, timezone, timedelta

from config_manager import OpenNodeConfigManager
from staking import StakingMngr
from account_manager import AccountManager
from omc import OMC
from node import Node

logger = logging.getLogger('ValidatorRegistration')

class ValidatorRegistrationManager:
    """
    Manages the process of joining an existing OMNE network as a validator
    """
    
    def __init__(self, 
                 config_manager: OpenNodeConfigManager,
                 staking_manager: StakingMngr,
                 account_manager: AccountManager,
                 omc: OMC,
                 node: Node):
        self.config = config_manager
        self.staking_manager = staking_manager
        self.account_manager = account_manager
        self.omc = omc
        self.node = node
        
        # Network connection state
        self.bootstrap_nodes = []
        self.connected_peers = []
        self.network_info = {}
        self.registration_status = "disconnected"  # disconnected, connecting, pending, verified, active
        
        # Staking requirements
        self.minimum_stake_amount = Decimal('1000.0')  # Default minimum stake
        self.stake_lock_period = 30  # Days
        
        self.logger = logger
        self.logger.info("ValidatorRegistrationManager initialized")
    
    def parse_bootstrap_nodes(self) -> List[str]:
        """
        Parse bootstrap nodes from configuration
        Format: "http://node1.omne.io:3400,http://node2.omne.io:3400"
        """
        bootstrap_str = self.config.config.bootstrap_nodes
        if not bootstrap_str:
            return []
        
        nodes = []
        for node_url in bootstrap_str.split(','):
            node_url = node_url.strip()
            if node_url:
                # Ensure proper format
                if not node_url.startswith('http'):
                    node_url = f"http://{node_url}"
                if ':' not in node_url.split('://')[-1]:
                    node_url = f"{node_url}:3400"
                nodes.append(node_url)
        
        return nodes
    
    def connect_to_network(self) -> bool:
        """
        Connect to existing OMNE network via bootstrap nodes
        """
        self.logger.info("🔗 Attempting to connect to OMNE network...")
        self.registration_status = "connecting"
        
        self.bootstrap_nodes = self.parse_bootstrap_nodes()
        if not self.bootstrap_nodes:
            self.logger.error("❌ No bootstrap nodes configured. Cannot connect to network.")
            self.logger.info("💡 Set OMNE_BOOTSTRAP_NODES environment variable with comma-separated node URLs")
            return False
        
        self.logger.info(f"📡 Trying to connect to bootstrap nodes: {self.bootstrap_nodes}")
        
        # Try each bootstrap node
        for bootstrap_node in self.bootstrap_nodes:
            if self._connect_to_bootstrap_node(bootstrap_node):
                self.logger.info(f"✅ Successfully connected to network via {bootstrap_node}")
                return True
        
        self.logger.error("❌ Failed to connect to any bootstrap nodes")
        self.registration_status = "disconnected"
        return False
    
    def _connect_to_bootstrap_node(self, bootstrap_url: str) -> bool:
        """
        Attempt to connect to a specific bootstrap node
        """
        try:
            # First, check if the node is alive
            health_response = requests.get(f"{bootstrap_url}/api/health", timeout=10)
            if health_response.status_code != 200:
                self.logger.warning(f"⚠️  Bootstrap node {bootstrap_url} health check failed")
                return False
            
            # Get network information
            network_response = requests.get(f"{bootstrap_url}/api/network/info", timeout=10)
            if network_response.status_code == 200:
                self.network_info = network_response.json()
                self.logger.info(f"📋 Retrieved network info: {self.network_info.get('network_name', 'Unknown')}")
            
            # Get minimum staking requirements
            stake_response = requests.get(f"{bootstrap_url}/api/staking/requirements", timeout=10)
            if stake_response.status_code == 200:
                stake_info = stake_response.json()
                self.minimum_stake_amount = Decimal(str(stake_info.get('minimum_stake', self.minimum_stake_amount)))
                self.stake_lock_period = stake_info.get('lock_period_days', self.stake_lock_period)
                self.logger.info(f"💰 Minimum stake: {self.minimum_stake_amount} OMC, Lock period: {self.stake_lock_period} days")
            
            # Announce ourselves to the network
            node_info = {
                'address': self.node.address,
                'public_key': self.node.public_key,
                'url': f"http://{self.config.config.network_host}:{self.config.config.network_port}",
                'steward': self.config.config.steward_address,
                'version': self.node.version,
                'node_type': 'validator_candidate',
                'timestamp': datetime.now(timezone.utc).isoformat()
            }
            
            # Sign the announcement
            node_signature = self.node.sign_node_data(node_info)
            if node_signature:
                node_info['signature'] = node_signature
            
            announce_response = requests.post(
                f"{bootstrap_url}/api/network/announce", 
                json=node_info, 
                timeout=10
            )
            
            if announce_response.status_code == 200:
                response_data = announce_response.json()
                self.connected_peers.append(bootstrap_url)
                self.logger.info(f"✅ Successfully announced to network. Status: {response_data.get('status', 'unknown')}")
                return True
            else:
                self.logger.warning(f"⚠️  Failed to announce to {bootstrap_url}: {announce_response.status_code}")
                return False
                
        except requests.exceptions.RequestException as e:
            self.logger.warning(f"⚠️  Connection to {bootstrap_url} failed: {e}")
            return False
        except Exception as e:
            self.logger.error(f"❌ Unexpected error connecting to {bootstrap_url}: {e}")
            return False
    
    def request_validator_status(self) -> bool:
        """
        Request to become a validator by staking the required amount
        """
        if self.registration_status != "connecting":
            self.logger.error("❌ Must be connected to network before requesting validator status")
            return False
        
        self.logger.info("🏛️  Requesting validator status...")
        
        # Check if we have enough OMC to stake
        steward_balance = self.account_manager.get_account_balance(self.config.config.steward_address)
        if steward_balance is None or steward_balance < self.minimum_stake_amount:
            self.logger.error(f"❌ Insufficient OMC balance. Required: {self.minimum_stake_amount}, Available: {steward_balance}")
            self.logger.info("💡 Ensure your steward address has sufficient OMC tokens to stake")
            return False
        
        # Create staking agreement
        self.logger.info(f"💰 Staking {self.minimum_stake_amount} OMC for validator status...")
        staking_agreement = self.staking_manager.stake_coins(
            staker_address=self.config.config.steward_address,
            stake_amount=self.minimum_stake_amount,
            min_term_days=self.stake_lock_period,
            node_address=self.node.address
        )
        
        if not staking_agreement:
            self.logger.error("❌ Failed to create staking agreement")
            return False
        
        # Submit validator registration to network
        registration_data = {
            'node_address': self.node.address,
            'steward_address': self.config.config.steward_address,
            'stake_amount': str(self.minimum_stake_amount),
            'stake_contract_id': staking_agreement['contract_id'],
            'public_key': self.node.public_key,
            'node_url': f"http://{self.config.config.network_host}:{self.config.config.network_port}",
            'timestamp': datetime.now(timezone.utc).isoformat()
        }
        
        # Sign the registration
        registration_signature = self.node.sign_node_data(registration_data)
        if registration_signature:
            registration_data['signature'] = registration_signature
        
        # Submit to connected peers
        for peer_url in self.connected_peers:
            try:
                response = requests.post(
                    f"{peer_url}/api/validator/register",
                    json=registration_data,
                    timeout=15
                )
                
                if response.status_code == 200:
                    result = response.json()
                    self.registration_status = "pending"
                    self.logger.info(f"✅ Validator registration submitted successfully")
                    self.logger.info(f"📋 Registration ID: {result.get('registration_id')}")
                    self.logger.info(f"⏳ Status: {result.get('status')} - awaiting network verification")
                    return True
                else:
                    self.logger.warning(f"⚠️  Registration to {peer_url} failed: {response.status_code}")
                    
            except requests.exceptions.RequestException as e:
                self.logger.warning(f"⚠️  Failed to submit registration to {peer_url}: {e}")
        
        self.logger.error("❌ Failed to submit validator registration to any peer")
        return False
    
    def check_verification_status(self) -> str:
        """
        Check the verification status of our validator registration
        Returns: 'pending', 'verified', 'rejected', 'unknown'
        """
        if self.registration_status not in ['pending', 'verified']:
            return 'unknown'
        
        for peer_url in self.connected_peers:
            try:
                response = requests.get(
                    f"{peer_url}/api/validator/status/{self.node.address}",
                    timeout=10
                )
                
                if response.status_code == 200:
                    status_data = response.json()
                    status = status_data.get('status', 'unknown')
                    
                    if status == 'verified':
                        self.registration_status = "verified"
                        self.logger.info("✅ Validator registration verified by network!")
                        return 'verified'
                    elif status == 'rejected':
                        self.registration_status = "disconnected"
                        self.logger.error(f"❌ Validator registration rejected: {status_data.get('reason', 'Unknown reason')}")
                        return 'rejected'
                    else:
                        self.logger.info(f"⏳ Verification status: {status}")
                        return 'pending'
                        
            except requests.exceptions.RequestException as e:
                self.logger.warning(f"⚠️  Failed to check status with {peer_url}: {e}")
        
        return 'unknown'
    
    def start_validator_activities(self) -> bool:
        """
        Start participating in validator activities once verified
        """
        if self.registration_status != "verified":
            self.logger.error("❌ Cannot start validator activities - not yet verified")
            return False
        
        self.logger.info("🎯 Starting validator activities...")
        
        # Update node status to active validator
        self.registration_status = "active"
        
        # Start validator-specific background tasks
        self._start_validator_background_tasks()
        
        self.logger.info("✅ Validator activities started - now participating in consensus!")
        return True
    
    def _start_validator_background_tasks(self):
        """
        Start background tasks specific to validator nodes
        """
        # Start status monitoring thread
        status_thread = threading.Thread(target=self._validator_status_monitor, daemon=True)
        status_thread.start()
        
        # Start network health monitoring
        health_thread = threading.Thread(target=self._network_health_monitor, daemon=True)
        health_thread.start()
    
    def _validator_status_monitor(self):
        """
        Periodically check our validator status and report to network
        """
        while self.registration_status == "active":
            try:
                # Report our status to connected peers
                status_report = {
                    'node_address': self.node.address,
                    'status': 'active',
                    'last_block_height': getattr(self, 'last_known_block_height', 0),
                    'timestamp': datetime.now(timezone.utc).isoformat()
                }
                
                for peer_url in self.connected_peers:
                    try:
                        requests.post(
                            f"{peer_url}/api/validator/heartbeat",
                            json=status_report,
                            timeout=5
                        )
                    except:
                        pass  # Ignore individual failures
                
                time.sleep(60)  # Report every minute
                
            except Exception as e:
                self.logger.error(f"❌ Error in validator status monitor: {e}")
                time.sleep(60)
    
    def _network_health_monitor(self):
        """
        Monitor network health and connectivity
        """
        while self.registration_status == "active":
            try:
                # Check connectivity to peers
                healthy_peers = []
                for peer_url in self.connected_peers:
                    try:
                        response = requests.get(f"{peer_url}/api/health", timeout=5)
                        if response.status_code == 200:
                            healthy_peers.append(peer_url)
                    except:
                        pass
                
                # If we lose too many peers, try to reconnect
                if len(healthy_peers) < len(self.connected_peers) * 0.5:
                    self.logger.warning("⚠️  Lost connection to many peers, attempting to reconnect...")
                    # Could implement peer rediscovery here
                
                time.sleep(300)  # Check every 5 minutes
                
            except Exception as e:
                self.logger.error(f"❌ Error in network health monitor: {e}")
                time.sleep(300)
    
    def get_registration_status(self) -> Dict:
        """
        Get current registration and validation status
        """
        return {
            'status': self.registration_status,
            'node_address': self.node.address,
            'steward_address': self.config.config.steward_address,
            'connected_peers': len(self.connected_peers),
            'bootstrap_nodes': self.bootstrap_nodes,
            'minimum_stake': str(self.minimum_stake_amount),
            'network_info': self.network_info
        }

def initialize_validator_registration(config_manager, staking_manager, account_manager, omc, node) -> ValidatorRegistrationManager:
    """
    Initialize and start the validator registration process
    """
    registration_manager = ValidatorRegistrationManager(
        config_manager, staking_manager, account_manager, omc, node
    )
    
    # Start the registration process in a background thread
    def registration_flow():
        try:
            # Step 1: Connect to network
            if not registration_manager.connect_to_network():
                logger.error("❌ Failed to connect to network")
                return
            
            # Step 2: Request validator status
            if not registration_manager.request_validator_status():
                logger.error("❌ Failed to request validator status")
                return
            
            # Step 3: Wait for verification (with timeout)
            verification_attempts = 0
            max_attempts = 60  # 10 minutes at 10-second intervals
            
            while verification_attempts < max_attempts:
                status = registration_manager.check_verification_status()
                
                if status == 'verified':
                    # Step 4: Start validator activities
                    registration_manager.start_validator_activities()
                    break
                elif status == 'rejected':
                    logger.error("❌ Validator registration was rejected")
                    break
                else:
                    verification_attempts += 1
                    time.sleep(10)  # Wait 10 seconds before checking again
            
            if verification_attempts >= max_attempts:
                logger.error("⏰ Verification timeout - registration may have failed")
        
        except Exception as e:
            logger.error(f"❌ Error in validator registration flow: {e}")
    
    # Start registration in background
    registration_thread = threading.Thread(target=registration_flow, daemon=True)
    registration_thread.start()
    
    return registration_manager
