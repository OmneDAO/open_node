#!/usr/bin/env python3
"""
validator_api.py - API endpoints for validator registration and management

Provides REST API endpoints for:
- Network announcements from new nodes
- Validator registration requests
- Validator status checking
- Network information sharing

These endpoints enable open nodes to join existing networks as validators
without creating genesis blocks or launching new networks.
"""

from flask import Blueprint, request, jsonify
import logging
from datetime import datetime, timezone
from decimal import Decimal
from typing import Dict, List, Optional

# This will be imported by network_manager.py
validator_api = Blueprint('validator_api', __name__)
logger = logging.getLogger('ValidatorAPI')

# Global reference to core components (set by network_manager)
ledger = None
omc = None
staking_manager = None
verifier = None
consensus_engine = None

def initialize_validator_api(ledger_ref, omc_ref, staking_ref, verifier_ref, consensus_ref):
    """Initialize API with references to core components"""
    global ledger, omc, staking_manager, verifier, consensus_engine
    ledger = ledger_ref
    omc = omc_ref
    staking_manager = staking_ref
    verifier = verifier_ref
    consensus_engine = consensus_ref
    logger.info("Validator API initialized")

@validator_api.route('/api/network/info', methods=['GET'])
def get_network_info():
    """
    Provide network information to connecting nodes
    """
    try:
        network_info = {
            'network_name': 'OMNE',
            'network_version': '1.0.0',
            'chain_id': getattr(ledger, 'chain_id', 1),
            'current_block_height': len(ledger.blocks) if ledger else 0,
            'total_validators': len(omc.get_active_validators()) if omc else 0,
            'network_status': 'active',
            'timestamp': datetime.now(timezone.utc).isoformat()
        }
        
        return jsonify(network_info), 200
    
    except Exception as e:
        logger.error(f"Error getting network info: {e}")
        return jsonify({'error': 'Failed to get network info'}), 500

@validator_api.route('/api/staking/requirements', methods=['GET'])
def get_staking_requirements():
    """
    Provide staking requirements for validator nodes
    """
    try:
        requirements = {
            'minimum_stake': '1000.0',  # Minimum OMC required to stake
            'lock_period_days': 30,     # Minimum staking period
            'max_validators': 100,      # Maximum number of validators
            'current_validators': len(omc.get_active_validators()) if omc else 0,
            'validator_rewards': {
                'block_reward': '10.0',
                'transaction_fees': 'shared',
                'annual_rate': '5.5%'
            },
            'requirements': [
                'Minimum 1000 OMC stake',
                '99.9% uptime requirement',
                'Valid node software version',
                'Proper network connectivity'
            ],
            'timestamp': datetime.now(timezone.utc).isoformat()
        }
        
        return jsonify(requirements), 200
    
    except Exception as e:
        logger.error(f"Error getting staking requirements: {e}")
        return jsonify({'error': 'Failed to get staking requirements'}), 500

@validator_api.route('/api/network/announce', methods=['POST'])
def announce_node():
    """
    Handle node announcements from new nodes wanting to join the network
    """
    try:
        data = request.get_json()
        if not data:
            return jsonify({'error': 'No data provided'}), 400
        
        # Validate required fields
        required_fields = ['address', 'public_key', 'url', 'steward', 'version']
        for field in required_fields:
            if field not in data:
                return jsonify({'error': f'Missing required field: {field}'}), 400
        
        # Verify signature if provided
        if 'signature' in data:
            # TODO: Implement signature verification
            pass
        
        # Check if node is already known
        node_address = data['address']
        existing_node = None
        if verifier and hasattr(verifier, 'nodes'):
            existing_node = next((n for n in verifier.nodes if n.get('address') == node_address), None)
        
        if existing_node:
            logger.info(f"Node {node_address} already known, updating information")
            existing_node.update(data)
        else:
            # Add new node to known nodes
            if verifier and hasattr(verifier, 'nodes'):
                new_node = {
                    'address': data['address'],
                    'public_key': data['public_key'],
                    'url': data['url'],
                    'steward': data['steward'],
                    'version': data['version'],
                    'node_type': data.get('node_type', 'unknown'),
                    'announced_at': datetime.now(timezone.utc).isoformat(),
                    'status': 'announced'
                }
                verifier.nodes.append(new_node)
                logger.info(f"Added new node announcement: {node_address}")
        
        response = {
            'status': 'announced',
            'message': 'Node announcement received successfully',
            'node_address': node_address,
            'next_steps': [
                'Submit validator registration if you want to become a validator',
                'Start syncing with the network',
                'Monitor network for consensus participation'
            ],
            'timestamp': datetime.now(timezone.utc).isoformat()
        }
        
        return jsonify(response), 200
    
    except Exception as e:
        logger.error(f"Error processing node announcement: {e}")
        return jsonify({'error': 'Failed to process announcement'}), 500

@validator_api.route('/api/validator/register', methods=['POST'])
def register_validator():
    """
    Handle validator registration requests
    """
    try:
        data = request.get_json()
        if not data:
            return jsonify({'error': 'No data provided'}), 400
        
        # Validate required fields
        required_fields = ['node_address', 'steward_address', 'stake_amount', 'public_key', 'node_url']
        for field in required_fields:
            if field not in data:
                return jsonify({'error': f'Missing required field: {field}'}), 400
        
        node_address = data['node_address']
        steward_address = data['steward_address']
        stake_amount = Decimal(data['stake_amount'])
        
        # Verify minimum stake amount
        minimum_stake = Decimal('1000.0')
        if stake_amount < minimum_stake:
            return jsonify({
                'error': f'Insufficient stake amount. Minimum: {minimum_stake}, Provided: {stake_amount}'
            }), 400
        
        # Check if validator is already registered
        if omc:
            active_validators = omc.get_active_validators()
            if any(v.get('address') == node_address for v in active_validators):
                return jsonify({'error': 'Node already registered as validator'}), 409
        
        # Create a registration record (in a real implementation, this would be stored)
        registration_id = f"reg_{int(datetime.now().timestamp())}_{node_address[-8:]}"
        
        registration_record = {
            'registration_id': registration_id,
            'node_address': node_address,
            'steward_address': steward_address,
            'stake_amount': str(stake_amount),
            'public_key': data['public_key'],
            'node_url': data['node_url'],
            'status': 'pending_verification',
            'submitted_at': datetime.now(timezone.utc).isoformat(),
            'verification_steps': [
                {'step': 'stake_verification', 'status': 'pending'},
                {'step': 'node_connectivity', 'status': 'pending'},
                {'step': 'software_verification', 'status': 'pending'},
                {'step': 'network_consensus', 'status': 'pending'}
            ]
        }
        
        # Store registration (in a real implementation, use persistent storage)
        if not hasattr(validator_api, 'pending_registrations'):
            validator_api.pending_registrations = {}
        validator_api.pending_registrations[registration_id] = registration_record
        
        # Start asynchronous verification process
        # In a real implementation, this would trigger background verification tasks
        
        logger.info(f"Validator registration submitted for {node_address}")
        
        response = {
            'status': 'submitted',
            'registration_id': registration_id,
            'message': 'Validator registration submitted successfully',
            'verification_process': 'Your registration is now under review by the network',
            'estimated_verification_time': '5-10 minutes',
            'next_steps': [
                'Monitor registration status using /api/validator/status/{node_address}',
                'Ensure your node remains online and accessible',
                'Wait for network consensus on your validator application'
            ],
            'timestamp': datetime.now(timezone.utc).isoformat()
        }
        
        return jsonify(response), 200
    
    except Exception as e:
        logger.error(f"Error processing validator registration: {e}")
        return jsonify({'error': 'Failed to process validator registration'}), 500

@validator_api.route('/api/validator/status/<node_address>', methods=['GET'])
def get_validator_status(node_address):
    """
    Check the status of a validator registration
    """
    try:
        # Find registration record
        registration_record = None
        if hasattr(validator_api, 'pending_registrations'):
            for reg_id, record in validator_api.pending_registrations.items():
                if record['node_address'] == node_address:
                    registration_record = record
                    break
        
        if not registration_record:
            # Check if already an active validator
            if omc:
                active_validators = omc.get_active_validators()
                if any(v.get('address') == node_address for v in active_validators):
                    return jsonify({
                        'status': 'active',
                        'message': 'Node is an active validator',
                        'timestamp': datetime.now(timezone.utc).isoformat()
                    }), 200
            
            return jsonify({'error': 'No registration found for this node address'}), 404
        
        # Simulate verification process (in real implementation, check actual verification status)
        current_time = datetime.now(timezone.utc)
        submitted_time = datetime.fromisoformat(registration_record['submitted_at'].replace('Z', '+00:00'))
        elapsed_minutes = (current_time - submitted_time).total_seconds() / 60
        
        # Mock verification progress based on elapsed time
        if elapsed_minutes > 10:
            # After 10 minutes, mark as verified
            registration_record['status'] = 'verified'
            for step in registration_record['verification_steps']:
                step['status'] = 'completed'
        elif elapsed_minutes > 5:
            # After 5 minutes, show partial verification
            registration_record['status'] = 'verifying'
            registration_record['verification_steps'][0]['status'] = 'completed'
            registration_record['verification_steps'][1]['status'] = 'completed'
        else:
            # Still pending
            registration_record['status'] = 'pending_verification'
        
        response = {
            'status': registration_record['status'],
            'registration_id': registration_record['registration_id'],
            'verification_steps': registration_record['verification_steps'],
            'message': {
                'pending_verification': 'Registration is being processed',
                'verifying': 'Verification in progress',
                'verified': 'Registration verified - you can now participate as a validator',
                'rejected': 'Registration was rejected'
            }.get(registration_record['status'], 'Unknown status'),
            'timestamp': datetime.now(timezone.utc).isoformat()
        }
        
        return jsonify(response), 200
    
    except Exception as e:
        logger.error(f"Error getting validator status: {e}")
        return jsonify({'error': 'Failed to get validator status'}), 500

@validator_api.route('/api/validator/heartbeat', methods=['POST'])
def validator_heartbeat():
    """
    Handle heartbeat from active validators
    """
    try:
        data = request.get_json()
        if not data or 'node_address' not in data:
            return jsonify({'error': 'Missing node address'}), 400
        
        node_address = data['node_address']
        
        # Update last seen timestamp for the validator
        # In a real implementation, this would update persistent storage
        logger.debug(f"Received heartbeat from validator {node_address}")
        
        return jsonify({
            'status': 'received',
            'timestamp': datetime.now(timezone.utc).isoformat()
        }), 200
    
    except Exception as e:
        logger.error(f"Error processing validator heartbeat: {e}")
        return jsonify({'error': 'Failed to process heartbeat'}), 500

@validator_api.route('/api/validators', methods=['GET'])
def list_validators():
    """
    List all active validators in the network
    """
    try:
        validators = []
        
        if omc:
            active_validators = omc.get_active_validators()
            for validator in active_validators:
                validators.append({
                    'address': validator.get('address'),
                    'stake_amount': str(validator.get('stake_amount', 0)),
                    'status': 'active',
                    'uptime': '99.9%',  # Mock data
                    'last_block_signed': validator.get('last_block_signed', 'N/A')
                })
        
        response = {
            'total_validators': len(validators),
            'validators': validators,
            'timestamp': datetime.now(timezone.utc).isoformat()
        }
        
        return jsonify(response), 200
    
    except Exception as e:
        logger.error(f"Error listing validators: {e}")
        return jsonify({'error': 'Failed to list validators'}), 500

@validator_api.route('/api/network/peers', methods=['GET'])
def get_network_peers():
    """
    Provide list of network peers for peer discovery
    """
    try:
        peers = []
        
        if verifier and hasattr(verifier, 'nodes'):
            for node in verifier.nodes:
                if node.get('status') in ['announced', 'active']:
                    peers.append({
                        'address': node.get('address'),
                        'url': node.get('url'),
                        'version': node.get('version'),
                        'type': node.get('node_type', 'unknown')
                    })
        
        response = {
            'peers': peers,
            'total_peers': len(peers),
            'timestamp': datetime.now(timezone.utc).isoformat()
        }
        
        return jsonify(response), 200
    
    except Exception as e:
        logger.error(f"Error getting network peers: {e}")
        return jsonify({'error': 'Failed to get network peers'}), 500
