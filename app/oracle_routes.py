# oracle_routes.py - API routes for oracle integration

from flask import Blueprint, request, jsonify
import logging
from typing import Dict, Any

from oracle_integration import get_oracle_registry, get_security_validator
from smart_contracts import SmartContracts

logger = logging.getLogger(__name__)

def create_oracle_routes(smart_contract_manager: SmartContracts) -> Blueprint:
    """
    Create Flask blueprint for oracle-related API routes.
    
    Args:
        smart_contract_manager: SmartContracts instance
        
    Returns:
        Blueprint: Flask blueprint with oracle routes
    """
    
    oracle_bp = Blueprint('oracle', __name__, url_prefix='/api/oracle')

    @oracle_bp.route('/register', methods=['POST'])
    def register_oracle():
        """
        Register a trusted oracle for a smart contract.
        
        POST /api/oracle/register
        {
            "contract_id": "contract_123",
            "oracle_address": "0xOracle123...",
            "admin_signature": "signature",
            "admin_address": "0xAdmin123..."
        }
        """
        try:
            data = request.get_json()
            
            if not data:
                return jsonify({'error': 'No JSON data provided'}), 400
            
            required_fields = ['contract_id', 'oracle_address', 'admin_signature', 'admin_address']
            for field in required_fields:
                if field not in data:
                    return jsonify({'error': f'Missing required field: {field}'}), 400
            
            success = smart_contract_manager.register_oracle(
                data['contract_id'],
                data['oracle_address'],
                data['admin_signature'],
                data['admin_address']
            )
            
            if success:
                return jsonify({
                    'success': True,
                    'message': 'Oracle registered successfully',
                    'contract_id': data['contract_id'],
                    'oracle_address': data['oracle_address']
                })
            else:
                return jsonify({'error': 'Failed to register oracle'}), 500
                
        except Exception as e:
            logger.error(f"Oracle registration error: {e}")
            return jsonify({'error': str(e)}), 500

    @oracle_bp.route('/remove', methods=['POST'])
    def remove_oracle():
        """
        Remove a trusted oracle from a smart contract.
        
        POST /api/oracle/remove
        {
            "contract_id": "contract_123",
            "oracle_address": "0xOracle123...",
            "admin_signature": "signature"
        }
        """
        try:
            data = request.get_json()
            
            if not data:
                return jsonify({'error': 'No JSON data provided'}), 400
            
            required_fields = ['contract_id', 'oracle_address', 'admin_signature']
            for field in required_fields:
                if field not in data:
                    return jsonify({'error': f'Missing required field: {field}'}), 400
            
            success = smart_contract_manager.remove_oracle(
                data['contract_id'],
                data['oracle_address'],
                data['admin_signature']
            )
            
            if success:
                return jsonify({
                    'success': True,
                    'message': 'Oracle removed successfully',
                    'contract_id': data['contract_id'],
                    'oracle_address': data['oracle_address']
                })
            else:
                return jsonify({'error': 'Failed to remove oracle'}), 500
                
        except Exception as e:
            logger.error(f"Oracle removal error: {e}")
            return jsonify({'error': str(e)}), 500

    @oracle_bp.route('/response', methods=['POST'])
    def handle_oracle_response():
        """
        Handle incoming oracle response.
        
        POST /api/oracle/response
        {
            "contract_id": "contract_123",
            "oracle_address": "0xOracle123...",
            "request_id": "req_123",
            "result": { "risk_score": 85, "analysis": "high_risk" },
            "signature": "oracle_signature",
            "timestamp": "2025-07-28T10:30:00Z"
        }
        """
        try:
            data = request.get_json()
            
            if not data:
                return jsonify({'error': 'No JSON data provided'}), 400
            
            contract_id = data.get('contract_id')
            if not contract_id:
                return jsonify({'error': 'Missing contract_id'}), 400
            
            result = smart_contract_manager.handle_oracle_response(contract_id, data)
            
            if result.get('success'):
                return jsonify(result)
            else:
                return jsonify(result), 400
                
        except Exception as e:
            logger.error(f"Oracle response handling error: {e}")
            return jsonify({'error': str(e)}), 500

    @oracle_bp.route('/trusted/<contract_id>', methods=['GET'])
    def get_trusted_oracles(contract_id: str):
        """
        Get all trusted oracles for a contract.
        
        GET /api/oracle/trusted/contract_123
        """
        try:
            oracles = smart_contract_manager.get_trusted_oracles(contract_id)
            
            return jsonify({
                'contract_id': contract_id,
                'trusted_oracles': oracles,
                'count': len(oracles)
            })
            
        except Exception as e:
            logger.error(f"Get trusted oracles error: {e}")
            return jsonify({'error': str(e)}), 500

    @oracle_bp.route('/domain/register', methods=['POST'])
    def register_domain():
        """
        Register an allowed domain for contract HTTP requests.
        
        POST /api/oracle/domain/register
        {
            "contract_id": "contract_123",
            "domain": "api.blox.ai",
            "admin_signature": "signature"
        }
        """
        try:
            data = request.get_json()
            
            if not data:
                return jsonify({'error': 'No JSON data provided'}), 400
            
            required_fields = ['contract_id', 'domain', 'admin_signature']
            for field in required_fields:
                if field not in data:
                    return jsonify({'error': f'Missing required field: {field}'}), 400
            
            success = smart_contract_manager.register_oracle_domain(
                data['contract_id'],
                data['domain'],
                data['admin_signature']
            )
            
            if success:
                return jsonify({
                    'success': True,
                    'message': 'Domain registered successfully',
                    'contract_id': data['contract_id'],
                    'domain': data['domain']
                })
            else:
                return jsonify({'error': 'Failed to register domain'}), 500
                
        except Exception as e:
            logger.error(f"Domain registration error: {e}")
            return jsonify({'error': str(e)}), 500

    @oracle_bp.route('/request', methods=['POST'])
    def make_oracle_request():
        """
        Make a secure HTTP request for oracle integration.
        
        POST /api/oracle/request
        {
            "contract_id": "contract_123",
            "url": "https://api.blox.ai/analysis",
            "method": "POST",
            "data": { "merchant_id": "123" },
            "headers": { "Authorization": "Bearer token" }
        }
        """
        try:
            data = request.get_json()
            
            if not data:
                return jsonify({'error': 'No JSON data provided'}), 400
            
            required_fields = ['contract_id', 'url']
            for field in required_fields:
                if field not in data:
                    return jsonify({'error': f'Missing required field: {field}'}), 400
            
            result = smart_contract_manager.make_oracle_request(
                data['contract_id'],
                data['url'],
                data.get('method', 'GET'),
                data.get('data'),
                data.get('headers')
            )
            
            return jsonify(result)
            
        except Exception as e:
            logger.error(f"Oracle request error: {e}")
            return jsonify({'error': str(e)}), 500

    @oracle_bp.route('/health', methods=['GET'])
    def oracle_health():
        """
        Check oracle system health.
        
        GET /api/oracle/health
        """
        try:
            oracle_registry = get_oracle_registry()
            security_validator = get_security_validator()
            
            return jsonify({
                'status': 'healthy',
                'timestamp': 'datetime.now(timezone.utc).isoformat()',
                'components': {
                    'oracle_registry': 'active',
                    'security_validator': 'active',
                    'http_client': 'active'
                },
                'stats': {
                    'total_registered_oracles': len(oracle_registry.oracle_metadata),
                    'active_contracts': len(oracle_registry.trusted_oracles)
                }
            })
            
        except Exception as e:
            logger.error(f"Oracle health check error: {e}")
            return jsonify({'error': str(e)}), 500

    return oracle_bp
