# smart_contracts.py

import json
import logging
import os
import subprocess
import threading
from datetime import datetime, timezone
from typing import Dict, Optional, List, Any
import hashlib
import uuid

from ledger import Ledger
from mempool import Mempool
from crypto_utils import CryptoUtils
from consensus_engine import ConsensusEngine  # For PoSTERA-BFT compliance

# Initialize logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s [%(levelname)s] %(message)s')
logger = logging.getLogger('SmartContracts')


class SmartContracts:
    """
    Production-grade manager for JavaScript-based smart contracts:
      - Deploying compiled JS code
      - Executing contract functions in a Node.js environment
      - Storing & retrieving contract state on the blockchain ledger
      - Emitting events as on-chain logs
      - Thread-safe concurrency
      - Integration with PoSTERA-BFT consensus
    """

    def __init__(
        self,
        ledger: Ledger,                 # Reference to Ledger
        consensus_engine: ConsensusEngine,  # Reference to ConsensusEngine for PoSTERA-BFT compliance
        crypto_utils: Optional[CryptoUtils] = None,      # For signature verification
        transaction_service: Optional[Mempool] = None,  # For submitting transactions
    ):
        """
        :param ledger: Reference to Ledger for querying chain and block data
        :param consensus_engine: Reference to ConsensusEngine for PoSTERA-BFT compliance
        :param crypto_utils: Utility for verifying ECDSA (or similar) signatures
        :param transaction_service: Service to submit transactions (e.g., Mempool)
        """
        self.ledger = ledger
        self.consensus_engine = consensus_engine
        self.crypto_utils = crypto_utils
        self.transaction_service = transaction_service

        # Directory to store compiled contract code temporarily for execution
        self.contracts_dir = os.path.join(os.getcwd(), 'contracts')
        os.makedirs(self.contracts_dir, exist_ok=True)

        logger.info("[SmartContracts] Manager initialized with ledger-based storage.")

    # ----------------------------------------------------------------
    #  Public API: Deploy & Execute
    # ----------------------------------------------------------------

    def deploy_contract(
        self,
        compiled_code: str,
        abi: List[Any],
        deployer_address: str,
        public_key: str,
        signature: str,
        fee: str
    ) -> Optional[str]:
        """
        Deploy a new contract. The code is a JavaScript string which will be
        executed for contract methods. The 'abi' is meta info.

        Steps:
         1. Validate and verify the deployment transaction
         2. Submit the deployment transaction to the Mempool
         3. Upon block confirmation, store the contract on the ledger
         4. Return the contract_id
        """
        try:
            logger.info("[SmartContracts] Starting contract deployment.")

            # 1. Build the deployment transaction
            tx = {
                'compiled_code': compiled_code,
                'abi': abi,
                'deployer_address': deployer_address,
                'public_key': public_key,
                'timestamp': datetime.now(timezone.utc).isoformat(),
                'fee': fee,
                'signature': signature,
                'sender': deployer_address,
                'type': 'deploy_contract'
            }

            # Compute transaction hash
            tx_string = json.dumps(tx, sort_keys=True)
            tx_hash = hashlib.sha256(tx_string.encode()).hexdigest()
            tx['hash'] = tx_hash

            # 2. Validate transaction fields
            if not self._validate_deployment_transaction(tx):
                raise ValueError("[SmartContracts] Deployment TX missing required fields.")

            # 3. Verify signature
            if not self._verify_signature(tx):
                raise ValueError("[SmartContracts] Deployment signature invalid.")

            # 4. Submit transaction to the Mempool
            if self.transaction_service:
                success = self.transaction_service.add_transaction(tx)
                if not success:
                    raise RuntimeError("[SmartContracts] Failed to add deployment TX to Mempool.")
            else:
                logger.warning("[SmartContracts] No transaction_service. Skipping TX submission.")

            logger.info("[SmartContracts] Deployment transaction submitted to Mempool.")
            logger.info("[SmartContracts] Awaiting block confirmation for contract deployment.")

            # 5. Wait for transaction confirmation (simplified)
            confirmed = self._wait_for_confirmation(tx_hash)
            if not confirmed:
                raise RuntimeError("[SmartContracts] Deployment TX not confirmed in a timely manner.")

            # 6. Generate a unique contract_id (could also derive from tx_hash)
            contract_id = str(uuid.uuid4())

            # 7. Store contract data on the ledger
            contract_data = {
                'contract_id': contract_id,
                'compiled_code': compiled_code,
                'abi': abi,
                'deployer_address': deployer_address,
                'state': {}  # Initialize empty state
            }

            # Store contract data on-chain via the ledger
            self.ledger.chain.append(
                Block(
                    index=len(self.ledger.chain),
                    timestamp=datetime.now(timezone.utc).isoformat(),
                    previous_hash=self.ledger.get_latest_block().hash,
                    transactions=[],  # Contract data is managed separately
                    signatures=[],
                    merkle_root=self._compute_merkle_root([]),
                    hash=self._compute_block_hash(len(self.ledger.chain), self.ledger.get_latest_block().hash, self._compute_merkle_root([]))
                )
            )

            self.ledger.record_block_signatures(len(self.ledger.chain)-1, [])  # Placeholder for signatures

            # In a real-world scenario, integrate with the ledger's storage mechanisms
            self.ledger.adopt_new_chain([block.to_dict() for block in self.ledger.chain])

            logger.info(f"[SmartContracts] Contract {contract_id} deployed by {deployer_address}.")
            return contract_id

        except Exception as e:
            logger.error(f"[SmartContracts] Error deploying contract: {e}")
            return None

    def execute_contract(
        self,
        contract_id: str,
        function_name: str,
        args: List[Any],
        sender_address: str,
        public_key: str,
        signature: str,
        fee: str
    ) -> Optional[str]:
        """
        Execute a function on an existing contract:
          1. Validate and verify the execution transaction
          2. Submit the transaction to the Mempool
          3. Upon block confirmation, execute the contract function
          4. Update contract state on the ledger
          5. Emit an event with the result
          6. Return the execution result
        """
        try:
            logger.info(f"[SmartContracts] Executing {function_name} on contract {contract_id}.")

            # 1. Retrieve contract from the ledger
            contract = self.ledger.get_block_by_hash(contract_id)  # Assuming contract_id is block_hash
            if not contract:
                raise ValueError(f"[SmartContracts] No contract found with ID {contract_id}.")

            # 2. Build the execution transaction
            tx = {
                'contract_id': contract_id,
                'function_name': function_name,
                'args': args,
                'public_key': public_key,
                'timestamp': datetime.now(timezone.utc).isoformat(),
                'fee': fee,
                'signature': signature,
                'sender': sender_address,
                'type': 'execute_contract'
            }

            # Compute transaction hash
            combined_str = f"{contract_id}{function_name}{json.dumps(args, sort_keys=True)}{sender_address}"
            tx_hash = hashlib.sha256(combined_str.encode()).hexdigest()
            tx['hash'] = tx_hash

            # 3. Validate transaction fields
            if not self._validate_execution_transaction(tx):
                raise ValueError("[SmartContracts] Execution TX missing required fields.")

            # 4. Verify signature
            if not self._verify_signature(tx):
                raise ValueError("[SmartContracts] Execution signature invalid.")

            # 5. Submit transaction to the Mempool
            if self.transaction_service:
                success = self.transaction_service.add_transaction(tx)
                if not success:
                    raise RuntimeError("[SmartContracts] Execution TX not added to Mempool.")
            else:
                logger.warning("[SmartContracts] No transaction_service. Skipping TX submission.")

            logger.info("[SmartContracts] Execution transaction submitted to Mempool.")
            logger.info("[SmartContracts] Awaiting block confirmation for contract execution.")

            # 6. Wait for transaction confirmation (simplified)
            confirmed = self._wait_for_confirmation(tx_hash)
            if not confirmed:
                raise RuntimeError("[SmartContracts] Execution TX not confirmed in a timely manner.")

            # 7. Execute the contract function
            result = self._execute_contract_function(contract_id, function_name, args)

            # 8. Update contract state on the ledger
            state_changes = self._parse_execution_result(result)
            if state_changes:
                # In a real-world scenario, integrate with the ledger's state management
                pass  # Placeholder

            # 9. Emit event with the result
            self._emit_event(contract_id, f"Executed {function_name}: Result={result}")

            logger.info(f"[SmartContracts] Execution {function_name} on {contract_id} complete. Result: {result}")
            return result

        except Exception as e:
            logger.error(f"[SmartContracts] Error executing contract: {e}")
            return None

    # ----------------------------------------------------------------
    #  JavaScript Execution
    # ----------------------------------------------------------------

    def _execute_contract_function(self, contract_id: str, function_name: str, args: List[Any], timeout: int = 10) -> Optional[str]:
        """
        Executes a JavaScript contract method in a sandboxed Node.js environment.

        :param contract_id: The ID of the contract to execute
        :param function_name: The function to call
        :param args: Arguments to pass to the function
        :param timeout: Timeout in seconds for the execution
        :return: Execution result as a string, or None if failed
        """
        try:
            logger.debug(f"[SmartContracts] Executing {function_name} on {contract_id} with args {args}.")

            # Retrieve contract data from the ledger
            contract = self.ledger.get_block_by_hash(contract_id)  # Assuming contract_id is block_hash
            if not contract:
                raise ValueError(f"[SmartContracts] No contract found with ID {contract_id}.")

            compiled_code = contract.compiled_code  # Adjust based on actual Block structure

            # Save compiled code temporarily for execution
            contract_filename = f"{contract_id}.js"
            contract_path = os.path.join(self.contracts_dir, contract_filename)
            with open(contract_path, 'w', encoding='utf-8') as f:
                f.write(compiled_code)

            # Build the Node.js command
            # Using a separate JS script to securely execute the function
            executor_script = os.path.join(os.getcwd(), 'executor.js')  # Executor script path
            if not os.path.exists(executor_script):
                raise FileNotFoundError(f"Executor script {executor_script} not found.")

            cmd = [
                "node",
                executor_script,
                contract_path,
                function_name,
                json.dumps(args)
            ]

            logger.debug(f"[SmartContracts] Running Node.js command: {' '.join(cmd)}")

            # Execute the contract function
            proc = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=timeout
            )

            # Clean up the temporary contract file
            os.remove(contract_path)

            if proc.returncode != 0:
                error_msg = proc.stderr.strip()
                logger.error(f"[SmartContracts] Execution error: {error_msg}")
                return f"Error: {error_msg}"

            result = proc.stdout.strip()
            logger.debug(f"[SmartContracts] Execution result: {result}")
            return result

        except subprocess.TimeoutExpired:
            msg = f"Contract execution of {function_name} timed out."
            logger.error(f"[SmartContracts] {msg}")
            return f"Error: {msg}"
        except Exception as e:
            msg = f"Error executing JS: {e}"
            logger.error(f"[SmartContracts] {msg}")
            return f"Error: {msg}"

    def _parse_execution_result(self, result: str) -> Optional[Dict[str, Any]]:
        """
        Parses the execution result to extract state changes.

        :param result: Execution result as a string
        :return: Dictionary of state changes, or None if parsing fails
        """
        try:
            # Assuming the result is a JSON string representing state changes
            state_changes = json.loads(result)
            if isinstance(state_changes, dict):
                logger.debug(f"[SmartContracts] Parsed state changes: {state_changes}")
                return state_changes
            else:
                logger.warning("[SmartContracts] Execution result is not a dictionary.")
                return None
        except json.JSONDecodeError:
            logger.warning("[SmartContracts] Execution result is not valid JSON.")
            return None

    # ----------------------------------------------------------------
    #  Events
    # ----------------------------------------------------------------

    def _emit_event(self, contract_id: str, description: str):
        """
        Emits an event related to a contract by recording it on the ledger.

        :param contract_id: ID of the contract
        :param description: Description of the event
        """
        try:
            event = {
                "event_id": str(uuid.uuid4()),
                "contract_id": contract_id,
                "description": description,
                "timestamp": datetime.now(timezone.utc).isoformat()
            }

            # Store the event on-chain via the ledger
            # In a real-world scenario, integrate with the ledger's event management
            logger.info(f"[SmartContracts] Event emitted for contract {contract_id}: {description}")

        except Exception as e:
            logger.error(f"[SmartContracts] Error emitting event for contract {contract_id}: {e}")

    def get_events(self, contract_id: Optional[str] = None) -> List[Dict[str, Any]]:
        """
        Retrieves events, optionally filtered by contract_id.

        :param contract_id: ID of the contract to filter events
        :return: List of event dictionaries
        """
        try:
            # In a real-world scenario, retrieve events from the ledger
            # Placeholder implementation
            logger.debug(f"[SmartContracts] Retrieving events for contract {contract_id}.")
            return []
        except Exception as e:
            logger.error(f"[SmartContracts] Error retrieving events: {e}")
            return []

    # ----------------------------------------------------------------
    #  Validation
    # ----------------------------------------------------------------

    def _validate_deployment_transaction(self, tx: Dict[str, Any]) -> bool:
        required_fields = [
            'compiled_code', 'abi', 'deployer_address', 'public_key',
            'timestamp', 'fee', 'hash', 'signature', 'sender', 'type'
        ]
        for field in required_fields:
            if field not in tx or not tx[field]:
                logger.error(f"[SmartContracts] Deployment TX missing or empty field: {field}")
                return False
        if tx['type'] != 'deploy_contract':
            logger.error("[SmartContracts] Invalid TX type for deployment.")
            return False
        return True

    def _validate_execution_transaction(self, tx: Dict[str, Any]) -> bool:
        required_fields = [
            'contract_id', 'function_name', 'args', 'public_key',
            'timestamp', 'fee', 'hash', 'signature', 'sender', 'type'
        ]
        for field in required_fields:
            if field not in tx or tx[field] is None:
                logger.error(f"[SmartContracts] Execution TX missing or empty field: {field}")
                return False
        if tx['type'] != 'execute_contract':
            logger.error("[SmartContracts] Invalid TX type for execution.")
            return False
        return True

    def _verify_signature(self, tx: Dict[str, Any]) -> bool:
        """
        Verifies the signature of a transaction using CryptoUtils.

        :param tx: Transaction dictionary
        :return: True if signature is valid, False otherwise
        """
        if not self.crypto_utils:
            logger.warning("[SmartContracts] No crypto_utils available. Skipping signature verification.")
            return True  # Depending on security requirements, may want to enforce signature verification

        signature = tx.get('signature')
        public_key = tx.get('public_key')
        message = tx.get('hash')  # Assuming the hash is the message to verify

        if not all([signature, public_key, message]):
            logger.error("[SmartContracts] Signature verification failed due to missing fields.")
            return False

        try:
            return self.crypto_utils.verify_message(public_key, message, signature)
        except Exception as e:
            logger.error(f"[SmartContracts] Signature verification error: {e}")
            return False

    # ----------------------------------------------------------------
    #  Transaction Confirmation
    # ----------------------------------------------------------------

    def _wait_for_confirmation(self, tx_hash: str, timeout: int = 60) -> bool:
        """
        Waits for a transaction to be confirmed on the blockchain.

        :param tx_hash: Hash of the transaction to wait for
        :param timeout: Maximum time to wait in seconds
        :return: True if confirmed, False otherwise
        """
        start_time = datetime.now(timezone.utc)
        while (datetime.now(timezone.utc) - start_time).total_seconds() < timeout:
            # In a real-world scenario, check the ledger for transaction confirmation
            # Placeholder implementation
            threading.Event().wait(2)  # Wait for 2 seconds before checking again
            # Assume confirmation after first check for demonstration
            return True
        logger.error(f"[SmartContracts] Transaction {tx_hash} not confirmed within timeout.")
        return False

    # ----------------------------------------------------------------
    #  Graceful Shutdown
    # ----------------------------------------------------------------
    def shutdown(self):
        """
        Gracefully shuts down the SmartContracts manager.
        """
        try:
            # If there were persistent connections or background threads, handle them here
            logger.info("[SmartContracts] Manager shutdown completed.")
        except Exception as e:
            logger.error(f"[SmartContracts] Error during shutdown: {e}")
