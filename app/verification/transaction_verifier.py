from typing import Dict, Any, Optional
# ── stdlib ─────────────────────────────────────────────────────────
import hashlib, base64, logging, os
from datetime import datetime, timezone, timedelta
from ecdsa import VerifyingKey, SECP256k1, BadSignatureError, util
from decimal import Decimal
import json
from settings import CHAIN_ID

class DecimalEncoder(json.JSONEncoder):
    def default(self, obj):
        if isinstance(obj, Decimal):
            return str(obj)
        return super(DecimalEncoder, self).default(obj)

LOG = logging.getLogger(__name__)

# ------------------------------------------------------------------
# configurable security parameters
# ------------------------------------------------------------------
CHAIN_ID              = os.getenv("OMNE_CHAIN_ID", "omne‑devnet")  # ← Stage 2 ready
TIME_WINDOW_SECONDS   = int(os.getenv("TX_TIME_WINDOW_SEC", "300"))  # ±5 min

class TransactionVerifier:
    @staticmethod
    def verify(transaction: Dict[str, Any]) -> bool:
        """
        Verify a transaction's signature and enforce chain_id checks.
        
        Args:
            transaction: The transaction to verify
            
        Returns:
            bool: True if verification succeeds, False otherwise
        """
        try:
            # Enforce chain_id check
            tx_chain_id = transaction.get("chain_id", CHAIN_ID)
            if tx_chain_id != CHAIN_ID:
                logging.error(f"Transaction rejected: chain_id mismatch (expected={CHAIN_ID}, got={tx_chain_id})")
                return False

            # Validate transaction structure
            if not TransactionVerifier._validate_structure(transaction):
                logging.error("Transaction structure validation failed")
                return False

            # Get canonical string using consistent method
            canonical_str = TransactionVerifier._get_canonical_string(transaction)
            LOG.debug(f"[verify_transaction] canonical_str={canonical_str!r}")
            
            # Compute hash
            digest = hashlib.sha256(canonical_str.encode('utf-8')).digest()
            
            # Verify signature
            pub_key_hex = transaction['public_key']
            try:
                # Handle different public key formats
                if pub_key_hex.startswith(("02", "03")) and len(pub_key_hex) == 66:
                    # Compressed public key format (omne-forge default)
                    LOG.debug("compressed pub‑key detected")
                    pub_bytes = bytes.fromhex(pub_key_hex)
                    vk = VerifyingKey.from_string(
                        pub_bytes,
                        curve=SECP256k1,
                        validate_point=True,
                        encoding="compressed"
                    )
                elif pub_key_hex.startswith('04'):
                    # Uncompressed public key format with '04' prefix
                    logging.info("Detected uncompressed public key format with '04' prefix")
                    vk = VerifyingKey.from_string(
                        bytes.fromhex(pub_key_hex[2:]),
                        curve=SECP256k1,
                        validate_point=True
                    )
                else:
                    # Raw public key format without prefix
                    logging.info("Attempting to parse as raw public key bytes")
                    vk = VerifyingKey.from_string(
                        bytes.fromhex(pub_key_hex),
                        curve=SECP256k1,
                        validate_point=True
                    )
            except Exception as e:
                logging.error(f"Failed to parse public key: {e}")
                return False
            
            signature_der = base64.b64decode(transaction['signature'])
            LOG.debug(f"[verify_transaction] sig_len={len(signature_der)}")
            
            LOG.debug("verifying with verify_digest()")
            vk.verify_digest(
                signature_der,
                digest,
                sigdecode=util.sigdecode_der
            )
            LOG.debug("verify_digest() ok")
            return True
            
        except BadSignatureError:
            logging.warning("Bad signature detected during verification")
            return False
        except Exception as e:
            logging.error(f"Error during signature verification: {e}")
            return False

    @staticmethod
    def _get_canonical_string(tx: Dict[str, Any]) -> str:
        """Return the exact byte‑stream that must be signed / verified."""
        tx_copy = dict(tx)
        tx_copy.pop("signature", None)
        tx_copy.pop("hash",       None)
        tx_copy.setdefault("chain_id", CHAIN_ID)

        # stable ordering of nested structures
        canonical_obj = TransactionVerifier._canonicalize_nested(tx_copy)
        canonical_str = json.dumps(
            canonical_obj,
            sort_keys=True,
            separators=(",", ":")      # <- matches front‑end / SDK
        )

        if os.getenv("OMNE_DEBUG_CANON"):
            LOG.debug("backend‑canonical %s", canonical_str)

        return canonical_str

    @staticmethod
    def _canonicalize_nested(obj: Any) -> Any:
        """
        Canonicalize nested data structures.
        """
        if isinstance(obj, dict):
            return {k: TransactionVerifier._canonicalize_nested(v) for k, v in sorted(obj.items())}
        elif isinstance(obj, list):
            return [TransactionVerifier._canonicalize_nested(item) for item in obj]
        elif isinstance(obj, Decimal):
            return str(obj)
        else:
            return str(obj)

    @staticmethod
    def _validate_structure(transaction: Dict[str, Any]) -> bool:
        """
        Validate the transaction structure including flexible data.
        """
        # Define basic required fields for all transactions
        basic_required_fields = {'sender', 'fee', 'nonce', 'public_key', 
                         'timestamp', 'type', 'signature'}
        
        # Object create transactions have different requirements
        is_object_create = transaction.get('type') == 'object_create'
        # Account creation transactions have different requirements
        is_account_creation = transaction.get('type') == 'account_creation'
        
        # Define required fields based on transaction type
        if is_object_create:
            required_fields = basic_required_fields | {'class', 'gas_limit', 'gas_price'}
        elif is_account_creation:
            required_fields = basic_required_fields | {'balance', 'data'}
        else:
            # For normal transactions and transactions within blocks
            required_fields = basic_required_fields | {'balance', 'data', 'block_nonce'}
        
        # Check required fields
        missing_fields = [field for field in required_fields if field not in transaction]
        if missing_fields:
            logging.warning(f"Missing required fields in transaction: {missing_fields}")
            return False

        # Enforce numeric-string format for gas & fee
        for fld in ("fee", "gas_limit", "gas_price"):
            if fld in transaction:
                try:
                    Decimal(str(transaction[fld]))  # raises on bad format
                except Exception:
                    logging.warning(f"{fld} must be a numeric string")
                    return False

        # Validate data field is a dictionary - only for transactions that require it
        if 'data' in required_fields and not isinstance(transaction.get('data', {}), dict):
            logging.warning("Transaction data must be a dictionary")
            return False

        # Validate timestamp format
        try:
            timestamp = transaction.get('timestamp', '')
            if timestamp:
                tx_time = datetime.fromisoformat(timestamp.replace('Z', '+00:00'))
                # Use datetime.utcnow().replace(tzinfo=timezone.utc) to ensure proper UTC time
                now = datetime.utcnow().replace(tzinfo=timezone.utc)
                # Add debug logging to help troubleshoot
                if os.getenv("OMNE_DEBUG_CANON") or os.getenv("OMNE_DEBUG_TIME"):
                    logging.debug(f"Node current UTC time: {now.isoformat()}")
                    logging.debug(f"Transaction time: {tx_time.isoformat()}")
                    logging.debug(f"Time difference: {abs((now - tx_time).total_seconds())} seconds")
                if abs((now - tx_time).total_seconds()) > TIME_WINDOW_SECONDS:
                    logging.warning("Transaction timestamp outside ±%ss window", TIME_WINDOW_SECONDS)
                    return False
        except ValueError:
            logging.warning(f"Invalid timestamp format: {timestamp}")
            return False

        return True

    @staticmethod
    def calculate_hash(transaction: Dict[str, Any]) -> str:
        """
        Calculate the hash of a transaction using the same canonicalization method.
        """
        canonical_str = TransactionVerifier._get_canonical_string(transaction)
        return hashlib.sha256(canonical_str.encode('utf-8')).hexdigest()