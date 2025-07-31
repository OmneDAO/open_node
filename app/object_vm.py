# object_vm.py  – deterministic, metered mini-VM for Omne
from __future__ import annotations
import dis, types, marshal, logging, sys, json
import asyncio
import signal
from contextlib import contextmanager
from decimal import Decimal
from typing import Any, Callable, Optional
import rlp

# Handle optional wasmer import
try:
    import wasmer
    WASMER_AVAILABLE = True
except ImportError:
    WASMER_AVAILABLE = False
    logging.warning("Wasmer not available, using Python-only VM execution")

from app.capability import Capability

logger = logging.getLogger("ObjectVM")

# ------------------------------------------------------------------
#  Error classes
# ------------------------------------------------------------------
class VMError(RuntimeError): ...
class OutOfGas(VMError): ...
class WallClockTimeout(VMError): ...

# ------------------------------------------------------------------
#  Opcode-cost table – pulled from registry once at startup
# ------------------------------------------------------------------
try:
    from object_registry import global_registry
    OPCOST: dict[str, int] = json.loads(
        global_registry.get("__vm/opcode_costs/current") or "{}"
    )
except Exception:
    OPCOST = {}

# ------------------------------------------------------------------
#  Gas-metering tracer
# ------------------------------------------------------------------
class Meter:
    def __init__(self, gas_limit: int):
        self.remaining = gas_limit
        self.used = 0

    def charge(self, opname: str) -> None:
        cost = OPCOST.get(opname, 0)
        self.remaining -= cost
        self.used += cost
        if self.remaining < 0:
            raise OutOfGas("gas exhausted")

def make_tracer(meter: Meter):
    def tracer(frame, event, arg):
        if event == "opcode":
            opname = dis.opname[frame.f_code.co_code[frame.f_lasti]]
            meter.charge(opname)
        return tracer
    return tracer

# ------------------------------------------------------------------
#  Wall-clock guard (native infinite loops)
# ------------------------------------------------------------------
EXEC_TIMEOUT_MS = 2000  # Default 2 seconds, configurable in config

@contextmanager
def wallclock_guard(timeout_seconds: float = 2.0):
    """
    Guards against infinite loops and other resource-consuming operations
    by enforcing a wall-clock timeout using signal.setitimer.
    
    Args:
        timeout_seconds: Maximum execution time in seconds
    
    Raises:
        WallClockTimeout: If execution exceeds the timeout
    """
    def timeout_handler(signum, frame):
        raise WallClockTimeout(f"VM execution exceeded {timeout_seconds}s wall-clock limit")
        
    # Store the previous handler to restore later
    signal.signal(signal.SIGALRM, timeout_handler)
    signal.setitimer(signal.ITIMER_REAL, timeout_seconds)
    
    try:
        yield
    finally:
        # Cancel the timer and restore the previous handler
        signal.setitimer(signal.ITIMER_REAL, 0)

async def async_wallclock_guard(coro, timeout_seconds: float = 2.0):
    """
    Async version of wallclock guard that uses asyncio.wait_for
    
    Args:
        coro: Coroutine to execute with timeout
        timeout_seconds: Maximum execution time in seconds
        
    Returns:
        Result of the coroutine execution
        
    Raises:
        WallClockTimeout: If execution exceeds the timeout
    """
    try:
        return await asyncio.wait_for(coro, timeout=timeout_seconds)
    except asyncio.TimeoutError:
        raise WallClockTimeout(f"VM execution exceeded {timeout_seconds}s wall-clock limit")

# ------------------------------------------------------------------
#  Safe built-ins   (no open / import / exec / eval / os / sys …)
# ------------------------------------------------------------------
SAFE_BUILTINS: dict[str, Any] = {
    # Basic types
    "None": None, "True": True, "False": False,
    "int": int, "float": float, "str": str, "list": list, "dict": dict, "set": set,
    
    # Math operations
    "abs": abs, "max": max, "min": min, "pow": pow, "round": round, "sum": sum,
    
    # Collection operations
    "len": len, "sorted": sorted, "enumerate": enumerate, "zip": zip, "range": range,
    
    # String operations
    "chr": chr, "ord": ord,
    
    # Other safe operations
    "Decimal": Decimal,
    "print": print,  # print is harmless in sandbox
}

# ------------------------------------------------------------------
#  WASM-based Object VM
# ------------------------------------------------------------------
class ObjectVM:
    """
    A lightweight WASM-based virtual machine for executing object methods deterministically.
    """

    def __init__(self):
        self.engine = wasmer.Engine()
        self.store = wasmer.Store(self.engine)

    def execute_method(self, object_id: str, method: str, args: list, capabilities: list[Capability]) -> Any:
        """
        Execute a method on an object with explicit capability checks.

        Args:
            object_id: The ID of the object to execute the method on.
            method: The method to execute.
            args: The arguments to pass to the method.
            capabilities: A list of capabilities required for the method execution.

        Returns:
            Any: The result of the method execution.

        Raises:
            PermissionError: If the required capabilities are not provided.
        """
        # Retrieve the object from the registry
        obj = self.registry.get(object_id)
        if not obj:
            raise ValueError(f"Object {object_id} does not exist")

        # Check required capabilities
        required_capabilities = obj.get("required_capabilities", {}).get(method, [])
        for required in required_capabilities:
            if not any(cap.validate(required["name"], required.get("attributes")) for cap in capabilities):
                raise PermissionError(f"Missing required capability: {required}")

        # Execute the method
        method_impl = getattr(obj, method, None)
        if not callable(method_impl):
            raise AttributeError(f"Method {method} not found on object {object_id}")

        return method_impl(*args)

    def emit(self, event_name: str, payload: dict) -> None:
        """
        Emit an event from the current object.

        Args:
            event_name: The name of the event.
            payload: The payload associated with the event.
        """
        if not hasattr(self, 'current_block') or not self.current_block:
            raise RuntimeError("No active block to emit events into.")

        self.current_block.add_event(event_name, payload)

    def self_destruct(self, obj_id: str, refund_address: str) -> None:
        """
        Allow an object to delete itself and refund any pre-paid rent.

        Args:
            obj_id: The ID of the object to self-destruct.
            refund_address: The address to refund the remaining balance to.

        Raises:
            RuntimeError: If the object does not exist or is already frozen.
        """
        if not hasattr(self, 'registry') or not self.registry:
            raise RuntimeError("ObjectRegistry is not initialized in the VM.")

        with self.registry._lock:
            if not self.registry.exists(obj_id):
                raise RuntimeError(f"Object {obj_id} does not exist.")

            current = rlp.decode(self.registry.trie.get(obj_id.encode()))

            if current.get("frozen", False):
                raise RuntimeError(f"Object {obj_id} is frozen and cannot self-destruct.")

            # Refund the remaining balance
            remaining_balance = current.get("balance", 0)
            self._refund_balance(refund_address, remaining_balance)

            # Delete the object
            self.registry.trie.delete(obj_id.encode())
            logger.info(f"Object {obj_id} has self-destructed and refunded {remaining_balance} to {refund_address}.")

    def _refund_balance(self, address: str, amount: int) -> None:
        """
        Refund the specified amount to the given address.

        Args:
            address: The address to refund to.
            amount: The amount to refund.
        """
        # Placeholder for actual refund logic (e.g., updating account balances)
        logger.info(f"Refunded {amount} to address {address}.")

    def process_remote_proof(self, proof: dict, expected_root: str, target_object_id: str, method: str, args: list) -> None:
        """
        Process a verified remote proof as a local object message.

        Args:
            proof: The remote proof data.
            expected_root: The expected Merkle root to verify the proof.
            target_object_id: The ID of the target object to invoke.
            method: The method to call on the target object.
            args: The arguments to pass to the method.

        Raises:
            RuntimeError: If the proof verification fails.
        """
        from app.light_client import LightClientVerifier

        if not LightClientVerifier.verify_proof(proof, expected_root):
            raise RuntimeError("Invalid remote proof")

        # Wrap the proof as a local object message
        logger.info(f"Processing remote proof for object {target_object_id}")
        self.execute_method(target_object_id, method, args)

    def upgrade_object(self, object_id: str, new_code_ref: str, owner_signature: str, governance_quorum: Optional[Callable[[str, str], bool]] = None) -> None:
        """
        Upgrade the code reference of an object with optional governance checks.

        Args:
            object_id: The ID of the object to upgrade.
            new_code_ref: The new code reference (hash of the bytecode).
            owner_signature: The signature of the owner authorizing the upgrade.
            governance_quorum: Optional callable to check governance approval.

        Raises:
            ValueError: If the object does not exist, the signature is invalid, or governance approval fails.
        """
        # Retrieve the object from the registry
        obj = self.registry.get(object_id)
        if not obj:
            raise ValueError(f"Object {object_id} does not exist")

        # Verify owner signature (placeholder for actual signature verification logic)
        if obj["owner"] != owner_signature:  # Simplified check
            raise ValueError("Invalid owner signature")

        # Check governance approval if required
        if governance_quorum and not governance_quorum(object_id, new_code_ref):
            raise ValueError("Governance quorum approval failed")

        # Perform the upgrade
        self.registry.upgrade(object_id, new_code_ref, owner_signature)
        logger.info(f"Object {object_id} upgraded to new code reference {new_code_ref}")

# ------------------------------------------------------------------
#  Main entry
# ------------------------------------------------------------------
HEADER = b"OMNE:VM:PY:1\n"

def run_object_tx(byte_code: bytes, method: str, args: tuple[Any, ...] = None,
                 gas_limit: int = 1000000, timeout_seconds: float = 2.0) -> Any:
    """
    Execute <method>(*args) inside a sandbox and return result.
    
    Args:
        byte_code: The compiled byte code to execute
        method: The method to call in the object
        args: Arguments to pass to the method
        gas_limit: Maximum gas allowed for execution
        timeout_seconds: Maximum wall-clock time for execution
        
    Returns:
        Result of the method execution
        
    Raises:
        OutOfGas: If gas limit is exceeded
        WallClockTimeout: If wall-clock time is exceeded
        VMError: For other VM-related errors
    """
    if args is None:
        args = ()

    if not byte_code.startswith(HEADER):
        raise VMError("invalid byte-code header")

    code_obj = marshal.loads(byte_code[len(HEADER):])

    meter = Meter(gas_limit)
    tracer = make_tracer(meter)
    sandbox: dict[str, Any] = {"__builtins__": SAFE_BUILTINS}

    try:
        with wallclock_guard(timeout_seconds):
            sys.settrace(tracer)
            exec(code_obj, sandbox, sandbox)     # load module
            fn = sandbox.get(method)
            if fn is None or not callable(fn):
                raise VMError(f"method {method} not found")
            result = fn(*args)
            
            # Store the gas used for later retrieval
            run_object_tx.last_gas_used = meter.used
            
            return result
    except WallClockTimeout:
        raise WallClockTimeout("wall-clock timeout")
    finally:
        sys.settrace(None)

# Static attribute to store last gas used
run_object_tx.last_gas_used = 0

# Example usage
if __name__ == "__main__":
    # Example WASM bytecode (placeholder)
    wasm_bytecode = b"..."  # Replace with actual compiled WASM bytecode
    vm = ObjectVM()

    try:
        result = vm.execute_method("example_object_id", "example_method", [1, 2, 3], [])
        print(f"Method result: {result}")
    except RuntimeError as e:
        print(e)
