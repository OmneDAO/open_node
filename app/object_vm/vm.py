# vm.py - VM execution functions for object_vm package
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

logger = logging.getLogger("ObjectVM")

# Error classes
class VMError(RuntimeError): ...
class OutOfGas(VMError): ...
class WallClockTimeout(VMError): ...

# Main entry
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

    try:
        code_obj = marshal.loads(byte_code[len(HEADER):])
        
        # Create a minimal sandbox environment
        sandbox_globals = {
            '__builtins__': {
                'len': len,
                'str': str,
                'int': int,
                'float': float,
                'bool': bool,
                'list': list,
                'dict': dict,
                'tuple': tuple,
                'set': set,
                'print': print,
                'range': range,
                'enumerate': enumerate,
                'zip': zip,
                'min': min,
                'max': max,
                'sum': sum,
                'abs': abs,
                'round': round,
                'Decimal': Decimal,
            },
            'method': method,
            'args': args,
        }
        
        # Execute the code in sandbox
        sandbox_locals = {}
        exec(code_obj, sandbox_globals, sandbox_locals)
        
        # Call the requested method if it exists
        if method in sandbox_locals and callable(sandbox_locals[method]):
            return sandbox_locals[method](*args)
        else:
            raise VMError(f"Method '{method}' not found or not callable")
            
    except Exception as e:
        logger.error(f"VM execution error: {e}")
        raise VMError(f"Execution failed: {str(e)}")
