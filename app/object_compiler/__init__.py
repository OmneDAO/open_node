"""
Object compiler for Omne blockchain.
Provides deterministic compilation of Python code into bytecode.
"""

import marshal
import hashlib
import ast
import sys
from typing import Tuple, Any

# Import gas measurement utilities
try:
    from ..object_vm import OPCOST
except ImportError:
    # Default opcode costs if not available
    OPCOST = {
        "LOAD_CONST": 1,
        "LOAD_NAME": 2,
        "LOAD_ATTR": 3,
        "STORE_NAME": 5,
        "STORE_ATTR": 5,
        "BINARY_ADD": 2,
        "BINARY_SUBTRACT": 2,
        "BINARY_MULTIPLY": 2,
        "BINARY_TRUE_DIVIDE": 5,
        "BINARY_MODULO": 5,
        "COMPARE_OP": 2,
        "LOAD_METHOD": 10,
        "CALL_METHOD": 10,
        "CALL_FUNCTION": 15,
        "BUILD_LIST": 10,
        "BUILD_DICT": 10,
        "BUILD_SET": 10,
    }

# The fixed header for Omne VM bytecode
HEADER = b"OMNE:VM:PY:1\n"


def canonical_compile(source_code: str) -> Tuple[bytes, str, int]:
    """
    Compile Python source code into deterministic bytecode.
    
    Args:
        source_code: The Python source code to compile
        
    Returns:
        tuple: (bytecode, code_hash, static_gas)
        - bytecode: The compiled bytecode with Omne VM header
        - code_hash: The SHA-256 hash of the bytecode
        - static_gas: The static gas cost based on code complexity
    """
    # Validate source code
    try:
        ast.parse(source_code)
    except SyntaxError as e:
        raise CompilerError(f"Syntax error in source code: {e}")

    # Compile to bytecode with deterministic flags
    try:
        code_obj = compile(
            source_code,
            filename="<object>",
            mode="exec",
            optimize=2,  # Use highest optimization level
            dont_inherit=True,
            flags=0,  # No special flags
        )
    except Exception as e:
        raise CompilerError(f"Compilation error: {e}")

    # Marshal the code object to bytes
    marshalled = marshal.dumps(code_obj)
    
    # Add header to the marshalled bytecode
    byte_code = HEADER + marshalled
    
    # Calculate hash of the bytecode
    code_hash = hashlib.sha256(byte_code).hexdigest()
    
    # Calculate static gas cost based on code complexity
    static_gas = calculate_static_gas(code_obj)
    
    return byte_code, code_hash, static_gas


def calculate_static_gas(code_obj) -> int:
    """
    Calculate the static gas cost based on code complexity.
    
    Args:
        code_obj: The compiled code object
        
    Returns:
        int: The static gas cost
    """
    # Base cost for any contract
    gas = 100
    
    # Add cost based on co_code length (bytecode size)
    gas += len(code_obj.co_code) * 2
    
    # Add cost for constants
    gas += len(code_obj.co_consts) * 5
    
    # Add cost for variable names
    gas += len(code_obj.co_names) * 3
    
    # Add cost for inner functions/classes
    for const in code_obj.co_consts:
        if hasattr(const, 'co_code'):
            gas += calculate_static_gas(const)
    
    return gas


class CompilerError(Exception):
    """Exception raised for errors in the compilation process."""
    pass