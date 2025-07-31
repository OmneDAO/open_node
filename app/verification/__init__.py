"""
Verification package for the Omne node.

This package contains modules for verifying transactions, blocks, and other
cryptographic operations in the Omne blockchain.
"""

from .transaction_verifier import TransactionVerifier

__all__ = ['TransactionVerifier'] 