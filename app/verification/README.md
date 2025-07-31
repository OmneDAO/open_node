# Transaction Verification

This directory contains modules for verifying transactions and other cryptographic operations in the Omne blockchain.

## TransactionVerifier

The `TransactionVerifier` class is responsible for verifying the integrity and authenticity of transactions in the Omne blockchain. It ensures that:

1. All required fields are present in the transaction
2. The transaction signature is valid
3. The transaction hash is correctly calculated

### Usage

```python
from verification.transaction_verifier import TransactionVerifier

# Verify a transaction
is_valid = TransactionVerifier.verify(transaction_dict)

# Calculate a transaction hash
transaction_hash = TransactionVerifier.calculate_hash(transaction_dict)
```

### Verification Process

The verification process consists of the following steps:

1. **Structure Validation**: Check that all required fields are present and correctly formatted
2. **Canonicalization**: Create a canonical string representation of the transaction
3. **Hash Calculation**: Calculate the transaction hash from the canonical string
4. **Signature Verification**: Verify the transaction signature using the public key

### Canonicalization

The canonicalization process ensures that the same transaction data always produces the same string representation, regardless of the order of fields or whitespace. This is crucial for consistent hash calculation and signature verification.

The canonicalization process:

1. Removes the `signature` and `hash` fields from the transaction
2. Sorts all keys alphabetically
3. Converts all values to strings in a consistent format
4. Handles nested data structures recursively
5. Joins all key-value pairs with a consistent separator

### Error Handling

The `TransactionVerifier` class includes comprehensive error handling to ensure that verification failures are properly logged and reported. This helps with debugging and security auditing. 