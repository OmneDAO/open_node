# accounts_routes.py

from flask import Blueprint, jsonify, request, current_app
from decimal import Decimal
import logging

accounts_bp = Blueprint('accounts_bp', __name__)
logger = logging.getLogger('AccountsRoutes')

@accounts_bp.route('/api/omc_balance', methods=['POST'])
def get_omc_balance():
    """
    Endpoint to check the balance of a wallet's OMC.
    Expects JSON: { "address": "0zUserAddress123" }
    """
    # Get the ledger from the current app context
    ledger = current_app.config.get('ledger')
    if not ledger:
        return jsonify({"error": "Ledger not available"}), 500
        
    try:
        data = request.get_json()
        address = data.get('address')
        if not address:
            return jsonify({"error": "Address not provided"}), 400

        balance = ledger.account_manager.get_account_balance(address)

        if balance is not None:
            response = {
                'message': 'Account balance retrieved successfully',
                'balance': str(balance),
                'balance_float': float(balance) / (10 ** ledger.omc.decimals)
            }
            return jsonify(response), 200
        else:
            return jsonify({"error": "Account not found"}), 404

    except Exception as e:
        return jsonify({"error": "Internal server error", "details": str(e)}), 500

@accounts_bp.route('/api/get_last_nonce', methods=['GET'])
def get_last_nonce():
    """
    Retrieves the last confirmed nonce for the given wallet address.
    Expects a query parameter 'address'.
    Returns JSON: { "nonce": <number> }
    """
    # Get the ledger from the current app context
    ledger = current_app.config.get('ledger')
    if not ledger:
        return jsonify({"error": "Ledger not available"}), 500
        
    address = request.args.get('address')
    if not address:
        return jsonify({"error": "Address not provided"}), 400

    # Retrieve the nonce from the account manager.
    nonce = 0
    try:
        nonce = ledger.account_manager.get_last_nonce(address)
    except Exception as e:
        return jsonify({"error": "Internal server error", "details": str(e)}), 500

    return jsonify({"nonce": nonce}), 200

@accounts_bp.route('/api/get_transactions_for_address', methods=['GET'])
def get_transactions_for_address():
    """
    Retrieves all transactions related to a given wallet address.
    This includes mined (on‑chain) transactions as well as pending transactions.
    """
    # Get the ledger from the current app context
    ledger = current_app.config.get('ledger')
    if not ledger:
        return jsonify({"error": "Ledger not available"}), 500
        
    wallet_address = request.args.get('address')
    if not wallet_address:
        return jsonify({"error": "Wallet address is required"}), 400

    address_transactions = {
        'mined_transactions': [],
        'pending_transactions': [],
        'cleaned_transactions': [],
        'verified_transactions': [],
        'confirmed_transactions': []
    }

    # --- Mined Transactions ---
    # Iterate over all blocks in the ledger's chain.
    # (Assumes that each block is either a dictionary or a Block instance with a to_dict() method.)
    if ledger is None:
        logger.error("Ledger not configured in Flask app context.")
        return jsonify({"error": "Server misconfiguration"}), 500

    # Keep track of transaction hashes to avoid duplicates
    mined_tx_hashes = set()

    for block in ledger.chain:
        if hasattr(block, "to_dict"):
            block_data = block.to_dict()
        else:
            block_data = block
        for tx in block_data.get('transactions', []):
            # Check if the wallet address is the sender or (if present) the recipient.
            if tx.get('sender') == wallet_address or tx.get('recipient') == wallet_address:
                tx_hash = tx.get('hash')
                if tx_hash and tx_hash not in mined_tx_hashes:
                    address_transactions['mined_transactions'].append(tx)
                    mined_tx_hashes.add(tx_hash)

    # --- Pending Transactions ---
    # Get pending transactions from the mempool
    mempool = ledger.mempool
    if mempool is not None and hasattr(mempool, "transactions"):
        # Use the get_transactions method to get all transactions
        pending = mempool.get_transactions()
        address_transactions['pending_transactions'] = [
            tx for tx in pending
            if (tx.get('sender') == wallet_address or tx.get('recipient') == wallet_address) and
            tx.get('hash') not in mined_tx_hashes  # Only include if not already mined
        ]
    else:
        logger.warning("Mempool not available or does not have transactions attribute.")
        address_transactions['pending_transactions'] = []

    # --- Verified/Confirmed/Cleaned Transactions ---
    # For now, if these lists are not implemented, return empty arrays.
    address_transactions['verified_transactions'] = []
    address_transactions['confirmed_transactions'] = []
    address_transactions['cleaned_transactions'] = []

    return jsonify(address_transactions), 200

@accounts_bp.route('/api/omc_info', methods=['GET'])
def omc_info():
    """
    Returns basic information about the Omne coin (OMC).
    """
    # Get the ledger from the current app context
    ledger = current_app.config.get('ledger')
    if not ledger:
        return jsonify({"error": "Ledger not available"}), 500
        
    if ledger is None or not hasattr(ledger, "omc"):
        logger.error("OMC not configured in ledger.")
        return jsonify({"error": "Server misconfiguration"}), 500

    coin_info = {
        'name': ledger.omc.name,
        'symbol': ledger.omc.symbol,
        'decimals': ledger.omc.decimals,
        'image': ledger.omc.image
    }
    return jsonify(coin_info), 200

@accounts_bp.route('/api/propagate_account', methods=['POST'])
async def propagate_account():
    """
    Propagates a new account to the network.
    Expects JSON with keys:
    "sender", "balance", "public_key", "signature", "timestamp", 
    "hash", "type", "nonce", "fee", "data"
    
    Returns:
    {
        "message": "Account propagated and added successfully.",
        "local_hash": "<mempool-local-hash>"
    }
    on success, or an error JSON on failure.
    """
    # Get the network manager from the current app context
    network_manager = current_app.config.get('network_manager')
    if not network_manager:
        return jsonify({"error": "Network manager not available"}), 500
        
    data = request.json
    sender = data.get('sender')
    balance = data.get('balance')
    public_key = data.get('public_key')
    signature = data.get('signature')
    fee = data.get('fee')
    tx_type = data.get('type')
    nonce = data.get('nonce')
    timestamp = data.get('timestamp')
    tx_hash = data.get('hash')

    data_field = data.get('data') or {}

    if not sender or balance is None:
        return jsonify({'error': "Missing 'sender' or 'balance' in request."}), 400

    # Convert balance to Decimal
    try:
        balance_decimal = Decimal(balance)
    except:
        return jsonify({'error': "Invalid balance format."}), 400

    # Check if account already exists
    if network_manager.account_manager.get_account_balance(sender) is not None:
        return jsonify({'message': 'Account already exists.'}), 200

    # Try adding account to ledger with the given balance
    success = network_manager.account_manager.add_account(sender, balance_decimal)
    if not success:
        return jsonify({'error': 'Failed to add account to ledger.'}), 500

    # Broadcast to local mempool + peers
    local_hash = await network_manager.broadcast_new_account(
        sender=sender,
        balance=str(balance_decimal),
        exclude_peer_url=None,
        public_key=public_key,
        signature=signature,
        timestamp=timestamp,
        tx_hash=tx_hash,  # user-provided hash, not used for verification
        type=tx_type,
        nonce=nonce,
        fee=fee,
        data=data_field
    )

    if local_hash:
        return jsonify({
            'message': 'Account propagated and added successfully.',
            'local_hash': local_hash
        }), 201
    else:
        return jsonify({'error': 'Failed to propagate account.'}), 500

@accounts_bp.route('/api/retrieve_accounts', methods=['GET'])
def retrieve_accounts():
    """
    Endpoint to retrieve all accounts, staking contracts, and node information.
    Now includes each address' sOMC balance as 'sOMC'.
    """
    # Get the ledger from the current app context
    ledger = current_app.config.get('ledger')
    if not ledger:
        return jsonify({"error": "Ledger not available"}), 500
        
    try:
        # 1) Handle pagination parameters
        page = int(request.args.get('page', 1))
        per_page = int(request.args.get('per_page', 100))

        # 2) Retrieve account balances from the ledger
        all_accounts = ledger.account_manager.get_all_accounts()  # => dict: address -> account dict
        account_items = list(all_accounts.items())  # => [ (address, account_dict), ... ]

        start = (page - 1) * per_page
        end = start + per_page
        paginated_list = account_items[start:end]

        # convert back to a dict
        paginated_accounts = dict(paginated_list)

        # 3) For each address in our paginated accounts, fetch sOMC from staked_omc
        for address, account_data in paginated_accounts.items():
            s_balance = ledger.staking_manager.staked_omc.get_balance(address)
            # If s_balance is None, it might not exist in staked_omc
            # We'll assume that means zero
            s_balance_str = str(s_balance) if s_balance is not None else "0"
            account_data["sOMC"] = s_balance_str

        # 4) Retrieve staking contracts with pagination
        all_staking = ledger.staking_manager.get_active_staking_agreements()
        staking_paginated = all_staking[start:end]

        # 5) Retrieve node info
        nodes = ledger.verifier.get_all_nodes()

        response_data = {
            'data': paginated_accounts,  # now each account has "sOMC": <string> included
            'staking_accounts': staking_paginated,
            'nodes': nodes,
            'pagination': {
                'page': page,
                'per_page': per_page,
                'total_accounts': len(all_accounts),
                'total_staking': len(all_staking)
            }
        }

        return jsonify(response_data), 200

    except Exception as e:
        logger.exception("Exception occurred while retrieving accounts.")
        return jsonify({"message": "Error retrieving accounts", "error": str(e)}), 500

@accounts_bp.route('/api/somc_balance', methods=['POST'])
def get_somc_balance():
    """
    Endpoint to check the sOMC balance of a given wallet address.
    Expects JSON: { "address": "0zUserAddress123" }
    """
    # Get the ledger from the current app context
    ledger = current_app.config.get('ledger')
    if not ledger:
        return jsonify({"error": "Ledger not available"}), 500
        
    try:
        data = request.get_json()
        if not data or "address" not in data:
            return jsonify({"error": "No 'address' provided"}), 400

        address = data["address"]
        logger.debug(f"Fetching sOMC balance for address: {address}")

        # Use staked_omc's get_balance
        s_balance = ledger.staking_manager.staked_omc.get_balance(address)
        if s_balance is None:
            # If an address isn't found in staked_omc, we consider it zero
            s_balance = 0

        # Return the integer-based sOMC plus a float version
        s_balance_str = str(s_balance)
        # If your staked_omc stores the raw integer scaled by decimals,
        # you might want to convert it like so:
        s_balance_float = float(s_balance) / (10 ** ledger.omc.decimals)

        response = {
            'message': 'sOMC balance retrieved successfully',
            'address': address,
            'balance': s_balance_str,
            'balance_float': s_balance_float
        }
        return jsonify(response), 200

    except Exception as e:
        logger.exception("Error in get_somc_balance endpoint.")
        return jsonify({"error": "Internal server error", "details": str(e)}), 500

@accounts_bp.route('/api/check_activity', methods=['POST'])
def check_activity():
    """
    Endpoint to check the activity of a wallet.
    Expects JSON: { "address": "0zUserAddress123" }
    """
    # Get the ledger from the current app context
    ledger = current_app.config.get('ledger')
    if not ledger:
        return jsonify({"error": "Ledger not available"}), 500
        
    try:
        data = request.get_json()
        address = data.get('address')
        if not address:
            return jsonify({"error": "Address not provided"}), 400

        logger.debug(f"Checking activity for address: {address}")

        # Initialize result dictionaries for each history type
        transfer_result = Decimal('0')
        minting_result = Decimal('0')
        burning_result = Decimal('0')

        # Check for the address in each history list and calculate the totals
        # Assuming OMC and StakedOMC maintain transfer_history, minting_history, burning_history

        # Transfer History
        for transfer in ledger.omc.transfer_history:
            from_address, to_address, amount = transfer
            if from_address == address:
                transfer_result -= Decimal(amount)
            if to_address == address:
                transfer_result += Decimal(amount)

        for transfer in ledger.staking_manager.staked_omc.transfer_history:
            from_address, to_address, amount = transfer
            if from_address == address:
                transfer_result -= Decimal(amount)
            if to_address == address:
                transfer_result += Decimal(amount)

        # Minting History
        for mint in ledger.omc.minting_history:
            to_address, amount = mint
            if to_address == address:
                minting_result += Decimal(amount)

        for mint in ledger.staking_manager.staked_omc.minting_history:
            to_address, amount = mint
            if to_address == address:
                minting_result += Decimal(amount)

        # Burning History
        for burn in ledger.omc.burning_history:
            amount = burn
            burning_result -= Decimal(amount)

        for burn in ledger.staking_manager.staked_omc.burning_history:
            amount = burn
            burning_result -= Decimal(amount)

        # Prepare the response
        response_data = {
            "address": address,
            "transfer_history": str(transfer_result),
            "minting_history": str(minting_result),
            "burning_history": str(burning_result)
        }

        logger.debug(f"Activity for {address}: {response_data}")

        return jsonify(response_data), 200

    except Exception as e:
        logger.exception("Error in check_activity endpoint.")
        return jsonify({"error": "Internal server error", "details": str(e)}), 500

@accounts_bp.route('/api/get_coin_economy', methods=['GET'])
def get_coin_economy():
    """
    Endpoint to retrieve coin economy data.
    """
    # Get the ledger from the current app context
    ledger = current_app.config.get('ledger')
    if not ledger:
        return jsonify({"error": "Ledger not available"}), 500
        
    try:
        logger.debug("Fetching coin economy data.")

        # Example economy data structure
        economy_data = {
            "total_coin_supply": str(ledger.omc.coin_max),
            "total_staked": str(ledger.staking_manager.get_total_staked()),
            "staked_omc_distributed": str(ledger.staking_manager.get_staked_omc_distributed()),
            "treasury_balance": str(ledger.omc.get_balance(ledger.omc.treasury_address))
        }

        logger.debug(f"Coin economy data: {economy_data}")

        return jsonify({
            "message": "Coin economy data retrieved successfully",
            "data": economy_data
        }), 200

    except Exception as e:
        logger.exception("Error in get_coin_economy endpoint.")
        return jsonify({"error": "Internal server error", "details": str(e)}), 500 