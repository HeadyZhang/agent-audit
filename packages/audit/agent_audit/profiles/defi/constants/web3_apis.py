"""Web3.py / ethers.js / DeFi protocol API constants.

All Web3 interaction-related function names and variable name patterns
are centralized here. Other modules import from this file.
"""

# ============================================================
# 1. Private key consumer functions
# ============================================================

PRIVATE_KEY_CONSUMER_FUNCTIONS = {
    # eth-account
    'from_key', 'from_mnemonic',
    # web3.py signing
    'sign_transaction', 'sign_message', 'sign_typed_data',
    # web3.py middleware
    'SignAndSendRawMiddlewareBuilder.build',
    'construct_sign_and_send_raw_middleware',
    # direct construction
    'Account.from_key', 'Account.from_mnemonic',
    'Account.decrypt',
}

PRIVATE_KEY_VARIABLE_PATTERNS = [
    r'private[_-]?key', r'priv[_-]?key', r'signing[_-]?key',
    r'secret[_-]?key', r'wallet[_-]?key', r'deployer[_-]?key',
    r'eth[_-]?key', r'account[_-]?key', r'owner[_-]?key',
    r'signer[_-]?key', r'hot[_-]?wallet[_-]?key',
]

# ============================================================
# 2. On-chain transaction API (sink functions)
# ============================================================

TRANSACTION_SEND_FUNCTIONS = {
    'send_transaction', 'send_raw_transaction',
    'sendTransaction', 'sendRawTransaction',
}

CONTRACT_TRANSACT_FUNCTIONS = {
    'transact',
    'build_transaction',
    'buildTransaction',
}

DEFI_FUND_TRANSFER_FUNCTIONS = {
    # ERC-20
    'transfer', 'transferFrom', 'approve',
    # Uniswap V2 Router
    'swapExactTokensForETH', 'swapExactETHForTokens',
    'swapExactTokensForTokens', 'swapTokensForExactTokens',
    'swapTokensForExactETH', 'swapETHForExactTokens',
    'addLiquidity', 'addLiquidityETH',
    'removeLiquidity', 'removeLiquidityETH',
    # Uniswap V3
    'exactInputSingle', 'exactInput',
    'exactOutputSingle', 'exactOutput',
    # Generic DeFi
    'deposit', 'withdraw', 'stake', 'unstake',
    'borrow', 'repay', 'liquidate',
    'mint', 'burn', 'redeem',
    'swap', 'exchange',
}

SWAP_FUNCTIONS_WITH_SLIPPAGE_PARAM = {
    'swapExactTokensForETH',
    'swapExactETHForTokens',
    'swapExactTokensForTokens',
    'swapTokensForExactTokens',
    'swapTokensForExactETH',
    'swapETHForExactTokens',
}

# ============================================================
# 3. RPC Provider constructors
# ============================================================

WEB3_PROVIDER_CONSTRUCTORS = {
    'HTTPProvider', 'WebsocketProvider',
    'IPCProvider', 'AsyncHTTPProvider',
    'JsonRpcProvider', 'WebSocketProvider',
    'InfuraProvider', 'AlchemyProvider',
}

# ============================================================
# 4. Amount/value variable names
# ============================================================

AMOUNT_VARIABLE_NAMES = {
    'amount', 'value', 'tx_value', 'transfer_amount',
    'wei', 'ether', 'token_amount', 'quantity',
    'amountIn', 'amountOut', 'amountOutMin', 'amountInMax',
    'deposit_amount', 'withdraw_amount', 'stake_amount',
    'trade_amount', 'swap_amount', 'send_amount',
}

# ============================================================
# 5. Human approval function name patterns
# ============================================================

HUMAN_APPROVAL_FUNCTION_PATTERNS = [
    r'approve', r'approval', r'confirm', r'confirmation',
    r'authorize', r'authorization', r'review',
    r'human_in_loop', r'human_approval', r'manual_review',
    r'request_approval', r'await_confirmation',
    r'require_signature', r'multi_sig',
]
