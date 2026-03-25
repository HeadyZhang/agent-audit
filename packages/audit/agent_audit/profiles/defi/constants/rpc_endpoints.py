"""RPC endpoint constants: public RPCs, MEV-protected RPCs."""

PUBLIC_RPC_DOMAINS = {
    'eth.llamarpc.com',
    'rpc.ankr.com',
    'ethereum.publicnode.com',
    '1rpc.io',
    'cloudflare-eth.com',
    'eth.drpc.org',
    'gateway.tenderly.co',
    'rpc.builder0x69.io',
    'virginia.rpc.blxrbdn.com',
    'rpc.payload.de',
    # BSC
    'bsc-dataseed.binance.org',
    'bsc-dataseed1.defibit.io',
    # Polygon
    'polygon-rpc.com',
    'rpc-mainnet.matic.network',
}

MEV_PROTECTED_RPC_DOMAINS = {
    'rpc.flashbots.net',
    'rpc.mevblocker.io',
    'mev-share.flashbots.net',
    'rpc.titanbuilder.xyz',
    'rsync-builder.xyz',
    'rpc.beaverbuild.org',
}

AUTHENTICATED_RPC_DOMAINS = {
    'infura.io',
    'alchemyapi.io', 'alchemy.com',
    'getblock.io',
    'moralis.io',
    'quicknode.com', 'quiknode.pro',
    'chainstack.com',
    'nodereal.io',
}
