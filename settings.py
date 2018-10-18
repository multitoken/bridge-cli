NETWORK_CONFIG = {
    "ropsten": {
        "url": "https://ropsten.infura.io/",
        "chainId": 3,
        "peaceRelayAddress": "0x5f71cf391F4B3E7357FFF16aE20e96A379b03de6",
        "ethTokenAddress": "0x71c69af534CD9903Cf684be4118C9bCa079EBA63"
    },
    "rinkeby": {
        "url": "https://rinkeby.infura.io/",
        "chainId": 4,
        "peaceRelayAddress": "0x28e7e887Ed5485f7F1955Fc165a3334a7E8208DC",
        "ethLockingAddress": "0x32d9B7A8fD328509B12B73f620079353907779Da"
    }
}

DEFAULT_REQUEST_TIMEOUT = 15

BLOCKS_OFFSET = 10

PEACE_RELAY_ABI_PATH = 'contracts/peace_relay.abi'
ETH_LOCKING_ABI_PATH = 'contracts/eth_locking.abi'
ETH_TOKEN_ABI_PATH = 'contracts/eth_token.abi'

PRIVATE_KEY = ''
