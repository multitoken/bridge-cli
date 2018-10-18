import argparse
import json
import logging
import time

import rlp
from eth_utils import encode_hex
from ethereum.utils import bytes_to_int, privtoaddr
from web3 import Web3, HTTPProvider
from web3.middleware import geth_poa_middleware

import merkle_proof
import settings

logging.basicConfig(level=logging.INFO, format='%(message)s')
logger = logging.getLogger(__name__)


def get_args():
    parser = argparse.ArgumentParser(
        description="Relay CLI",
        formatter_class=argparse.RawTextHelpFormatter)
    parser.add_argument('--source', required=True, type=str, help="Network to relay blocks from")
    parser.add_argument('--dest', required=True, type=str, help="Network to relay blocks to")
    parser.add_argument('--start', required=True, type=int, help="Block to start from")
    parser.add_argument('--verbose', required=False, action='store_true', help="Print verbose output")
    return parser.parse_args()


class BridgeContract:
    def __init__(self, address: str, web3: Web3):
        with open(settings.PEACE_RELAY_ABI_PATH) as fh:
            self.contract = web3.eth.contract(abi=json.load(fh), address=address)

    def submit_block(self, block_hash: int, rlp_header: bytes):
        return self.contract.functions.submitBlock(block_hash, rlp_header).buildTransaction()


def main():
    args = get_args()
    if args.verbose:
        logger.setLevel(logging.DEBUG)

    from_network = settings.NETWORK_CONFIG[args.source]
    web3_from = Web3(HTTPProvider(endpoint_uri=from_network['url'],
                                  request_kwargs={'timeout': settings.DEFAULT_REQUEST_TIMEOUT}))
    web3_from.middleware_stack.inject(geth_poa_middleware, layer=0)

    to_network = settings.NETWORK_CONFIG[args.dest]
    web3_to = Web3(HTTPProvider(endpoint_uri=to_network['url'],
                                request_kwargs={'timeout': settings.DEFAULT_REQUEST_TIMEOUT}))

    block_to_relay = args.start
    latest_block = web3_from.eth.blockNumber
    bridge_contract = BridgeContract(to_network['peaceRelayAddress'], web3_to)

    while True:
        if block_to_relay < latest_block - settings.BLOCKS_OFFSET:
            logger.info('Relaying {}'.format(block_to_relay))
            w3_block = dict(web3_from.eth.getBlock(block_to_relay))
            poa_data = w3_block.get('proofOfAuthorityData')
            if poa_data:
                w3_block['extraData'] = poa_data
            block = merkle_proof.block_header(w3_block)
            raw_txn = bridge_contract.submit_block(bytes_to_int(block.hash), rlp.encode(block))
            raw_txn['nonce'] = web3_to.eth.getTransactionCount(privtoaddr(settings.PRIVATE_KEY))
            signed_txn = web3_to.eth.account.signTransaction(raw_txn, private_key=settings.PRIVATE_KEY)
            txn_hash = encode_hex(web3_to.eth.sendRawTransaction(signed_txn.rawTransaction))
            txn_info = web3_to.eth.getTransaction(txn_hash)
            while txn_info is None or txn_info.blockNumber is None:
                time.sleep(1)
                txn_info = web3_to.eth.getTransaction(txn_hash)
            logger.info('Successfully relayed block {} in txn {}'.format(block_to_relay, txn_hash))
            block_to_relay += 1
        else:
            time.sleep(1)
            latest_block = web3_from.eth.blockNumber


if __name__ == '__main__':
    main()
