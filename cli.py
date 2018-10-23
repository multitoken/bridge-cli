import argparse
import json
import logging
import time

import rlp
from eth_utils import to_wei, encode_hex
from ethereum.utils import privtoaddr, bytes_to_int
from web3 import Web3, HTTPProvider
from web3.middleware import geth_poa_middleware

import settings
from merkle_proof import generate_proof_blob_from_jsonrpc_using_number, transaction, \
    generate_receipt_proof_blob_from_jsonrpc, receipt

logger = logging.getLogger(__name__)


def get_args():
    parser = argparse.ArgumentParser(
        description="Bridge CLI",
        formatter_class=argparse.RawTextHelpFormatter)
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument('--lock', type=float, help="Amount of ether to lock")
    group.add_argument('--burn', type=float, help="Amount of tokens to burn")
    parser.add_argument('--verbose', required=False, action='store_true', help="Print verbose output")
    return parser.parse_args()


class BridgeContract:
    def __init__(self, address: str, web3: Web3):
        with open(settings.PEACE_RELAY_ABI_PATH) as fh:
            self.contract = web3.eth.contract(abi=json.load(fh), address=address)

    def submit_block(self, block_hash: int, rlp_header: bytes):
        return self.contract.functions.submitBlock(block_hash, rlp_header).buildTransaction()


class ETHLockingContract:
    def __init__(self, address: str, web3: Web3):
        with open(settings.ETH_LOCKING_ABI_PATH) as fh:
            self.contract = web3.eth.contract(abi=json.load(fh), address=address)

    def lock(self, address: str):
        return self.contract.functions.lock(address).buildTransaction()

    def unlock(self, tx_value: bytes, block_hash: int, tx_path: bytes, tx_parent_nodes: bytes,
               rec_value: bytes, rec_path: bytes, rec_parent_nodes: bytes):
        return self.contract.functions.unlock(tx_value, block_hash, tx_path, tx_parent_nodes,
                                              rec_value, rec_path, rec_parent_nodes).buildTransaction()


class ETHTokenContract:
    def __init__(self, address: str, web3: Web3):
        with open(settings.ETH_TOKEN_ABI_PATH) as fh:
            self.contract = web3.eth.contract(abi=json.load(fh), address=address)

    def mint(self, value: bytes, block_hash: int, path: bytes, parent_nodes: bytes):
        return self.contract.functions.mint(value, block_hash, path, parent_nodes).buildTransaction()

    def burn(self, value: int, eth_addr: str):
        return self.contract.functions.burn(value, eth_addr).buildTransaction({'gas': 200000})


def send_txn(raw_txn, address, private_key, web3):
    raw_txn['nonce'] = web3.eth.getTransactionCount(address, 'pending')
    signed_txn = web3.eth.account.signTransaction(raw_txn, private_key=private_key)
    txn_hash = encode_hex(web3.eth.sendRawTransaction(signed_txn.rawTransaction))
    return txn_hash


def wait_for_txn(txn_hash, web3):
    txn_info = web3.eth.getTransaction(txn_hash)
    while txn_info is None or txn_info.blockNumber is None:
        time.sleep(1)
        txn_info = web3.eth.getTransaction(txn_hash)
    return txn_info


def lock(amount: float):
    from_network = settings.NETWORK_CONFIG['rinkeby']
    web3_from = Web3(HTTPProvider(endpoint_uri=from_network['url'],
                                  request_kwargs={'timeout': settings.DEFAULT_REQUEST_TIMEOUT}))
    web3_from.middleware_stack.inject(geth_poa_middleware, layer=0)

    to_network = settings.NETWORK_CONFIG['ropsten']
    web3_to = Web3(HTTPProvider(endpoint_uri=to_network['url'],
                                request_kwargs={'timeout': settings.DEFAULT_REQUEST_TIMEOUT}))

    private_key = settings.PRIVATE_KEY
    address = privtoaddr(private_key)

    eth_locking_contract = ETHLockingContract(from_network['ethLockingAddress'], web3_from)
    eth_token_contract = ETHTokenContract(to_network['ethTokenAddress'], web3_to)

    raw_txn = eth_locking_contract.lock(address)
    raw_txn['value'] = to_wei(amount, 'ether')
    txn_hash = send_txn(raw_txn, address, private_key, web3_from)
    txn_info = wait_for_txn(txn_hash, web3_from)
    logger.info('Successfully locked {} ETH in txn {}'.format(amount, txn_hash))

    proof_blob = generate_proof_blob_from_jsonrpc_using_number(
        from_network['url'], txn_info.blockNumber, txn_info.transactionIndex)
    decoded_proof_blob = rlp.decode(proof_blob)
    raw_txn = eth_token_contract.mint(rlp.encode(transaction(txn_info)),
                                      bytes_to_int(txn_info.blockHash),
                                      decoded_proof_blob[3],
                                      rlp.encode(decoded_proof_blob[5]))
    txn_hash = send_txn(raw_txn, address, private_key, web3_to)
    txn_info = wait_for_txn(txn_hash, web3_to)
    logger.info('Successfully minted {} tokens in txn {}'.format(amount, txn_hash))


def burn(amount: float):
    from_network = settings.NETWORK_CONFIG['ropsten']
    web3_from = Web3(HTTPProvider(endpoint_uri=from_network['url'],
                                  request_kwargs={'timeout': settings.DEFAULT_REQUEST_TIMEOUT}))

    to_network = settings.NETWORK_CONFIG['rinkeby']
    web3_to = Web3(HTTPProvider(endpoint_uri=to_network['url'],
                                request_kwargs={'timeout': settings.DEFAULT_REQUEST_TIMEOUT}))

    private_key = settings.PRIVATE_KEY
    address = privtoaddr(private_key)

    eth_locking_contract = ETHLockingContract(to_network['ethLockingAddress'], web3_to)
    eth_token_contract = ETHTokenContract(from_network['ethTokenAddress'], web3_from)

    raw_txn = eth_token_contract.burn(to_wei(amount, 'ether'), address)
    txn_hash = send_txn(raw_txn, address, private_key, web3_from)
    txn_hash = '0x261c9dabfa19dc594763f72a0e0b0d53b5045bad167e83b5569b7b4f071eef76'
    txn_info = wait_for_txn(txn_hash, web3_from)
    txn_receipt = web3_from.eth.getTransactionReceipt(txn_hash)
    logger.info('Successfully burned {} tokens in txn {}'.format(amount, txn_hash))

    proof_blob = generate_proof_blob_from_jsonrpc_using_number(
        from_network['url'], txn_info.blockNumber, txn_info.transactionIndex)
    decoded_proof_blob = rlp.decode(proof_blob)
    receipt_proof_blob = generate_receipt_proof_blob_from_jsonrpc(
        web3_from, txn_info.blockNumber, txn_info.transactionIndex)
    decoded_receipt_proof_blob = rlp.decode(receipt_proof_blob)
    raw_txn = eth_locking_contract.unlock(rlp.encode(transaction(txn_info)),
                                          bytes_to_int(txn_info.blockHash),
                                          decoded_proof_blob[3],
                                          rlp.encode(decoded_proof_blob[5]),
                                          rlp.encode(receipt(txn_receipt)),
                                          decoded_receipt_proof_blob[3],
                                          rlp.encode(decoded_receipt_proof_blob[5]))
    txn_hash = send_txn(raw_txn, address, private_key, web3_to)
    txn_info = wait_for_txn(txn_hash, web3_to)
    logger.info('Successfully unlocked {} ETH in txn {}'.format(amount, txn_hash))


def main():
    args = get_args()
    if args.verbose:
        logger.setLevel(logging.DEBUG)

    if args.lock:
        lock(args.lock)
    else:
        burn(args.burn)


if __name__ == '__main__':
    main()
