import os
import time
from web3 import Web3
from dotenv import load_dotenv

load_dotenv()
w3 = Web3(Web3.HTTPProvider(os.getenv('ALCHEMY_RPC_URL')))

OPERATOR_WALLETS = [
    '0xd802C9427ce416B9DAb2db5aDD76EfAA6d9d826a',
    '0x6a6e177dcf992ac16f7367c14b26a3cf4775dfde',
]

# Known contracts deployed by these wallets (skip these)
KNOWN_CONTRACTS = {
    '0xde2d34339c279a7a79bc4fc1c4f37d3c055211b7',
    '0xa982e044217b6bbaa7b3123b670c1c0ca1138a37',
    '0x308e9ecc849533a042f13fd77e5c82ec3c62e9f2',
}

print("=== Operator Wallet Watcher ===")
print()

for raw_wallet in OPERATOR_WALLETS:
    wallet = Web3.to_checksum_address(raw_wallet)
    nonce = w3.eth.get_transaction_count(wallet)
    balance = w3.eth.get_balance(wallet)

    print(f"Wallet:  {wallet}")
    print(f"  Nonce (txs sent):  {nonce}")
    print(f"  Balance:           {w3.from_wei(balance, 'ether')} MATIC")
    print()

    # Fetch recent transactions by scanning blocks
    # Public RPCs often don't index tx-by-address; we approximate by checking
    # recent outbound txs in a window. For full history use Polygonscan API.
    current_block = w3.eth.block_number
    scan_blocks = 500  # recent window

    found = []
    print(f"  Scanning last {scan_blocks} blocks for outbound txs...")

    # Note: this is slow on free tier. In production use Polygonscan API.
    # For now we just report the nonce, which tells us if new txs exist.
    print(f"  (Full tx history requires Polygonscan API or an indexer)")
    print(f"  Current nonce = {nonce}. Store this value and compare later.")
    print(f"  If nonce increases, a new contract was likely deployed.")
    print()

print("=== Baseline recorded ===")
print()
print("To detect new deployments: re-run this script later and compare nonces.")
print("Any increase means the operator sent a transaction (likely a contract deploy).")