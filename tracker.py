import os
import time
import re
import base64
from web3 import Web3
from web3.exceptions import BlockNotFound
from dotenv import load_dotenv

load_dotenv()

# ==== CONFIGURATION ====
ETH_HIDING_TOPIC = '0x868f5f914e26b486c50b15494d56c6b2f2f17f6514343909bd36a034c19452cc'

OPERATOR_WALLETS = [
    '0xd802C9427ce416B9DAb2db5aDD76EfAA6d9d826a',
    '0x6a6e177dcf992ac16f7367c14b26a3cf4775dfde',
]

KNOWN_CONTRACTS = [
    '0xde2d34339c279a7a79bc4fc1c4f37d3c055211b7',
    '0xa982e044217b6bbaa7b3123b670c1c0ca1138a37',
    '0x308e9ecc849533a042f13fd77e5c82ec3c62e9f2',
]

C2_GETTER   = 'b68d1809'   # EtherHiding getter
OWNER_SEL   = '8da5cb5b'   # owner()
TRANSFER_SEL = 'f2fde38b'  # transferOwnership(address)

CHUNK_SIZE = 10
SCAN_DELAY_SECONDS = 0.5
SCAN_WINDOW_BLOCKS = 100

# ==== SETUP ====
RPC_URL = os.getenv('ALCHEMY_RPC_URL')
if not RPC_URL or RPC_URL.endswith('/v2/'):
    print("ERROR: ALCHEMY_RPC_URL is missing or incomplete in .env")
    exit(1)

w3 = Web3(Web3.HTTPProvider(RPC_URL))
if not w3.is_connected():
    print("ERROR: Could not connect to Polygon RPC.")
    exit(1)

print(f"Connected to Polygon. Current block: {w3.eth.block_number}")


# ==== PHASE 1: EVENT SCANNER ====

def scan_block_range(start_block, end_block):
    all_logs = []
    current = start_block
    chunk_num = 0
    total_chunks = (end_block - start_block) // CHUNK_SIZE + 1

    while current <= end_block:
        chunk_end = min(current + CHUNK_SIZE - 1, end_block)
        chunk_num += 1
        try:
            logs = w3.eth.get_logs({
                'fromBlock': current,
                'toBlock': chunk_end,
                'topics': [ETH_HIDING_TOPIC]
            })
            if logs:
                print(f"  [FOUND] {len(logs)} event(s) in blocks {current}-{chunk_end}")
                all_logs.extend(logs)
            if chunk_num % 10 == 0:
                print(f"  ... scanned {chunk_num}/{total_chunks} chunks (block {current})")
            current = chunk_end + 1
            time.sleep(SCAN_DELAY_SECONDS)
        except Exception as e:
            print(f"  [ERROR] Block {current}-{chunk_end}: {str(e)[:120]}")
            current = chunk_end + 1
            time.sleep(SCAN_DELAY_SECONDS)
    return all_logs


# ==== PHASE 2: FINGERPRINT CHECK ====

def is_etherhiding(addr_input):
    addr = Web3.to_checksum_address(addr_input)
    code = w3.eth.get_code(addr)
    result = {
        'address': addr,
        'has_code': len(code) > 0,
        'bytecode_size': len(code),
        'has_c2_getter': False,
        'has_ownable': False,
        'owner': None,
        'blob_len': 0,
        'blob_preview': None,
        'verdict': 'not EtherHiding',
    }
    if not result['has_code']:
        result['verdict'] = 'empty contract'
        return result

    hexcode = code.hex()
    result['has_c2_getter'] = C2_GETTER in hexcode
    result['has_ownable'] = OWNER_SEL in hexcode and TRANSFER_SEL in hexcode

    if result['has_c2_getter']:
        try:
            raw = w3.eth.call({'to': addr, 'data': '0x' + C2_GETTER})
            result['blob_len'] = len(raw)
            if len(raw) >= 64:
                offset = int.from_bytes(raw[0:32], 'big')
                if offset + 32 <= len(raw):
                    length = int.from_bytes(raw[offset:offset+32], 'big')
                    if 0 < length < 500:
                        data = raw[offset+32:offset+32+length]
                        result['blob_preview'] = data[:60].decode('utf-8', errors='replace')
        except Exception as e:
            result['blob_preview'] = f"CALL FAILED: {str(e)[:60]}"

    if result['has_ownable']:
        try:
            raw = w3.eth.call({'to': addr, 'data': '0x' + OWNER_SEL})
            if len(raw) >= 32:
                result['owner'] = Web3.to_checksum_address('0x' + raw[12:32].hex())
        except Exception:
            pass

    if result['has_c2_getter'] and result['has_ownable'] and result['blob_len'] > 100:
        result['verdict'] = '*** CONFIRMED ETHERHIDING ***'
    elif result['has_c2_getter']:
        result['verdict'] = 'suspicious (incomplete signature)'
    return result


def analyze_event(log):
    tx_hash = log['transactionHash'].hex()
    block_num = log['blockNumber']
    try:
        tx = w3.eth.get_transaction(tx_hash)
        from_address = tx['from']
    except Exception:
        from_address = 'Unknown'
    try:
        block = w3.eth.get_block(block_num)
        readable_time = time.strftime('%Y-%m-%d %H:%M:%S UTC', time.gmtime(block['timestamp']))
    except BlockNotFound:
        readable_time = 'Unknown'
    return {
        'contract': log['address'],
        'tx_hash': tx_hash,
        'block': block_num,
        'from': from_address,
        'timestamp': readable_time,
    }


# ==== MAIN ====

def main():
    print("\n=== EtherHiding Contract Tracker ===")
    print(f"Event topic: {ETH_HIDING_TOPIC[:20]}...")
    print(f"Known contracts: {len(KNOWN_CONTRACTS)}")
    print(f"Operator wallets: {len(OPERATOR_WALLETS)}")

    current_block = w3.eth.block_number
    start_block = current_block - SCAN_WINDOW_BLOCKS

    print(f"\n[PHASE 1] Scanning blocks {start_block} to {current_block} for events...")
    events = scan_block_range(start_block, current_block)

    if events:
        print(f"\n=== Found {len(events)} EtherHiding Event(s) ===")
        for log in events:
            info = analyze_event(log)
            print(f"\n  Contract: {info['contract']}")
            print(f"  Tx:       {info['tx_hash']}")
            print(f"  Block:    {info['block']}")
            print(f"  Time:     {info['timestamp']}")
            print(f"  From:     {info['from']}")
    else:
        print("\nNo events found in scanned range.")

    print("\n[PHASE 2] Fingerprinting known contracts...")
    for addr in KNOWN_CONTRACTS:
        r = is_etherhiding(addr)
        print(f"\n  {r['address']}")
        print(f"    Bytecode:       {r['bytecode_size']} bytes")
        print(f"    C2 getter:      {r['has_c2_getter']}")
        print(f"    Ownable:        {r['has_ownable']}")
        print(f"    Owner:          {r['owner']}")
        print(f"    Blob length:    {r['blob_len']}")
        print(f"    Blob preview:   {r['blob_preview']}")
        print(f"    Verdict:        {r['verdict']}")

    print("\n=== Scan Complete ===")


if __name__ == "__main__":
    main()