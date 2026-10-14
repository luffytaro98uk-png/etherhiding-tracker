"""
Unified CLI for the EtherHiding Contract Tracker.

Commands:
    fingerprint <address>              Fingerprint a single contract
    wallet <address>                   Derive and fingerprint all contracts from a wallet
    scan [--blocks N]                  Scan recent blocks for rotation events
    templates                          Fingerprint all known campaign contracts
    monitor                            Run the Template B activation monitor
    report                             Print a summary intelligence report
"""
import os
import sys
import time
import argparse
import subprocess
from datetime import datetime, timezone
from web3 import Web3
from dotenv import load_dotenv

load_dotenv()

KNOWN_OPERATOR_WALLETS = [
    '0xd802C9427ce416B9DAb2db5aDD76EfAA6d9d826a',
    '0x6a6e177dcf992ac16f7367c14b26a3cf4775dfde',
]

KNOWN_CONTRACTS = {
    'Template A': [
        '0xde2d34339c279a7a79bc4fc1c4f37d3c055211b7',
        '0xa982e044217b6bbaa7b3123b670c1c0ca1138a37',
        '0x308e9ecc849533a042f13fd77e5c82ec3c62e9f2',
    ],
    'Template B': [
        '0x75A91aCdB3dd25B39fe0619d2A00DE49A8e56eb9',
        '0x4c7C35db1f8E23301a447801B019968D8b4A6329',
        '0x700121c474A1eF6b4BAC074e0B805F262a5BD46e',
        '0xd245e35d988244528F10582107Ce1BC38DA35a24',
        '0x96C90CD4E58718cb20A58e14b7931eD94Ad040C7',
        '0x0dC9f5de745394D98C0cE163D498043EB325AC45',
        '0xFad3F51fF70223CadeecCf8FCf2D362533f360eE',
        '0xB685a24587658989410D68500448f45467CA47D8',
        '0xed4417B3992A4e6613f734E720e24DE5630695f8',
        '0xA5517ea1914EbfcEcDe8528e0973D98E60178607',
        '0x5C4576E21809FfA8d265bB7385f044A693356c43',
    ],
    'Template C': [
        '0x46124F9F0f0d70c8b9e62258179574E05FbFF181',
    ],
}

C2_GETTER_A = 'b68d1809'
C2_GETTER_BC = '3bc5de30'
OWNER_SEL = '8da5cb5b'
TRANSFER_SEL = 'f2fde38b'
EVENT_TOPIC = '0x868f5f914e26b486c50b15494d56c6b2f2f17f6514343909bd36a034c19452cc'

CHUNK_SIZE = 10
SCAN_DELAY = 0.5

RPC_URL = os.getenv('ALCHEMY_RPC_URL')
if not RPC_URL or RPC_URL.endswith('/v2/'):
    print("ERROR: ALCHEMY_RPC_URL missing or incomplete in .env")
    sys.exit(1)

w3 = Web3(Web3.HTTPProvider(RPC_URL))
if not w3.is_connected():
    print("ERROR: Could not connect to Polygon RPC.")
    sys.exit(1)


def fingerprint_contract(address):
    addr = Web3.to_checksum_address(address)
    code = w3.eth.get_code(addr)
    r = {
        'address': addr,
        'has_code': len(code) > 0,
        'bytecode_size': len(code),
        'has_c2_getter': False,
        'has_ownable': False,
        'owner': None,
        'blob_len': None,
        'verdict': 'not EtherHiding',
    }
    if not r['has_code']:
        r['verdict'] = 'empty contract'
        return r

    hexcode = code.hex()
    has_getter_a = C2_GETTER_A in hexcode
    has_getter_bc = C2_GETTER_BC in hexcode
    r['has_c2_getter'] = has_getter_a or has_getter_bc
    r['has_ownable'] = OWNER_SEL in hexcode and TRANSFER_SEL in hexcode

    if r['has_c2_getter']:
        selector = C2_GETTER_A if has_getter_a else C2_GETTER_BC
        try:
            raw = w3.eth.call({'to': addr, 'data': '0x' + selector})
            if len(raw) >= 64:
                offset = int.from_bytes(raw[0:32], 'big')
                if offset == 32:
                    length = int.from_bytes(raw[32:64], 'big')
                    if length == 0:
                        r['blob_len'] = 0
                    elif length <= len(raw) - 64:
                        r['blob_len'] = length
                    else:
                        r['blob_len'] = len(raw)
                else:
                    r['blob_len'] = len(raw)
        except Exception:
            r['blob_len'] = 'CALL FAILED'

    if r['has_ownable']:
        try:
            raw = w3.eth.call({'to': addr, 'data': '0x' + OWNER_SEL})
            if len(raw) >= 32:
                r['owner'] = Web3.to_checksum_address('0x' + raw[12:32].hex())
        except Exception:
            pass

    if has_getter_a and r['has_ownable'] and isinstance(r['blob_len'], int) and r['blob_len'] > 20:
        r['verdict'] = '*** CONFIRMED ETHERHIDING (Template A) ***'
    elif has_getter_bc and r['bytecode_size'] == 1856:
        if r['blob_len'] == 0:
            r['verdict'] = 'EtherHiding Template B - DORMANT'
        elif isinstance(r['blob_len'], int) and r['blob_len'] > 0:
            r['verdict'] = '*** EtherHiding Template B - ACTIVATED ***'
    elif has_getter_bc and r['bytecode_size'] == 1441:
        if isinstance(r['blob_len'], int) and r['blob_len'] > 0:
            r['verdict'] = '*** CONFIRMED ETHERHIDING (Template C) ***'
        else:
            r['verdict'] = 'EtherHiding Template C - empty'
    elif r['has_c2_getter']:
        r['verdict'] = 'suspicious - EtherHiding-like getter present'

    return r


def print_fingerprint(r):
    print(f"Contract: {r['address']}")
    print(f"  Bytecode:      {r['bytecode_size']} bytes")
    print(f"  C2 getter:     {r['has_c2_getter']}")
    print(f"  Ownable:       {r['has_ownable']}")
    print(f"  Owner:         {r['owner']}")
    print(f"  Blob length:   {r['blob_len']}")
    print(f"  Verdict:       {r['verdict']}")


def cmd_fingerprint(args):
    r = fingerprint_contract(args.address)
    print("=" * 70)
    print("FINGERPRINT")
    print("=" * 70)
    print()
    print_fingerprint(r)
    print()


def cmd_wallet(args):
    import rlp
    from eth_utils import keccak

    wallet = Web3.to_checksum_address(args.address)
    nonce = w3.eth.get_transaction_count(wallet)

    print("=" * 70)
    print(f"WALLET: {wallet}")
    print("=" * 70)
    print(f"Nonce (total transactions): {nonce}")
    print()

    def derive_contract(deployer, n):
        encoded = rlp.encode([bytes.fromhex(deployer[2:]), n])
        return '0x' + keccak(encoded)[-20:].hex()

    found = 0
    for n in range(nonce):
        try:
            addr = Web3.to_checksum_address(derive_contract(wallet, n))
            code = w3.eth.get_code(addr)
            if len(code) > 0:
                found += 1
                r = fingerprint_contract(addr)
                print(f"[Nonce {n}] {addr}")
                print(f"    bytecode={r['bytecode_size']}  blob={r['blob_len']}")
                print(f"    {r['verdict']}")
                print()
        except Exception as e:
            print(f"[Nonce {n}] ERROR: {str(e)[:80]}")

    print(f"Total contracts discovered: {found}")


def cmd_scan(args):
    current = w3.eth.block_number
    start = current - args.blocks

    print("=" * 70)
    print(f"EVENT SCAN: blocks {start} to {current}")
    print("=" * 70)
    print(f"Topic: {EVENT_TOPIC[:24]}...")
    print()

    total_chunks = (args.blocks // CHUNK_SIZE) + 1
    found = 0

    for i, chunk_start in enumerate(range(start, current, CHUNK_SIZE)):
        chunk_end = min(chunk_start + CHUNK_SIZE - 1, current)
        try:
            logs = w3.eth.get_logs({
                'fromBlock': chunk_start,
                'toBlock': chunk_end,
                'topics': [EVENT_TOPIC]
            })
            if logs:
                found += len(logs)
                print(f"  [FOUND] {len(logs)} event(s) at blocks {chunk_start}-{chunk_end}")
                for log in logs:
                    print(f"    Contract: {log['address']}")
                    print(f"    Tx:       {log['transactionHash'].hex()}")
            if (i + 1) % 10 == 0:
                print(f"  ... {i+1}/{total_chunks} chunks")
        except Exception as e:
            print(f"  [ERROR] block {chunk_start}: {str(e)[:80]}")
        time.sleep(SCAN_DELAY)

    print()
    print(f"Total events found: {found}")


def cmd_templates(args):
    print("=" * 70)
    print("KNOWN CAMPAIGN CONTRACTS")
    print("=" * 70)
    print()

    for template, addrs in KNOWN_CONTRACTS.items():
        print(f"--- {template} ({len(addrs)} contracts) ---")
        print()
        for addr in addrs:
            r = fingerprint_contract(addr)
            print(f"  {r['address']}")
            print(f"    bytecode={r['bytecode_size']}  blob={r['blob_len']}")
            print(f"    {r['verdict']}")
            print()


def cmd_monitor(args):
    subprocess.run([sys.executable, 'monitor.py'])


def cmd_report(args):
    print("=" * 70)
    print("ETHERHIDING CAMPAIGN INTELLIGENCE REPORT")
    print("=" * 70)
    print(f"Generated: {datetime.now(timezone.utc).isoformat()}")
    print(f"Chain:     Polygon Mainnet")
    print(f"Block:     {w3.eth.block_number}")
    print()

    print("OPERATOR WALLETS")
    print("-" * 70)
    for w in KNOWN_OPERATOR_WALLETS:
        addr = Web3.to_checksum_address(w)
        nonce = w3.eth.get_transaction_count(addr)
        bal = w3.from_wei(w3.eth.get_balance(addr), 'ether')
        print(f"  {addr}")
        print(f"    nonce={nonce}  balance={bal} MATIC")
    print()

    print("CONTRACT SUMMARY")
    print("-" * 70)
    total = 0
    dormant_b = 0
    for template, addrs in KNOWN_CONTRACTS.items():
        print(f"\n  {template}:")
        for addr in addrs:
            r = fingerprint_contract(addr)
            total += 1
            if template == 'Template B' and r['blob_len'] == 0:
                dormant_b += 1
            print(f"    {r['address']}")
            print(f"      {r['verdict']}")

    print()
    print("SUMMARY")
    print("-" * 70)
    print(f"  Total contracts tracked:    {total}")
    print(f"  Dormant Template B slots:   {dormant_b}")
    print(f"  Operator wallets:           {len(KNOWN_OPERATOR_WALLETS)}")
    print()
    print("  Highest-priority signal:")
    print("    Template B blob transitioning from 0 to non-zero.")
    print("    Run 'python cli.py monitor' to watch for this.")


def main():
    parser = argparse.ArgumentParser(prog='cli.py', description='EtherHiding Contract Tracker')
    sub = parser.add_subparsers(dest='command', required=True)

    p_fp = sub.add_parser('fingerprint', help='Fingerprint a single contract')
    p_fp.add_argument('address')
    p_fp.set_defaults(func=cmd_fingerprint)

    p_w = sub.add_parser('wallet', help='Derive contracts from a wallet')
    p_w.add_argument('address')
    p_w.set_defaults(func=cmd_wallet)

    p_s = sub.add_parser('scan', help='Scan recent blocks for events')
    p_s.add_argument('--blocks', type=int, default=100)
    p_s.set_defaults(func=cmd_scan)

    p_t = sub.add_parser('templates', help='Fingerprint all known contracts')
    p_t.set_defaults(func=cmd_templates)

    p_m = sub.add_parser('monitor', help='Run the Template B activation monitor')
    p_m.set_defaults(func=cmd_monitor)

    p_r = sub.add_parser('report', help='Print intelligence summary')
    p_r.set_defaults(func=cmd_report)

    args = parser.parse_args()
    args.func(args)


if __name__ == '__main__':
    main()