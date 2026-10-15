"""
Analyze a contract: extract selectors, dump storage slots.

Usage:
    python analyze.py <address>
"""
import sys
import re
import os
from web3 import Web3
from dotenv import load_dotenv

load_dotenv()
w3 = Web3(Web3.HTTPProvider(os.getenv('ALCHEMY_RPC_URL')))

if len(sys.argv) < 2:
    print("Usage: python analyze.py <address>")
    sys.exit(1)

raw_addr = sys.argv[1]
addr = Web3.to_checksum_address(raw_addr)

print("=" * 70)
print(f"ANALYSIS: {addr}")
print("=" * 70)
print()

# Get code
code = w3.eth.get_code(addr)
hexcode = code.hex()

if len(code) == 0:
    print("No code at this address (EOA or self-destructed contract).")
    print(f"Balance: {w3.from_wei(w3.eth.get_balance(addr), 'ether')} POL")
    print(f"Nonce:   {w3.eth.get_transaction_count(addr)}")
    sys.exit(0)

print(f"Bytecode size: {len(code)} bytes")
print(f"Code hash (sha3-256, first 16): ", end='')
import hashlib
print(hashlib.sha3_256(code).hexdigest()[:16])
print()

# Extract selectors
sels = sorted(set(re.findall(r'63([0-9a-f]{8})14', hexcode)))
print(f"Selectors found: {len(sels)}")
for s in sels:
    print(f"  0x{s}")
print()

# Known selectors for reference
KNOWN = {
    'b68d1809': 'Template A C2 getter',
    'b249cd2d': 'Template A setter (Update Domain)',
    '3bc5de30': 'Template B/C C2 getter',
    '47064d6a': 'Template B setter (setData)',
    '73d4a13a': 'Template C second getter',
    '8da5cb5b': 'owner()',
    'f2fde38b': 'transferOwnership(address)',
    '893d20e8': 'owner-related getter (Template A)',
    'ab62f0e1': 'Template C unverified selector',
}

matches = [s for s in sels if s in KNOWN]
if matches:
    print("Known selector matches:")
    for s in matches:
        print(f"  0x{s} -> {KNOWN[s]}")
    print()

# Storage dump
print("Storage slots (0-9):")
for i in range(10):
    try:
        val = w3.eth.get_storage_at(addr, i)
        if val != b'\x00' * 32:
            hexval = val.hex()
            print(f"  slot {i}: 0x{hexval}")
            # If it looks like an address (12 zero bytes + 20 bytes)
            if hexval.startswith('0' * 24) and len(hexval) == 64:
                try:
                    candidate = Web3.to_checksum_address('0x' + hexval[24:])
                    print(f"    (looks like address: {candidate})")
                except Exception:
                    pass
    except Exception:
        pass

print()
print("=" * 70)