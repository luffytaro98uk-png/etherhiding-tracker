from web3 import Web3
import os
from dotenv import load_dotenv

load_dotenv()
w3 = Web3(Web3.HTTPProvider(os.getenv('ALCHEMY_RPC_URL')))

contracts = {
    'primary':       '0xde2d34339c279a7a79bc4fc1c4f37d3c055211b7',
    'sibling':       '0xa982e044217b6bbaa7b3123b670c1c0ca1138a37',
    'wallet2_first': '0x308e9ecc849533a042f13fd77e5c82ec3c62e9f2',
}

# Try both getters
SELECTORS = ['b68d1809', '893d20e8']

def decode_abi_string(raw_bytes):
    """Decode ABI-encoded string: offset(32) + length(32) + data"""
    if len(raw_bytes) < 64:
        return None
    try:
        offset = int.from_bytes(raw_bytes[0:32], 'big')
        if offset + 32 > len(raw_bytes):
            return None
        length = int.from_bytes(raw_bytes[offset:offset+32], 'big')
        if length == 0 or length > 500:
            return None
        string_data = raw_bytes[offset+32:offset+32+length]
        return string_data.decode('utf-8')
    except Exception:
        return None

def decode_short_string(raw_bytes):
    """Decode a short string stored directly in the return slot."""
    try:
        # Last byte is length * 2 for short strings
        last_byte = raw_bytes[31] if len(raw_bytes) >= 32 else 0
        if 2 <= last_byte <= 62 and last_byte % 2 == 0:
            length = last_byte // 2
            return raw_bytes[:length].decode('utf-8')
    except Exception:
        pass
    return None

for name, raw_addr in contracts.items():
    addr = Web3.to_checksum_address(raw_addr)
    print(f"=== {name}: {addr} ===")

    for sel in SELECTORS:
        try:
            result = w3.eth.call({'to': addr, 'data': '0x' + sel})
            print(f"  Selector 0x{sel}:")
            print(f"    Raw length: {len(result)} bytes")

            decoded = decode_abi_string(result)
            if decoded:
                print(f"    ABI string: {decoded}")
                continue

            decoded = decode_short_string(result)
            if decoded:
                print(f"    Short string: {decoded}")
                continue

            print(f"    Raw hex: {result.hex()[:120]}")

        except Exception as e:
            err = str(e)
            if 'execution reverted' in err.lower() or 'revert' in err.lower():
                print(f"  Selector 0x{sel}: REVERTED")
            else:
                print(f"  Selector 0x{sel}: ERROR - {err[:120]}")

    print()