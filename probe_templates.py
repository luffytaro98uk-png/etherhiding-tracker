from web3 import Web3
import os
import re
from dotenv import load_dotenv

load_dotenv()
w3 = Web3(Web3.HTTPProvider(os.getenv('ALCHEMY_RPC_URL')))

# Representative contracts
TEMPLATE_B = '0x75A91aCdB3dd25B39fe0619d2A00DE49A8e56eb9'
TEMPLATE_C = '0x46124F9F0f0d70c8b9e62258179574E05FbFF181'

# All selectors found across B and C
SELS_B = ['3bc5de30', '47064d6a']
SELS_C = ['3bc5de30', '73d4a13a', '8da5cb5b', 'ab62f0e1', 'f2fde38b']

def try_call(addr, selector, label):
    """Attempt a call and try to decode any return value."""
    try:
        result = w3.eth.call({'to': addr, 'data': '0x' + selector})
        print(f"  [{label}] 0x{selector}")
        print(f"    raw length: {len(result)} bytes")
        print(f"    raw hex:    {result.hex()[:200]}")

        # Try ABI-encoded string decode
        if len(result) >= 64:
            try:
                offset = int.from_bytes(result[0:32], 'big')
                if offset + 32 <= len(result):
                    length = int.from_bytes(result[offset:offset+32], 'big')
                    if 0 < length < 500:
                        data = result[offset+32:offset+32+length]
                        try:
                            text = data.decode('utf-8')
                            print(f"    ABI string: {text}")
                        except Exception:
                            print(f"    (binary, {length} bytes)")
            except Exception:
                pass

        # Try short string (last byte is length*2)
        if len(result) >= 32:
            last = result[31]
            if 2 <= last <= 62 and last % 2 == 0:
                length = last // 2
                try:
                    text = result[:length].decode('utf-8')
                    print(f"    short string: {text}")
                except Exception:
                    pass

        # Try address decode
        if len(result) == 32:
            addr_candidate = '0x' + result[12:32].hex()
            print(f"    as address: {addr_candidate}")

        print()
        return result
    except Exception as e:
        err = str(e)[:100]
        if 'revert' in err.lower():
            print(f"  [{label}] 0x{selector}: REVERTED")
        else:
            print(f"  [{label}] 0x{selector}: ERROR {err}")
        print()
        return None

print("=" * 70)
print("PROBING TEMPLATE B CONTRACT")
print("=" * 70)
print(f"Contract: {TEMPLATE_B}")
print()

for sel in SELS_B:
    try_call(TEMPLATE_B, sel, 'B')

print("=" * 70)
print("PROBING TEMPLATE C CONTRACT")
print("=" * 70)
print(f"Contract: {TEMPLATE_C}")
print()

for sel in SELS_C:
    try_call(TEMPLATE_C, sel, 'C')

print("=" * 70)
print("STORAGE SCAN: TEMPLATE B (slots 0-15)")
print("=" * 70)

for slot in range(16):
    try:
        val = w3.eth.get_storage_at(TEMPLATE_B, slot)
        if val != b'\x00' * 32:
            print(f"  slot {slot:2d}: {val.hex()}")
    except Exception:
        pass

print()
print("=== Done ===")