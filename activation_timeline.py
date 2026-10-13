"""
Reconstruct the activation timeline of Template B contracts.

For each contract, binary-search the block range to find when the blob
transitioned from 0 to non-zero.
"""
import os
import sys
import time
from web3 import Web3
from dotenv import load_dotenv

load_dotenv()

w3 = Web3(Web3.HTTPProvider(os.getenv('ALCHEMY_RPC_URL')))

C2_GETTER = '3bc5de30'

CONTRACTS = {
    '0xFad3F51fF70223CadeecCf8FCf2D362533f360eE': 80,
    '0xB685a24587658989410D68500448f45467CA47D8': 76,
    '0xed4417B3992A4e6613f734E720e24DE5630695f8': 80,
    '0xA5517ea1914EbfcEcDe8528e0973D98E60178607': 64,
    '0x5C4576E21809FfA8d265bB7385f044A693356c43': 64,
}

def get_blob_len(addr, block):
    """Call the getter at a specific historical block."""
    try:
        result = w3.eth.call(
            {'to': addr, 'data': '0x' + C2_GETTER},
            block_identifier=block
        )
        if len(result) < 64:
            return None
        offset = int.from_bytes(result[0:32], 'big')
        if offset + 32 > len(result):
            return None
        return int.from_bytes(result[offset:offset+32], 'big')
    except Exception:
        return None

def find_activation_block(addr, deploy_block, current_block):
    """Binary search for the first block where blob > 0."""
    low = deploy_block
    high = current_block

    # First, verify current is active and deploy was dormant
    cur = get_blob_len(addr, current_block)
    if cur is None or cur == 0:
        return None, "still dormant at current block"

    # Binary search
    while low < high:
        mid = (low + high) // 2
        length = get_blob_len(addr, mid)
        if length is None:
            # Can't read - assume historical state unavailable
            return None, "historical state not available (needs archive node)"
        if length == 0:
            low = mid + 1
        else:
            high = mid
        time.sleep(0.3)

    return low, "found"

# Template B deployment block range (from GuidePoint report: May 2026)
# We'll search from a wide range to be safe
DEPLOY_BLOCK = 70000000  # approximate - Polygon block before May 2026
CURRENT = w3.eth.block_number

print("=" * 70)
print("TEMPLATE B ACTIVATION TIMELINE")
print("=" * 70)
print(f"Current block: {CURRENT}")
print(f"Deployment search floor: {DEPLOY_BLOCK}")
print()
print("NOTE: Historical state queries require an archive node.")
print("Alchemy free tier does NOT include archive access.")
print("If this fails, we'll need to use the event log approach instead.")
print()

for raw_addr, blob_now in CONTRACTS.items():
    addr = Web3.to_checksum_address(raw_addr)
    print(f"Contract: {addr}")
    print(f"  Current blob: {blob_now} bytes")

    # Try reading historical state
    test_block = CURRENT - 1000
    test_len = get_blob_len(addr, test_block)

    if test_len is None:
        print(f"  Historical read at block {test_block}: FAILED")
        print(f"  -> Archive node required. Skipping binary search.")
        print()
        continue

    print(f"  Historical read at block {test_block}: blob={test_len}")

    block, reason = find_activation_block(addr, DEPLOY_BLOCK, CURRENT)
    if block:
        ts = w3.eth.get_block(block)['timestamp']
        readable = time.strftime('%Y-%m-%d %H:%M:%S UTC', time.gmtime(ts))
        print(f"  ACTIVATED at block {block} ({readable})")
    else:
        print(f"  Could not determine: {reason}")
    print()

print("=" * 70)
print("ALTERNATIVE APPROACH: Event Log Timeline")
print("=" * 70)
print()
print("If historical state is unavailable, we can find activation events")
print("by scanning for the setter function's event (if it emits one).")
print("Template B emits no events per our earlier analysis.")
print()
print("Fallback: use Polygonscan's transaction history for each contract")
print("to find the first inbound transaction after deployment.")