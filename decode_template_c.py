from web3 import Web3
import os
import base64
from dotenv import load_dotenv

load_dotenv()
w3 = Web3(Web3.HTTPProvider(os.getenv('ALCHEMY_RPC_URL')))

TEMPLATE_C = '0x46124F9F0f0d70c8b9e62258179574E05FbFF181'
TEMPLATE_B = '0x75A91aCdB3dd25B39fe0619d2A00DE49A8e56eb9'

def extract_blob(addr, selector):
    """Call selector and decode the ABI-encoded bytes payload."""
    result = w3.eth.call({'to': addr, 'data': '0x' + selector})
    if len(result) < 64:
        return None
    offset = int.from_bytes(result[0:32], 'big')
    length = int.from_bytes(result[offset:offset+32], 'big')
    if length == 0:
        return b''
    return result[offset+32:offset+32+length]

# Extract from Template C (both selectors should give same blob)
print("=" * 70)
print("TEMPLATE C BLOB EXTRACTION")
print("=" * 70)
print()

blob1 = extract_blob(TEMPLATE_C, '3bc5de30')
blob2 = extract_blob(TEMPLATE_C, '73d4a13a')

print(f"Selector 0x3bc5de30: {len(blob1)} bytes")
print(f"  hex: {blob1.hex()}")
print()
print(f"Selector 0x73d4a13a: {len(blob2)} bytes")
print(f"  hex: {blob2.hex()}")
print()
print(f"Same blob? {blob1 == blob2}")
print()

# Analyze the blob structure
print("=" * 70)
print("BLOB ANALYSIS")
print("=" * 70)
print()

# Byte histogram - look for structure
from collections import Counter
byte_counts = Counter(blob1)
print("Byte frequency (top 10 most common):")
for byte_val, count in byte_counts.most_common(10):
    print(f"  0x{byte_val:02x} ({byte_val:3d}): {count} times")
print()

# Check for repeating patterns (would suggest XOR with short key)
print("Looking for repeated byte sequences (possible XOR key length)...")
for period in range(2, 33):
    matches = 0
    total = 0
    for i in range(len(blob1) - period):
        total += 1
        if blob1[i] == blob1[i + period]:
            matches += 1
    if total > 0:
        ratio = matches / total
        if ratio > 0.15:
            print(f"  period={period:2d}: match ratio = {ratio:.2%}")
print()

# Try common transformations
print("Testing common transformations:")
print()

# 1. Base64 decode
try:
    b64_decoded = base64.b64decode(blob1, validate=True)
    print(f"  [base64] decodes to {len(b64_decoded)} bytes: {b64_decoded.hex()}")
except Exception:
    print(f"  [base64] not valid base64")

# 2. UTF-8 decode
try:
    text = blob1.decode('utf-8')
    print(f"  [utf-8]  {text}")
except Exception:
    print(f"  [utf-8]  not valid UTF-8")

# 3. Try XOR with candidate keys from the report
print()
print("XOR tests with candidate keys:")
for key_name, key_bytes in [
    ("!sdf$&G321", b"!sdf$&G321"),
    ("$%)W$fgl34", b"$%)W$fgl34"),
]:
    xored = bytes(b ^ key_bytes[i % len(key_bytes)] for i, b in enumerate(blob1))
    printable = ''.join(chr(c) if 32 <= c < 127 else '.' for c in xored)
    print(f"  key='{key_name}': {printable}")
print()

# 4. Single-byte XOR brute force
print("Single-byte XOR brute force (printable hits only):")
hits = 0
for key in range(1, 256):
    xored = bytes(b ^ key for b in blob1)
    if all(32 <= c < 127 for c in xored):
        print(f"  key=0x{key:02x}: {xored.decode('ascii')}")
        hits += 1
if hits == 0:
    print("  (no key produced all-printable output)")

print()
print("=" * 70)
print("TEMPLATE B STATUS")
print("=" * 70)
print()

b_blob = extract_blob(TEMPLATE_B, '3bc5de30')
if b_blob is not None:
    print(f"Template B blob: {len(b_blob)} bytes")
    if len(b_blob) == 0:
        print("  ** EMPTY - contract is dormant, no C2 stored yet **")
    else:
        print(f"  hex: {b_blob.hex()}")
print()

print("=== Done ===")