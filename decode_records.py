"""
Decode the 5 records in contract 0x4af804 slots 2-6.
Test multiple hypotheses: XOR, base64, timestamp, hash.
"""

import base64
from datetime import datetime, timezone

records = [
    '5c69e5c11a0794fe6016d7ba1c98bd4b5b6bf09f0a520000000000000000002c',
    '5c69e5c11a0794fe7a02dcaf1c98bd4b5b6bf09f0a520000000000000000002c',
    '5c69e5c11a0794fe721ed0b51c98bd4b5b6bf09f0a520000000000000000002c',
    '5c69e5c11a0794fe7b16d0b21c98bd4b5b6bf09f0a520000000000000000002c',
    '5c69e5c11a0794fe7a16d8a21c98bd4b5b6bf09f0a520000000000000000002c',
]

KEYS = {
    'GuidePoint XOR key': b'$%)W$fgl34',
    'Traffic XOR key': b'!sdf$&G321',
}

print("=" * 70)
print("RAW RECORDS")
print("=" * 70)
for i, r in enumerate(records):
    data = bytes.fromhex(r)
    print(f"\nRecord {i} (slot {i+2}):")
    print(f"  hex: {r}")
    print(f"  ascii: {''.join(chr(b) if 32 <= b < 127 else '.' for b in data)}")
    # Try as short string (last byte = length*2)
    length_byte = data[31]
    if length_byte % 2 == 0 and 0 < length_byte // 2 <= 31:
        string_len = length_byte // 2
        print(f"  Solidity short string length: {string_len} bytes")
        print(f"  string bytes: {data[:string_len].hex()}")
        try:
            print(f"  string text:  {data[:string_len].decode('utf-8')}")
        except Exception:
            print(f"  string text:  (not UTF-8)")

print()
print("=" * 70)
print("BYTE-BY-BYTE DIFFERENCES")
print("=" * 70)
# Find which byte positions differ across records
data_list = [bytes.fromhex(r) for r in records]
differing = []
for pos in range(32):
    values = set(d[pos] for d in data_list)
    if len(values) > 1:
        differing.append((pos, sorted(values)))

print(f"Byte positions that differ across records: {len(differing)}")
for pos, values in differing:
    print(f"  byte {pos:>2}: {[hex(v) for v in values]}")

print()
print("=" * 70)
print("XOR TESTS WITH KNOWN CAMPAIGN KEYS")
print("=" * 70)
for key_name, key in KEYS.items():
    print(f"\n--- {key_name}: {key} ---")
    for i, r in enumerate(records):
        data = bytes.fromhex(r)
        xored = bytes(data[j] ^ key[j % len(key)] for j in range(len(data)))
        printable = ''.join(chr(b) if 32 <= b < 127 else '.' for b in xored)
        print(f"  Record {i}: {printable}")

print()
print("=" * 70)
print("AS UINT32 INTERPRETATION OF BYTES 8-11")
print("=" * 70)
for i, r in enumerate(records):
    data = bytes.fromhex(r)
    mid = int.from_bytes(data[8:12], 'big')
    print(f"  Record {i}: 0x{data[8:12].hex()} = {mid}")
    # As timestamp
    try:
        dt = datetime.fromtimestamp(mid, tz=timezone.utc)
        print(f"    as unix timestamp: {dt}")
    except Exception:
        pass

print()
print("=" * 70)
print("AS UINT64 INTERPRETATION OF BYTES 0-7")
print("=" * 70)
for i, r in enumerate(records):
    data = bytes.fromhex(r)
    head = int.from_bytes(data[0:8], 'big')
    print(f"  Record {i}: 0x{data[0:8].hex()} = {head}")
    try:
        dt = datetime.fromtimestamp(head, tz=timezone.utc)
        print(f"    as unix timestamp: {dt}")
    except Exception:
        pass

print()
print("=" * 70)
print("XOR OF RECORDS AGAINST EACH OTHER")
print("=" * 70)
print("If two records share a keystream, C1 XOR C2 reveals structure.")
for i in range(len(records)):
    for j in range(i+1, len(records)):
        d1 = bytes.fromhex(records[i])
        d2 = bytes.fromhex(records[j])
        xored = bytes(a ^ b for a, b in zip(d1, d2))
        printable = ''.join(chr(b) if 32 <= b < 127 else '.' for b in xored)
        print(f"  Rec {i} XOR Rec {j}: {printable}")