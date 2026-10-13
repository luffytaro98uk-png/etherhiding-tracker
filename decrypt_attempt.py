import base64
import string

payloads = {
    'primary':       'CU8FARtiVEZSI1ZxSQEdSF1cXGlSVwMKGldYWhxoHFcWEAdJ',
    'sibling':       'eEJGQVxwCRMHQCd8CkFAWh9JEkwwR0xXWlpDSFxXJ11RTA==',
    'wallet2_first': 'TBlDWgFjX10RXB1VDh4aLQIVTQAKDlhHXQ==',
}

def is_printable(b):
    return all(32 <= c < 127 for c in b)

print("=" * 60)
print("STEP 1: Base64 decode")
print("=" * 60)
decoded = {}
for name, b64 in payloads.items():
    try:
        raw = base64.b64decode(b64)
        decoded[name] = raw
        print(f"{name}: {len(raw)} bytes")
        print(f"  hex: {raw.hex()}")
        print(f"  ascii: {''.join(chr(c) if 32 <= c < 127 else '.' for c in raw)}")
    except Exception as e:
        print(f"{name}: base64 error - {e}")
print()

print("=" * 60)
print("STEP 2: Single-byte XOR brute force (looking for printable output)")
print("=" * 60)
for name, raw in decoded.items():
    print(f"\n{name}:")
    hits = []
    for key in range(1, 256):
        xored = bytes(b ^ key for b in raw)
        if is_printable(xored):
            hits.append((key, xored.decode('ascii')))
    if hits:
        for key, text in hits[:10]:
            print(f"  key=0x{key:02x} ({key:3d}): {text}")
    else:
        print("  no single-byte key produced all-printable output")
print()

print("=" * 60)
print("STEP 3: Repeating-key XOR analysis (find key length by entropy)")
print("=" * 60)
for name, raw in decoded.items():
    print(f"\n{name}:")
    # Check if XORing all payloads together reveals structure (common plaintext)
    # Try to find repeating byte patterns
    for keylen in range(2, 33):
        # Score: sum of how "flat" each byte column is (low variance = likely XOR with same key byte)
        columns = [raw[i::keylen] for i in range(keylen)]
        # If plaintext is ASCII, each column XORed with a constant should be mostly same value
        score = 0
        for col in columns:
            if len(col) < 2:
                continue
            # Count most-common byte
            from collections import Counter
            mc = Counter(col).most_common(1)[0][1]
            score += mc
        avg = score / keylen
        if avg > 0.7 * (len(raw) // keylen):
            print(f"  keylen={keylen}: avg column uniformity = {avg:.1f} (suspicious)")
print()

print("=" * 60)
print("STEP 4: Test known campaign XOR key (!sdf$&G321)")
print("=" * 60)
key_str = "!sdf$&G321"
key_bytes = key_str.encode('ascii')
for name, raw in decoded.items():
    xored = bytes(b ^ key_bytes[i % len(key_bytes)] for i, b in enumerate(raw))
    printable = ''.join(chr(c) if 32 <= c < 127 else '.' for c in xored)
    print(f"{name}:")
    print(f"  {printable}")