import base64

binary_blob = bytes.fromhex('474f67df063ab6a7d04a32f63b34976a569b7fbc67531eefd338bde93ce52d1174c979a22156e317c1219303ae5bfec5623816f7dce961066c7352e58f02c1ab372c416b')

print("Single-byte XOR brute force:")
for k in range(256):
    x = bytes(b ^ k for b in binary_blob)
    printable = sum(1 for c in x if 32 <= c < 127)
    if printable > len(x) * 0.85:
        try:
            print(f"  key=0x{k:02x}: {x.decode('ascii')}")
        except Exception:
            pass

# Also try: is it AES-encrypted? (high entropy suggests so)
from collections import Counter
counts = Counter(binary_blob)
print(f"\nUnique bytes: {len(counts)} of {len(binary_blob)}")
print(f"Most common: {counts.most_common(3)}")

# Base64-decode the raw blob? (maybe it's b64-of-binary-of-something)
try:
    inner = binary_blob.decode('ascii')
    print(f"Blob as ASCII: {inner[:60]}")
    try:
        deeper = base64.b64decode(inner)
        print(f"Re-decoded: {deeper.hex()}")
    except Exception:
        pass
except Exception:
    print("Not ASCII")