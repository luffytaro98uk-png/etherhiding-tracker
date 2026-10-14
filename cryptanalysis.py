"""
Multi-ciphertext cryptanalysis of EtherHiding payloads.

Approach:
- XOR ciphertexts targeting the same contract to cancel the key stream
- Look for readable fragments in the XOR output (where plaintexts overlap)
- Crib-drag common URL patterns
"""

import base64
from itertools import combinations

# Ciphertexts extracted from setData() calls, decoded from base64
# Grouped by target contract

CONTRACTS = {
    '0x5C4576E2 (Template B)': {
        '86520883':  '1e8b810ae0b953f8669144244950e394cf33072dd7db01ed210d34704cff17a2db24c6a17d88044d8c94d3d1ff0d70c3',
        '90334311':  '7a98a864f5ec3d02bc287e9a917a4b537701961f82459729f23aec44dc290cc529fcf8ffc0f3b26379d4d5207e7c781716b695',
        '90694377':  '3580ed4b33fc4a00b29c35602295e15531381ce60e53fecf00d22d01bb9ccfee6d340eb7a3227218fb3629e0d83b',
    },
    '0xFad3F51f (Template B)': {
        '86434237':  '9bb76be82fd240421d7fbd0ca361fef61db46f333bcd6ca9399e268706a7a831e500aba08fa4722a46a735b09bf2ff23',
        '86434239':  '9ab0decc5cb2f57938abd4ba33315e35a5a39f32280f6012bda54a73e880dd0f33dc485b34fd65c628782a66b216cf6f3286bb7888a5b3',
        '86434517':  'fb6344ff5038c0e061a4054c8e1a0ba247942c8edbdb2fa93f2ce9f2c16c6a844782c1cb374f911c37de7a93591960cdc0f836d0689c723372b17f',
    },
    '0x308e9ecc (Template A)': {
        '80401978':  '4c19435a01635f5d0d5b5604414f1b371511165e490845491777131d141c',
        '80402130':  '4c19435a01635f5d115c1d550e1e1a2d02154d000a0e58475d',
    },
}


def hex_to_bytes(h):
    return bytes.fromhex(h)


def xor(a, b):
    return bytes(x ^ y for x, y in zip(a, b))


def printable_ratio(data):
    if not data:
        return 0.0
    printable = sum(1 for c in data if 32 <= c < 127)
    return printable / len(data)


def render(data):
    """Render bytes as printable where possible."""
    return ''.join(chr(c) if 32 <= c < 127 else '.' for c in data)


print("=" * 78)
print("MULTI-CIPHERTEXT XOR ANALYSIS")
print("=" * 78)
print()

# PART 1: XOR within the same contract
print("PART 1: XOR PAIRS WITHIN THE SAME CONTRACT")
print("=" * 78)
print()
print("If two ciphertexts use the same keystream, C1 XOR C2 = P1 XOR P2.")
print("Where P1 and P2 are both ASCII letters, the XOR output is a lowercase letter.")
print()

for contract, writes in CONTRACTS.items():
    print(f"\n--- {contract} ({len(writes)} writes) ---")
    blocks = sorted(writes.keys())
    
    for b1, b2 in combinations(blocks, 2):
        c1 = hex_to_bytes(writes[b1])
        c2 = hex_to_bytes(writes[b2])
        
        # XOR up to the shorter length
        minlen = min(len(c1), len(c2))
        xored = xor(c1[:minlen], c2[:minlen])
        
        ratio = printable_ratio(xored)
        
        print(f"\n  Block {b1} XOR Block {b2}")
        print(f"    Common length: {minlen}")
        print(f"    Printable ratio: {ratio:.1%}")
        print(f"    Result: {render(xored)}")
        
        # If high printable ratio, this is very interesting
        if ratio > 0.85:
            print(f"    *** HIGH PRINTABLE RATIO - LIKELY SAME KEYSTREAM ***")

# PART 2: Crib-drag against XOR results
print()
print("=" * 78)
print("PART 2: CRIB-DRAG AGAINST XOR RESULTS")
print("=" * 78)
print()

CRIBS = [
    (b'https://', 'URL prefix'),
    (b'http://',  'URL prefix'),
    (b'/UpdateCheck/', 'Known path'),
    (b'.shop', 'TLD'),
    (b'.online', 'TLD'),
    (b'.site', 'TLD'),
    (b'.xyz', 'TLD'),
    (b'.top', 'TLD'),
    (b'.com', 'TLD'),
    (b'.net', 'TLD'),
    (b'.biz', 'TLD'),
]

for contract, writes in CONTRACTS.items():
    print(f"\n--- {contract} ---")
    blocks = sorted(writes.keys())
    
    for b1, b2 in combinations(blocks, 2):
        c1 = hex_to_bytes(writes[b1])
        c2 = hex_to_bytes(writes[b2])
        minlen = min(len(c1), len(c2))
        xored = xor(c1[:minlen], c2[:minlen])
        
        print(f"\n  Block {b1} vs {b2}:")
        
        for crib, desc in CRIBS:
            # If plaintext P1 contains crib, then xored = P1 XOR P2,
            # so P2 = xored XOR crib should be readable
            for pos in range(len(xored) - len(crib) + 1):
                segment = xored[pos:pos+len(crib)]
                candidate_p2 = xor(segment, crib)
                if printable_ratio(candidate_p2) > 0.95:
                    print(f"    Crib '{crib.decode()}' at pos {pos}: P2 would be '{render(candidate_p2)}'")

# PART 3: Cross-contract comparison
print()
print("=" * 78)
print("PART 3: CROSS-CONTRACT COMPARISON")
print("=" * 78)
print()
print("If different contracts share a keystream (weak crypto), their")
print("ciphertexts will XOR to readable output.")
print()

# Take the most recent writes from each contract
recent = {
    '0x5C4576E2': CONTRACTS['0x5C4576E2 (Template B)']['90694377'],
    '0xFad3F51f': CONTRACTS['0xFad3F51f (Template B)']['86434517'],
    '0x308e9ecc': CONTRACTS['0x308e9ecc (Template A)']['80402130'],
}

contracts_list = list(recent.keys())
for i in range(len(contracts_list)):
    for j in range(i+1, len(contracts_list)):
        name1 = contracts_list[i]
        name2 = contracts_list[j]
        c1 = hex_to_bytes(recent[name1])
        c2 = hex_to_bytes(recent[name2])
        minlen = min(len(c1), len(c2))
        xored = xor(c1[:minlen], c2[:minlen])
        ratio = printable_ratio(xored)
        print(f"{name1} XOR {name2}: ratio={ratio:.1%}")
        print(f"  {render(xored)}")
        print()

# PART 4: Analysis of shared prefixes within Template A
print()
print("=" * 78)
print("PART 4: SHARED PREFIX ANALYSIS (Template A)")
print("=" * 78)
print()

tA = CONTRACTS['0x308e9ecc (Template A)']
c1 = hex_to_bytes(tA['80401978'])
c2 = hex_to_bytes(tA['80402130'])

print(f"Payload 1 (block 80401978): {c1.hex()}")
print(f"Payload 2 (block 80402130): {c2.hex()}")
print()

# Find shared prefix
shared = 0
for a, b in zip(c1, c2):
    if a == b:
        shared += 1
    else:
        break

print(f"Shared prefix length: {shared} bytes")
print(f"Shared prefix: {c1[:shared].hex()}")
print()

# Where they differ
print("Byte-by-byte comparison:")
print(f"{'pos':>4} {'c1':>4} {'c2':>4} {'xor':>4} {'char1':>6} {'char2':>6}")
for i in range(min(len(c1), len(c2))):
    xored = c1[i] ^ c2[i]
    ch1 = chr(c1[i]) if 32 <= c1[i] < 127 else '.'
    ch2 = chr(c2[i]) if 32 <= c2[i] < 127 else '.'
    marker = '  <-- same' if c1[i] == c2[i] else ''
    print(f"{i:>4} {c1[i]:>4x} {c2[i]:>4x} {xored:>4x} {ch1:>6} {ch2:>6}{marker}")

print()
print("=" * 78)
print("DONE")
print("=" * 78)