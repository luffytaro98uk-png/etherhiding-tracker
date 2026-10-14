"""
Fetch and decode setData() calldata from known EtherHiding transactions.

For each transaction hash, this script:
1. Fetches the raw transaction
2. Extracts the calldata
3. Confirms the selector is 0x47064d6a (setData)
4. Decodes the ABI-encoded string argument
5. Prints the base64 payload
"""
import os
import base64
from web3 import Web3
from dotenv import load_dotenv

load_dotenv()
w3 = Web3(Web3.HTTPProvider(os.getenv('ALCHEMY_RPC_URL')))

SETTER_SELECTOR = '0x47064d6a'

# Transactions to decode: (tx_hash, target_contract, block, age_description)
TRANSACTIONS = [
    # Template B - contract 0x5C4576E2 (3 writes)
    ('0xeb9432756da741e756ad83d56a611a1277fdcbf51618a9960e4888d9b3aa6fbf',
     '0x5C4576E21809FfA8d265bB7385f044A693356c43', 90694377, '83 days ago'),
    ('0x682bb55b0bd8c21e3009a2e205880b84934d31410c6a2af6b7dec78ca7017026',
     '0x5C4576E21809FfA8d265bB7385f044A693356c43', 90334311, '89 days ago'),
    ('0xdd44cc31f9a18bd60bbfc5039906bc5d8d18ffa294c19df9c225e6db088c5f8f',
     '0x5C4576E21809FfA8d265bB7385f044A693356c43', 86520883, '160 days ago'),

    # Template B - contract 0xFad3F51f (3 writes, same hour)
    ('0x5619ed4ab75ed5fe87d9b083f7f22a8fef7c6a7957b829d371400f9dfed44c4e',
     '0xFad3F51fF70223CadeecCf8FCf2D362533f360eE', 86434517, '161 days ago'),
    ('0x2724924bf32fc406e089ddc20549f7e9b2aff70b038637cda56f666e55aa4c66',
     '0xFad3F51fF70223CadeecCf8FCf2D362533f360eE', 86434239, '161 days ago'),
    ('0x834526f5ef91354238b923b87219e256ba0c72bf4760f41f7e20e10952f319c0',
     '0xFad3F51fF70223CadeecCf8FCf2D362533f360eE', 86434237, '161 days ago'),

    # Template B - other contracts
    ('0x13fd779d3ac1567578b75cd499886e91b70e4bdf401c0dad766cfc4bac34b96b',
     '0xB685a24587658989410D68500448f45467CA47D8', 86434300, '161 days ago'),
    ('0xe4417e2c5a0825d132828d6752518b4b65824301542bc0d3c947e12b15c4433c',
     '0xed4417B3992A4e6613f734E720e24DE5630695f8', 86434564, '161 days ago'),
    ('0x301778638d4f7d56c5249c4177727de83c571a2a45c5c106b8e6279e1b81dbb0',
     '0xA5517ea1914EbfcEcDe8528e0973D98E60178607', 86435182, '161 days ago'),

    # Template A - Update Domain calls
    ('0x348def13601954b0684a6f827478d5a3470e3e07f2583e998bb5091231fcff13',
     '0x308e9ecc849533a042f13fD77E5C82eC3c62e9f2', 80402130, '301 days ago'),
    ('0xa6817c30c87c816075174f9f84489028e44f65c6ebaa5ee53fa367e08b20c279',
     '0x308e9ecc849533a042f13fD77E5C82eC3c62e9f2', 80401978, '301 days ago'),
]


def decode_setdata_string(calldata_hex):
    """
    Decode an ABI-encoded setData(string) call.
    calldata_hex: the full calldata including the 4-byte selector
    Returns: (selector, decoded_string) or (selector, error)
    """
    if not calldata_hex.startswith('0x'):
        calldata_hex = '0x' + calldata_hex

    raw = bytes.fromhex(calldata_hex[2:])
    if len(raw) < 4:
        return None, 'calldata too short'

    selector = '0x' + raw[:4].hex()
    args = raw[4:]

    if len(args) < 64:
        return selector, 'args too short for ABI string'

    # ABI string: [offset (32)] [length (32)] [data ...]
    offset = int.from_bytes(args[0:32], 'big')
    if offset + 32 > len(args):
        return selector, 'invalid offset'

    length = int.from_bytes(args[offset:offset+32], 'big')
    data_start = offset + 32
    data_end = data_start + length

    if data_end > len(args):
        return selector, f'length {length} exceeds available data'

    string_bytes = args[data_start:data_end]

    try:
        decoded = string_bytes.decode('utf-8')
        return selector, decoded
    except UnicodeDecodeError:
        return selector, f'binary data: {string_bytes.hex()}'


print("=" * 78)
print("SETTER CALLDATA ANALYSIS")
print("=" * 78)
print()

results = []

for tx_hash, target, block, age in TRANSACTIONS:
    print(f"Block {block} ({age})")
    print(f"  Target: {target}")
    print(f"  Tx:     {tx_hash[:20]}...")

    try:
        tx = w3.eth.get_transaction(tx_hash)

        # Verify sender
        sender = tx['from']
        print(f"  From:   {sender}")

        # Verify target
        tx_to = tx['to']
        if tx_to and tx_to.lower() != target.lower():
            print(f"  WARNING: tx.to ({tx_to}) != expected target ({target})")

        # Decode calldata
        calldata = tx['input'].hex()
        if not calldata.startswith('0x'):
            calldata = '0x' + calldata

        selector, payload = decode_setdata_string(calldata)

        print(f"  Selector: {selector}")
        print(f"  Payload:  {payload}")

        if selector == SETTER_SELECTOR:
            print(f"  ✓ Correct setData selector")

        # Try base64 decode
        if isinstance(payload, str) and not payload.startswith('binary'):
            try:
                decoded_bytes = base64.b64decode(payload)
                print(f"  Base64 decodes to: {len(decoded_bytes)} bytes")
                print(f"  Hex: {decoded_bytes.hex()}")
            except Exception as e:
                print(f"  Base64 decode failed: {e}")

        results.append({
            'block': block,
            'age': age,
            'target': target,
            'selector': selector,
            'payload': payload,
        })

    except Exception as e:
        print(f"  ERROR: {e}")

    print()

# Summary: group by contract
print("=" * 78)
print("GROUPED BY TARGET CONTRACT")
print("=" * 78)
print()

by_target = {}
for r in results:
    by_target.setdefault(r['target'], []).append(r)

for target, entries in by_target.items():
    print(f"\n{target}")
    print(f"  {len(entries)} write(s)")
    payloads = set()
    for e in sorted(entries, key=lambda x: x['block']):
        print(f"    Block {e['block']} ({e['age']}): {e['payload']}")
        payloads.add(e['payload'])
    if len(payloads) == 1:
        print(f"  → All writes contain the SAME payload (no rotation)")
    else:
        print(f"  → {len(payloads)} DIFFERENT payloads (rotation confirmed)")

print()
print("=" * 78)
print("DONE")
print("=" * 78)