from web3 import Web3
import os
from dotenv import load_dotenv

load_dotenv()
w3 = Web3(Web3.HTTPProvider(os.getenv('ALCHEMY_RPC_URL')))

# Selector that identifies the C2 getter
C2_GETTER = 'b68d1809'

# Function selectors that identify OpenZeppelin Ownable
OWNER_SEL = '8da5cb5b'           # owner()
TRANSFER_SEL = 'f2fde38b'         # transferOwnership(address)

def is_etherhiding_contract(address):
    """Return a dict of detection signals for a contract address."""
    addr = Web3.to_checksum_address(address)
    code = w3.eth.get_code(addr)
    signals = {
        'address': addr,
        'has_code': len(code) > 0,
        'bytecode_size': len(code),
        'has_c2_getter': False,
        'has_ownable': False,
        'encrypted_blob': None,
        'blob_length': 0,
        'owner': None,
    }

    if not signals['has_code']:
        return signals

    # Check for the three key selectors in bytecode
    hexcode = code.hex()
    signals['has_c2_getter'] = C2_GETTER in hexcode
    signals['has_ownable'] = OWNER_SEL in hexcode and TRANSFER_SEL in hexcode

    # If it has the C2 getter, try to call it
    if signals['has_c2_getter']:
        try:
            result = w3.eth.call({'to': addr, 'data': '0x' + C2_GETTER})
            signals['blob_length'] = len(result)
            if len(result) > 32:
                # Decode ABI string
                offset = int.from_bytes(result[0:32], 'big')
                if offset + 32 <= len(result):
                    length = int.from_bytes(result[offset:offset+32], 'big')
                    if 0 < length < 500:
                        data = result[offset+32:offset+32+length]
                        import base64
                        try:
                            signals['encrypted_blob'] = base64.b64encode(data).decode('ascii')
                        except Exception:
                            signals['encrypted_blob'] = data.hex()
        except Exception as e:
            signals['encrypted_blob'] = f"CALL FAILED: {str(e)[:80]}"

    # Try reading owner()
    if signals['has_ownable']:
        try:
            result = w3.eth.call({'to': addr, 'data': '0x' + OWNER_SEL})
            if len(result) >= 32:
                owner_bytes = result[12:32]
                signals['owner'] = Web3.to_checksum_address('0x' + owner_bytes.hex())
        except Exception:
            pass

    return signals


# Known EtherHiding contracts to fingerprint
known = [
    '0xde2d34339c279a7a79bc4fc1c4f37d3c055211b7',
    '0xa982e044217b6bbaa7b3123b670c1c0ca1138a37',
    '0x308e9ecc849533a042f13fd77e5c82ec3c62e9f2',
]

# Known operator wallets (from GuidePoint report)
operator_wallets = [
    '0xd802C9427ce416B9DAb2db5aDD76EfAA6d9d826a',
    '0x6a6e177dcf992ac16f7367c14b26a3cf4775dfde',
]

print("=" * 70)
print("ETHERHIDING CONTRACT FINGERPRINT")
print("=" * 70)
print()

for addr in known:
    sig = is_etherhiding_contract(addr)
    print(f"Contract: {sig['address']}")
    print(f"  Bytecode size:     {sig['bytecode_size']} bytes")
    print(f"  Has C2 getter:     {sig['has_c2_getter']}")
    print(f"  Has Ownable:       {sig['has_ownable']}")
    print(f"  Owner:             {sig['owner']}")
    print(f"  Blob length:       {sig['blob_length']} bytes")
    if sig['encrypted_blob']:
        print(f"  Encrypted blob:    {sig['encrypted_blob']}")

    # Verdict
    if sig['has_c2_getter'] and sig['has_ownable'] and sig['blob_length'] > 32:
        print(f"  VERDICT:           *** CONFIRMED ETHERHIDING ***")
    elif sig['has_c2_getter']:
        print(f"  VERDICT:           suspicious (missing ownable or blob)")
    else:
        print(f"  VERDICT:           not EtherHiding")
    print()

print("=" * 70)
print("OPERATOR WALLET REFERENCE")
print("=" * 70)
for w in operator_wallets:
    print(f"  {Web3.to_checksum_address(w)}")