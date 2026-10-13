from web3 import Web3
import os
import re
from dotenv import load_dotenv

load_dotenv()
w3 = Web3(Web3.HTTPProvider(os.getenv('ALCHEMY_RPC_URL')))

# Template B contracts from your derive_contracts.py output
TEMPLATE_B = [
    '0x75A91aCdB3dd25B39fe0619d2A00DE49A8e56eb9',
    '0x4c7C35db1f8E23301a447801B019968D8b4A6329',
    '0x700121c474A1eF6b4BAC074e0B805F262a5BD46e',
    '0xd245e35d988244528F10582107Ce1BC38DA35a24',
    '0x96C90CD4E58718cb20A58e14b7931eD94Ad040C7',
    '0x0dC9f5de745394D98C0cE163D498043EB325AC45',
    '0xFad3F51fF70223CadeecCf8FCf2D362533f360eE',
    '0xB685a24587658989410D68500448f45467CA47D8',
    '0xed4417B3992A4e6613f734E720e24DE5630695f8',
    '0xA5517ea1914EbfcEcDe8528e0973D98E60178607',
    '0x5C4576E21809FfA8d265bB7385f044A693356c43',
]

# Template C (the 1441-byte one)
TEMPLATE_C = '0x46124F9F0f0d70c8b9e62258179574E05FbFF181'

def extract_selectors(bytecode_hex):
    """Extract all 4-byte function selectors from dispatch table."""
    sels = sorted(set(re.findall(r'63([0-9a-f]{8})14', bytecode_hex)))
    return sels

def extract_strings(bytecode_hex):
    """Extract any printable ASCII sequences of 4+ chars from bytecode."""
    strings = []
    # Find runs of printable ASCII in hex (each byte is 2 hex chars)
    for match in re.finditer(r'(?:[0-9a-f]{2}){4,}', bytecode_hex):
        raw = bytes.fromhex(match.group(0))
        text = ''.join(chr(c) if 32 <= c < 127 else '' for c in raw)
        # Split on non-printable boundaries
        for chunk in re.findall(r'[\x20-\x7e]{4,}', text):
            strings.append(chunk)
    return strings

def dump_storage(addr, slots=10):
    """Dump first N storage slots."""
    result = []
    for i in range(slots):
        try:
            val = w3.eth.get_storage_at(addr, i)
            if val != b'\x00' * 32:
                result.append((i, val.hex()))
        except Exception:
            pass
    return result

print("=" * 70)
print("TEMPLATE B ANALYSIS")
print("=" * 70)
print()

for i, raw_addr in enumerate(TEMPLATE_B):
    addr = Web3.to_checksum_address(raw_addr)
    code = w3.eth.get_code(addr)
    hexcode = code.hex()
    
    print(f"[{i+1}] {addr}")
    print(f"    Bytecode: {len(code)} bytes")
    
    sels = extract_selectors(hexcode)
    print(f"    Selectors ({len(sels)}):")
    for s in sels:
        print(f"      0x{s}")
    
    print()
    
    # Only dump storage on the first one to keep output small
    if i == 0:
        print(f"    Storage slots (non-zero):")
        storage = dump_storage(addr, 10)
        for slot_num, val in storage:
            print(f"      slot {slot_num}: {val}")
            # Try to decode as string
            try:
                raw_bytes = bytes.fromhex(val)
                text = raw_bytes.decode('utf-8', errors='ignore')
                printable = ''.join(c for c in text if c.isprintable())
                if printable and len(printable) > 4:
                    print(f"        as text: {printable}")
            except Exception:
                pass
        print()
        break  # Just do the first one for now

print("=" * 70)
print("TEMPLATE C ANALYSIS")
print("=" * 70)
print()

addr = Web3.to_checksum_address(TEMPLATE_C)
code = w3.eth.get_code(addr)
hexcode = code.hex()

print(f"{addr}")
print(f"  Bytecode: {len(code)} bytes")

sels = extract_selectors(hexcode)
print(f"  Selectors ({len(sels)}):")
for s in sels:
    print(f"    0x{s}")

# Try known EtherHiding selector
print()
print("  Testing selector 0xb68d1809 (C2 getter)...")
try:
    raw = w3.eth.call({'to': addr, 'data': '0xb68d1809'})
    print(f"    Result: {len(raw)} bytes")
    print(f"    Hex: {raw.hex()[:120]}")
except Exception as e:
    print(f"    REVERTED: {str(e)[:100]}")

# Try owner()
print()
print("  Testing selector 0x8da5cb5b (owner)...")
try:
    raw = w3.eth.call({'to': addr, 'data': '0x8da5cb5b'})
    if len(raw) >= 32:
        owner = Web3.to_checksum_address('0x' + raw[12:32].hex())
        print(f"    Owner: {owner}")
except Exception as e:
    print(f"    REVERTED: {str(e)[:100]}")

print()
print("  Storage slots:")
storage = dump_storage(addr, 10)
for slot_num, val in storage:
    print(f"    slot {slot_num}: {val}")
    try:
        raw_bytes = bytes.fromhex(val)
        text = raw_bytes.decode('utf-8', errors='ignore')
        printable = ''.join(c for c in text if c.isprintable())
        if printable and len(printable) > 4:
            print(f"      as text: {printable}")
    except Exception:
        pass

print()
print("=== Done ===")