from web3 import Web3
import os
import re
from dotenv import load_dotenv

load_dotenv()
w3 = Web3(Web3.HTTPProvider(os.getenv('ALCHEMY_RPC_URL')))

contracts = {
    'primary':       '0xde2d34339c279a7a79bc4fc1c4f37d3c055211b7',
    'sibling':       '0xa982e044217b6bbaa7b3123b670c1c0ca1138a37',
    'wallet2_first': '0x308e9ecc849533a042f13fd77e5c82ec3c62e9f2',
}

for name, raw_addr in contracts.items():
    addr = Web3.to_checksum_address(raw_addr)
    code = w3.eth.get_code(addr)

    print(f"=== {name}: {addr} ===")
    print(f"Bytecode: {len(code)} bytes")

    if len(code) == 0:
        print("  (empty contract)")
        print()
        continue

    hexcode = code.hex()
    # Solidity dispatch: PUSH4 <selector> EQ  => pattern 63xxxxxxxx14
    sels = sorted(set(re.findall(r'63([0-9a-f]{8})14', hexcode)))

    print(f"Selectors found: {len(sels)}")
    for s in sels:
        print(f"  0x{s}")

    print()