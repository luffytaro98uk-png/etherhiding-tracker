import os
import time
import json
import rlp
from web3 import Web3
from dotenv import load_dotenv
from eth_utils import keccak

load_dotenv()
w3 = Web3(Web3.HTTPProvider(os.getenv('ALCHEMY_RPC_URL')))

WALLET = '0xCaf2C54E400437da717cF215181B170F65187aBf'


def derive_contract(deployer, n):
    encoded = rlp.encode([bytes.fromhex(deployer[2:]), n])
    return '0x' + keccak(encoded)[-20:].hex()


nonce = w3.eth.get_transaction_count(Web3.to_checksum_address(WALLET))
print(f'Wallet nonce: {nonce}')
print()

results = []

for n in range(nonce):
    try:
        addr = Web3.to_checksum_address(derive_contract(WALLET, n))
        code = w3.eth.get_code(addr)
        if len(code) == 0:
            continue

        slot1 = w3.eth.get_storage_at(addr, 1)
        hexval = slot1.hex()

        # Try to decode as Solidity short string
        last_byte = slot1[31]
        decoded = None
        if 0 < last_byte <= 62 and last_byte % 2 == 0:
            length = last_byte // 2
            try:
                decoded = slot1[:length].decode('utf-8')
            except Exception:
                pass

        results.append({
            'nonce': n,
            'address': addr,
            'bytecode': len(code),
            'slot1_raw': hexval,
            'slot1_decoded': decoded,
        })

        # Print everything — decoded or not
        print(f'[Nonce {n}] {addr} size={len(code)}')
        if decoded:
            print(f'  Decoded: {decoded[:80]}')
        else:
            print(f'  Raw: {hexval[:64]}')
        print()

        time.sleep(0.1)
    except Exception as e:
        print(f'[Nonce {n}] ERROR: {str(e)[:80]}')

print(f'\nTotal contracts with code: {len(results)}')
print(f'Contracts with decoded strings: {sum(1 for r in results if r["slot1_decoded"])}')

with open('all_contracts_slots.json', 'w') as f:
    json.dump(results, f, indent=2)
print('Saved to all_contracts_slots.json')