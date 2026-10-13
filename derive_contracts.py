from web3 import Web3
import os
from dotenv import load_dotenv

load_dotenv()
w3 = Web3(Web3.HTTPProvider(os.getenv('ALCHEMY_RPC_URL')))

OPERATOR_WALLETS = [
    '0xd802C9427ce416B9DAb2db5aDD76EfAA6d9d826a',
    '0x6a6e177dcf992ac16f7367c14b26a3cf4775dfde',
]

def compute_contract_address(deployer, nonce):
    """Compute contract address from deployer and nonce using CREATE opcode logic."""
    import rlp
    from eth_utils import keccak
    
    deployer_bytes = bytes.fromhex(deployer[2:])
    encoded = rlp.encode([deployer_bytes, nonce])
    contract_hash = keccak(encoded)
    return '0x' + contract_hash[-20:].hex()

C2_GETTER = 'b68d1809'
OWNER_SEL = '8da5cb5b'
TRANSFER_SEL = 'f2fde38b'

print("=" * 70)
print("DERIVING CONTRACT ADDRESSES FROM WALLET NONCES")
print("=" * 70)
print()

for raw_wallet in OPERATOR_WALLETS:
    wallet = Web3.to_checksum_address(raw_wallet)
    nonce = w3.eth.get_transaction_count(wallet)
    
    print(f"Wallet: {wallet}")
    print(f"  Total transactions (nonce): {nonce}")
    print()
    
    # Compute contract address for every nonce
    for n in range(nonce):
        try:
            addr = Web3.to_checksum_address(compute_contract_address(wallet, n))
            code = w3.eth.get_code(addr)
            
            if len(code) > 0:
                hexcode = code.hex()
                has_getter = C2_GETTER in hexcode
                has_ownable = OWNER_SEL in hexcode and TRANSFER_SEL in hexcode
                
                verdict = "not EtherHiding"
                if has_getter and has_ownable:
                    try:
                        raw = w3.eth.call({'to': addr, 'data': '0x' + C2_GETTER})
                        if len(raw) > 100:
                            verdict = "*** CONFIRMED ETHERHIDING ***"
                        else:
                            verdict = "suspicious (short blob)"
                    except Exception:
                        verdict = "suspicious (getter failed)"
                
                print(f"  Nonce {n}: {addr}")
                print(f"    bytecode={len(code)}  getter={has_getter}  ownable={has_ownable}")
                print(f"    VERDICT: {verdict}")
                print()
        except Exception as e:
            print(f"  Nonce {n}: ERROR - {str(e)[:80]}")
    
    print()