import os
import time
import requests
from web3 import Web3
from dotenv import load_dotenv

load_dotenv()
ALCHEMY_URL = os.getenv('ALCHEMY_RPC_URL')
w3 = Web3(Web3.HTTPProvider(ALCHEMY_URL))

OPERATOR_WALLETS = [
    '0xd802C9427ce416B9DAb2db5aDD76EfAA6d9d826a',
    '0x6a6e177dcf992ac16f7367c14b26a3cf4775dfde',
]

def get_all_transfers(wallet_address):
    """Fetch all external transfers for a wallet using Alchemy's Transfers API."""
    all_transfers = []
    page_key = None
    
    while True:
        params = {
            "fromBlock": "0x0",
            "toBlock": "latest",
            "fromAddress": wallet_address,
            "category": ["external", "internal"],
            "excludeZeroValue": False,
            "maxCount": "0x3e8",  # 1000
            "withMetadata": True,
        }
        if page_key:
            params["pageKey"] = page_key
        
        payload = {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "alchemy_getAssetTransfers",
            "params": [params],
        }
        
        r = requests.post(ALCHEMY_URL, json=payload, timeout=30)
        data = r.json()
        
        if "error" in data:
            print(f"  API error: {data['error']}")
            break
        
        result = data.get("result", {})
        transfers = result.get("transfers", [])
        all_transfers.extend(transfers)
        
        page_key = result.get("pageKey")
        if not page_key:
            break
        
        time.sleep(0.3)  # Be nice to the API
    
    return all_transfers

def get_contract_address_from_tx(tx_hash):
    """Get the deployed contract address from a transaction receipt."""
    try:
        receipt = w3.eth.get_transaction_receipt(tx_hash)
        return receipt.get('contractAddress')
    except Exception as e:
        return None

print("=" * 70)
print("WALLET HISTORY RECONSTRUCTION (Alchemy Transfers API)")
print("=" * 70)
print()

all_deployed = []

for wallet in OPERATOR_WALLETS:
    wallet_addr = Web3.to_checksum_address(wallet)
    print(f"Wallet: {wallet_addr}")
    
    transfers = get_all_transfers(wallet_addr)
    print(f"  Total transfers: {len(transfers)}")
    
    # Contract deployments have 'to' = None
    deployments = [t for t in transfers if t.get('to') is None]
    print(f"  Contract deployments (to=null): {len(deployments)}")
    
    for dep in deployments:
        tx_hash = dep.get('hash')
        block = dep.get('blockNum')
        timestamp = dep.get('metadata', {}).get('blockTimestamp', 'unknown')
        
        contract_addr = get_contract_address_from_tx(tx_hash)
        
        if contract_addr:
            contract_addr = Web3.to_checksum_address(contract_addr)
            print(f"\n    Deployed: {contract_addr}")
            print(f"      Block: {block}")
            print(f"      Time:  {timestamp}")
            print(f"      Tx:    {tx_hash}")
            all_deployed.append(contract_addr)
        else:
            print(f"\n    Tx (could not resolve contract addr): {tx_hash}")
    
    print()

print("=" * 70)
print(f"TOTAL CONTRACTS DEPLOYED: {len(all_deployed)}")
print("=" * 70)

# Save to file
with open('deployed_contracts.txt', 'w') as f:
    for addr in all_deployed:
        f.write(addr + '\n')
print("\nSaved to deployed_contracts.txt")

# Fingerprint each discovered contract
print()
print("=" * 70)
print("FINGERPRINTING DISCOVERED CONTRACTS")
print("=" * 70)
print()

C2_GETTER = 'b68d1809'
OWNER_SEL = '8da5cb5b'
TRANSFER_SEL = 'f2fde38b'

for raw_addr in all_deployed:
    try:
        addr = Web3.to_checksum_address(raw_addr)
        code = w3.eth.get_code(addr)
        
        if len(code) == 0:
            print(f"  {addr}  [empty]")
            continue
        
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
        
        print(f"  {addr}")
        print(f"    bytecode={len(code)}  getter={has_getter}  ownable={has_ownable}")
        print(f"    VERDICT: {verdict}")
        print()
    except Exception as e:
        print(f"  {raw_addr}  ERROR: {str(e)[:80]}")
        print()

print("=== Done ===")