"""
Fetch and decode the operator wallet's transaction history.

Uses the Etherscan V2 API (chainid=137 for Polygon) to list all
transactions from the operator wallet, then decodes the calldata
for writes to the two known contracts.
"""
import os
import time
import requests
from dotenv import load_dotenv

load_dotenv()

API_KEY = os.getenv("EXPLORER_API_KEY")
if not API_KEY:
    print("ERROR: EXPLORER_API_KEY not set.")
    print("Run: $env:EXPLORER_API_KEY=\"your_key\"")
    exit(1)

WALLET = "0x34c15320d6E8f59f1b66f6c191Aaa7F87B894B66"
XOR_KEY = bytes.fromhex('341d91b1693dbbd10877bed632fbd228')

TARGETS = {
    "0x08207b087f61d7e95e441e15fd6d40befd6ed308": "0x08207B",
    "0x4af8048edfe4523953e9907528bf5cef7fa8db09": "0x4af804",
    "0x2b2e30da517b22a20eb367a36b9ca725cf93e9e5": "0x2B2e30",
    "0x56384ef15734cce9026d9e75ac3be616513fe2ae": "0x56384E",
}


def try_xor_decode(hex_input):
    """Try to find and XOR-decode a 22-byte hostname in the calldata."""
    if not hex_input or hex_input == '0x':
        return None
    try:
        raw = bytes.fromhex(hex_input[2:])
    except Exception:
        return None
    for start in range(0, max(1, len(raw) - 22 + 1)):
        chunk = raw[start:start + 22]
        decrypted = bytes(chunk[i] ^ XOR_KEY[i % 16] for i in range(len(chunk)))
        try:
            text = decrypted.decode('utf-8')
            if text.startswith('http') or 'cocova' in text:
                return text
        except Exception:
            pass
    return None


def try_ascii_decode(hex_input):
    """Try to find ASCII URL text in the calldata."""
    if not hex_input or hex_input == '0x':
        return None
    try:
        raw = bytes.fromhex(hex_input[2:])
        text = raw.decode('utf-8', errors='ignore')
        import re
        matches = re.findall(r'https?://[a-zA-Z0-9\.\-/_]+', text)
        return matches[0] if matches else None
    except Exception:
        return None


def fetch_page(page):
    url = "https://api.etherscan.io/v2/api"
    params = {
        "chainid": 137,
        "module": "account",
        "action": "txlist",
        "address": WALLET,
        "startblock": 0,
        "endblock": 99999999,
        "page": page,
        "offset": 100,
        "sort": "asc",
        "apikey": API_KEY,
    }
    r = requests.get(url, params=params, timeout=30)
    return r.json()


print("=" * 78)
print("WRITE HISTORY — operator wallet 0x34c153...")
print("=" * 78)
print()

all_txs = []
page = 1
while True:
    data = fetch_page(page)
    status = data.get("status")
    if status != "1":
        if page == 1:
            print(f"API error: {data.get('message')}")
            print(f"Full response: {data}")
            exit(1)
        break
    txs = data.get("result", [])
    if not txs:
        break
    all_txs.extend(txs)
    if len(txs) < 100:
        break
    page += 1
    time.sleep(0.25)

print(f"Total transactions fetched: {len(all_txs)}")
print()

# Filter for writes to known contracts
writes = [tx for tx in all_txs if tx.get("to", "").lower() in TARGETS]
print(f"Writes to known contracts: {len(writes)}")
print()

for tx in writes:
    to = tx["to"].lower()
    ts = int(tx["timeStamp"])
    readable = time.strftime("%Y-%m-%d %H:%M:%S UTC", time.gmtime(ts))
    method = tx.get("methodId", "0x")
    inp = tx.get("input", "0x")
    is_error = tx.get("isError", "0")

    print(f"--- {readable} ---")
    print(f"  Block:   {tx['blockNumber']}")
    print(f"  Nonce:   {tx['nonce']}")
    print(f"  To:      {TARGETS[to]}")
    print(f"  Method:  {method}")
    print(f"  Hash:    {tx['hash']}")
    print(f"  Status:  {'REVERTED' if is_error == '1' else 'OK'}")

    # Try to decode the input as a plaintext URL (for 0x08207B)
    plain = try_ascii_decode(inp)
    if plain:
        print(f"  Plaintext URL: {plain}")

    # Try XOR decode (for 0x4af804)
    xored = try_xor_decode(inp)
    if xored:
        print(f"  XOR-decoded:   {xored}")

    # Show raw input if nothing decoded
    if not plain and not xored:
        print(f"  Input (raw):   {inp[:130]}")

    print()

print("=" * 78)
print("DONE")
print("=" * 78)