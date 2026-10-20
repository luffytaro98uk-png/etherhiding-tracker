import base64
from web3 import Web3
import os
from dotenv import load_dotenv

load_dotenv()
w3 = Web3(Web3.HTTPProvider(os.getenv('ALCHEMY_RPC_URL')))

addr = Web3.to_checksum_address('0xb8fB2bfb182A172b29C365AD6CF743449975C418')
raw = w3.eth.call({'to': addr, 'data': '0xb68d1809'})

# Decode ABI string
offset = int.from_bytes(raw[0:32], 'big')
length = int.from_bytes(raw[offset:offset+32], 'big')
data = raw[offset+32:offset+32+length]

print(f'ABI string length: {length} bytes')
print(f'Raw: {data.hex()[:80]}...')

# Hex-decode the ASCII hex string
try:
    b64_string = bytes.fromhex(data.decode('ascii'))
    print(f'After hex decode: {b64_string[:80]}...')
except Exception as e:
    print(f'Hex decode failed: {e}')
    exit(1)

# Base64-decode
try:
    binary_blob = base64.b64decode(b64_string)
    print(f'Binary blob: {len(binary_blob)} bytes')
    print(f'Hex: {binary_blob.hex()}')
except Exception as e:
    print(f'Base64 decode failed: {e}')
    exit(1)

# XOR with cocova key
key = bytes.fromhex('341d91b1693dbbd10877bed632fbd228')
xored = bytes(binary_blob[i] ^ key[i % 16] for i in range(len(binary_blob)))
print(f'XOR result hex: {xored.hex()}')
print(f'XOR result ASCII: {xored.decode("utf-8", errors="replace")}')

# Try GuidePoint keys
for keyname, keystr in [('GuidePoint', '24255729245766676c3334'), ('Traffic', '21736466242647333231')]:
    try:
        k = bytes.fromhex(keystr)
        xored2 = bytes(binary_blob[i] ^ k[i % len(k)] for i in range(len(binary_blob)))
        print(f'{keyname} XOR: {xored2.hex()}')
        print(f'  ASCII: {xored2.decode("utf-8", errors="replace")}')
    except Exception:
        pass