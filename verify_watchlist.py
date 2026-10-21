import json

with open('watchlist.json') as f:
    d = json.load(f)

print(f"Contracts: {len(d.get('contracts', []))}")
print(f"Wallets: {len(d.get('operator_wallets', []))}")
print(f"IPs: {len(d.get('ip_c2', []))}")
print(f"Domains: {len(d.get('domains', []))}")
print(f"Keys: {list(d.keys())}")