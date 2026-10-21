import json

with open('watchlist.json') as f:
    d = json.load(f)

# Read live_urls.txt as UTF-16 if it has a BOM, otherwise UTF-8
raw = open('live_urls.txt', 'rb').read()
if raw.startswith(b'\xff\xfe'):
    text = raw.decode('utf-16-le')
elif raw.startswith(b'\xfe\xff'):
    text = raw.decode('utf-16-be')
else:
    text = raw.decode('utf-8')

lines = [l.strip() for l in text.splitlines() if l.strip()]
print(f"Lines read: {len(lines)}")

live = [l.replace('https://', '').replace('http://', '').split('/')[0] for l in lines]
live = [x for x in live if x and 'example' not in x and 'localhost' not in x]
print(f"Cleaned domains: {len(live)}")

before = len(d.get('domains', []))
d['domains'] = sorted(set(d.get('domains', []) + live))
after = len(d['domains'])

print(f"Domains before: {before}")
print(f"Domains after: {after}")

with open('watchlist.json', 'w') as f:
    json.dump(d, f, indent=2)

print("Written to watchlist.json")