# Case Study: cocova.co Operator Infrastructure on Polygon

**Date:** 2026-10-15
**Status:** On-chain analysis complete
**Related:** [REPORT.md](./REPORT.md) (GuidePoint replication), [CASE_REPORT_2026-10-15.md](./CASE_REPORT_2026-10-15.md) (full detailed report)

---

## Summary

A previously unmapped EtherHiding operator was reconstructed from public 
blockchain data. Four contracts, 278 transactions, and the operator's 
storage encryption key were recovered.

**Headline findings:**

- **New C2 domain discovered:** `year[.]calvinpreschooloffice[.]com` — 
  not on the previously shared `*[.]cocova[.]co` list
- **XOR key recovered:** `341d91b1693dbbd10877bed632fbd228`
- **Seven-month domain history** reconstructed across 6 TLDs
- **Technical link to GuidePoint campaign** via shared selectors

---

## Operator Wallet
0x34c15320d6E8f59f1b66f6c191Aaa7F87B894B66

text

278 transactions on Polygon. Active since 2026-03-11.

---

## Contracts

| Contract | Role |
|---|---|
| `0x56384Ef15734CcE9026D9e75ac3bE616513fe2Ae` | Template A variant (dormant) |
| `0x08207B087F61d7e95E441E15fd6d40BEfd6eD308` | Plaintext C2 storage |
| `0x2B2e30dA517b22a20Eb367a36b9cA725cf93e9E5` | Control contract |
| `0x4af8048EdfE4523953E9907528BF5Cef7Fa8db09` | XOR-encrypted C2 storage |

---

## Decryption

The `0x4af804` contract stores hostnames XOR-encrypted with a 16-byte 
repeating key. The key was recovered from a single known plaintext / 
ciphertext pair:
Ciphertext: 5c69e5c11a0794fe6016d7ba1c98bd4b5b6bf09f0a52
Plaintext: https://hail[.]cocova[.]co
Key: 341d91b1693dbbd10877bed632fbd228

text

This key decrypts all current records in `0x4af804` and can be used to 
decrypt future hostname writes from this operator using the same scheme.

---

## Domains

### Current (October 2026)
hail[.]cocova[.]co
ruby[.]cocova[.]co
zinc[.]cocova[.]co
sand[.]cocova[.]co
raft[.]cocova[.]co

text

### Newly discovered
year[.]calvinpreschooloffice[.]com

text

### Historical (March 2026)
cloudflare-check[.]cfd
myverifyblog[.]sbs
webanalytics-cdn[.]cfd
myverifhouse[.]sbs
sitepromclop[.]click
microblogver[.]bond
mygoodblog[.]cfd
mygoodblog[.]bond
microloh[.]bond
mybiggestjoy[.]bond

text

---

## How to Reproduce

**1. Fingerprint the contracts:**

```bash
python cli.py fingerprint 0x08207B087F61d7e95E441E15fd6d40BEfd6eD308
python cli.py fingerprint 0x4af8048EdfE4523953E9907528BF5Cef7Fa8db09
2. Enumerate the operator's deployments:

bash
python cli.py wallet 0x34c15320d6E8f59f1b66f6c191Aaa7F87B894B66
3. Fetch the full write history:

bash
python write_history.py > write_history.txt
4. Decrypt the storage records:

bash
python decrypt.py
Expected output: 5 *[.]cocova[.]co hostnames.

5. Extract calldata for a specific write:

bash
python fetch_setter_calldata.py 0x15f3b206cbb898e910a63130ed3ff4dccff08599436a25e067e5170145e008f6
Expected output: https://year[.]calvinpreschooloffice[.]com

Tooling Used
Script	Purpose
cli.py	Fingerprint, wallet pivot, templates
write_history.py	Fetch full transaction history and decode calldata
decrypt.py	XOR decryption of encrypted storage
analyze.py	Selector extraction and storage dump
fetch_setter_calldata.py	Extract calldata from individual transactions
Verification
All findings are reproducible from public data:

Etherscan V2 API: api[.]etherscan[.]io/v2/api with chainid=137

Polygonscan: polygonscan[.]com/address/0x34c15320d6E8f59f1b66f6c191Aaa7F87B894B66

The year[.]calvinpreschooloffice[.]com write: block 95509254, tx 0x15f3b206cbb898e910a63130ed3ff4dccff08599436a25e067e5170145e008f6

OPSEC
All queries were read-only eth_call requests to Alchemy RPC or Etherscan V2 API.

Do not visit the C2 domains directly. The TDS at hail[.]cocova[.]co profiles visitors.

Use a sandbox (Any.run, Joe Sandbox, Triage) if domain verification is required.

Full Report
See CASE_REPORT_2026-10-15.md for the
complete technical analysis, including the full write history table,
calldata decode, and hypotheses for the calvinpreschooloffice[.]com finding.

text

### 3. Add the Full Report

Copy the detailed report you have into `CASE_REPORT_2026-10-15.md` in the repo root.

### 4. Add a `watchlist.json`

This is the piece that makes the repo extensible. Create `watchlist.json`:

```json
{
  "version": 1,
  "description": "Watchlist of malicious smart contracts identified by this toolset",
  "contracts": [
    {
      "address": "0x08207B087F61d7e95E441E15fd6d40BEfd6eD308",
      "chain": "polygon",
      "chain_id": 137,
      "label": "cocova case — plaintext C2 storage",
      "getter": "0x77343408",
      "storage_slot": 1,
      "encoding": "plaintext_url",
      "current_value": "https://hail[.]cocova[.]co",
      "discovered": "2026-10-15"
    },
    {
      "address": "0x4af8048EdfE4523953E9907528BF5Cef7Fa8db09",
      "chain": "polygon",
      "chain_id": 137,
      "label": "cocova case — XOR-encrypted C2 storage",
      "getter": "0x7d0c8f7a",
      "encoding": "abi_string",
      "cipher": {
        "type": "repeating_xor",
        "key_hex": "341d91b1693dbbd10877bed632fbd228",
        "period": 16
      },
      "discovered": "2026-10-15"
    },
    {
      "address": "0x56384Ef15734CcE9026D9e75ac3bE616513fe2Ae",
      "chain": "polygon",
      "chain_id": 137,
      "label": "cocova case — Template A variant (dormant)",
      "getter": "0xb68d1809",
      "discovered": "2026-10-15"
    },
    {
      "address": "0x2B2e30dA517b22a20Eb367a36b9cA725cf93e9E5",
      "chain": "polygon",
      "chain_id": 137,
      "label": "cocova case — control contract",
      "discovered": "2026-10-15"
    }
  ],
  "operator_wallets": [
    {
      "address": "0x34c15320d6E8f59f1b66f6c191Aaa7F87B894B66",
      "label": "cocova case operator",
      "discovered": "2026-10-15"
    }
  ]
}
This is the seed. Anyone who discovers another related contract can add it to the list.

5. Update the Main README.md
Add a short section near the top:

markdown
## Case Studies

This toolset has been applied to two investigations:

- **[GuidePoint replication (2026-10)](./REPORT.md)** — reproduced the 
  EtherHiding contract enumeration published by GuidePoint Security
- **[cocova.co operator (2026-10-15)](./CASE_cocova.md)** — mapped a 
  live operator's full infrastructure, recovered the XOR key, and 
  discovered a new C2 domain

See [`watchlist.json`](./watchlist.json) for the current list of 
tracked contracts and operator wallets.