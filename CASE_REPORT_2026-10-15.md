

---

# Case Report: EtherHiding Infrastructure on Polygon — Full Operator Mapping and New Domain Discovery

**Analyst:** Himanshu Pandey
**Date:** 2026-10-15
**Chain:** Polygon Mainnet (chain ID 137)
**Classification:** TLP:AMBER (verify before sharing)
**Status:** On-chain analysis complete; malware-sample confirmation pending

---

## 1. Executive Summary

A previously unmapped operator running an EtherHiding-style C2 infrastructure on Polygon has been fully reconstructed from public blockchain data. Four contracts, 278 transactions spanning seven months, and the operator's storage encryption key have been recovered.

**Headline findings:**

1. **New C2 domain discovered:** `year[.]calvinpreschooloffice[.]com` — not on the previously shared `*[.]cocova[.]co` list. Written to contract `0x4af804` on 2026-10-14 09:13 UTC, then reverted 45 minutes later.
2. **XOR encryption key recovered:** `341d91b1693dbbd10877bed632fbd228` — a 16-byte repeating-key XOR cipher protecting the operator's hostname pool.
3. **Seven-month domain history reconstructed:** 12+ domains across `.cfd`, `.sbs`, `.click`, `.bond`, `.com`, and `.co` TLDs.
4. **Technical link to GuidePoint campaign:** Contract `0x56384E` shares the C2 getter (`0xb68d1809`) and setter (`0xb249cd2d`) selectors with GuidePoint Security's published Template A.

---

## 2. Background

EtherHiding is a technique in which malware retrieves its command-and-control (C2) address by reading a smart contract on a public blockchain instead of contacting a hardcoded domain. The read is performed with `eth_call` — no gas, no transaction record. Operators rotate the C2 by writing a new value to the contract; every rotation is permanently recorded on-chain.

This case concerns a `cocova[.]co` TLD campaign previously shared by a peer analyst. The peer's indicators comprised five hostnames. The analysis below extends that work to the operator's full infrastructure.

---

## 3. Operator Wallet

**Address:** `0x34c15320d6E8f59f1b66f6c191Aaa7F87B894B66`

**Total transactions:** 278
**Active since:** 2026-03-11
**Current nonce:** 275

The wallet has deployed four contracts across nonces 0, 2, 48, and 270. All other transactions are calls to those contracts or (in one case) a reverted call.

---

## 4. Contracts Deployed

### 4.1 `0x56384Ef15734CcE9026D9e75ac3bE616513fe2Ae` — Template A Variant (Dormant)

| Property | Value |
|---|---|
| Bytecode size | 2410 bytes |
| Code hash (SHA3-256, first 16) | `c2723847c13faa8f` |
| Selectors | `0xb249cd2d`, `0xb68d1809`, `0xe096a091`, `0xf851a440` (`admin()`) |
| Non-zero storage slots | Slot 5 = operator wallet |
| Getter `0xb68d1809` status | Reverts with `invalid jump destination` |

**Critical finding:** This contract shares two selectors with GuidePoint Security's published Template A:

| Selector | Function | Role |
|---|---|---|
| `0xb68d1809` | C2 getter | Same as GuidePoint Template A |
| `0xb249cd2d` | Setter (Update Domain) | Same as GuidePoint Template A |

This contract was the operator's first deployment (nonce 0, 2026-03-11). The first attempted write to it (nonce 1) reverted. The operator then switched to `0x08207B`.

### 4.2 `0x08207B087F61d7e95E441E15fd6d40BEfd6eD308` — Plaintext C2 Storage

| Property | Value |
|---|---|
| Bytecode size | 2451 bytes |
| Code hash (SHA3-256, first 16) | `9e29ad7f192e11c0` |
| Selectors | `0x38bcdc1c`, `0x5600f04f`, `0x77343408`, `0xf851a440` (`admin()`) |
| Non-zero storage | Slot 0 = operator wallet; Slot 1 = `https://hail[.]cocova[.]co` (plaintext) |
| Setter | `0x77343408` |

This contract stores the active C2 URL in plaintext at slot 1. The plaintext design is a departure from GuidePoint's encrypted ABI-encoded payloads.

### 4.3 `0x2B2e30dA517b22a20Eb367a36b9cA725cf93e9E5` — Control Contract

| Property | Value |
|---|---|
| Bytecode size | 3143 bytes |
| Code hash (SHA3-256, first 16) | `4dfdd50183c5c573` |
| Selectors | `0x38bcdc1c`, `0x41c0e1b5`, `0x4fb2e45d`, `0x65c43cc7`, `0x8da5cb5b` (`owner()`), `0xd11db010` |
| Non-zero storage | Slot 0 = operator wallet; Slots 1-2 = counters (513, 4) |
| Setter | `0xd11db010` |

Standard Ownable pattern. Likely coordinates the other contracts. Shares selector `0x38bcdc1c` with `0x08207B`.

### 4.4 `0x4af8048EdfE4523953E9907528BF5Cef7Fa8db09` — XOR-Encrypted C2 Storage

| Property | Value |
|---|---|
| Bytecode size | 2426 bytes |
| Code hash (SHA3-256, first 16) | `68d32ec9f265c336` |
| Selectors | `0x37548408`, `0x7d0c8f7a`, `0xf851a440` (`admin()`) |
| Non-zero storage | Slot 0 = operator wallet; Slots 2-6 = 5 encrypted records |
| Setter | `0x7d0c8f7a` |

This is the current C2 storage contract. Slots 2-6 hold 5 encrypted hostnames using a repeating-key XOR cipher.

---

## 5. Encryption Analysis

### 5.1 Cipher Identification

Each encrypted record in `0x4af804` slots 2-6 is a 22-byte or 38-byte string structured as:

```
[8-byte shared header] [4-byte unique value] [10-byte shared suffix]
```

Only the 4-byte middle segment varies across the 5 records. Byte-frequency analysis, single-byte XOR brute force, and multi-ciphertext XOR all ruled out:
- The two known campaign XOR keys (`$%)W$fgl34`, `!sdf$&G321`)
- Base64, UTF-8, or other simple encodings

### 5.2 Key Recovery

By XORing the first record against the known plaintext `https://hail[.]cocova[.]co` (22 bytes), the key stream was recovered:

```
5c69e5c11a0794fe6016d7ba1c98bd4b5b6bf09f0a52  (ciphertext)
XOR
68747470733a2f2f6861696c2e636f636f76612e636f  (plaintext)
=
341d91b1693dbbd10877bed632fbd228341d91b1693d  (repeating key)
```

The key repeats with a period of **16 bytes**:

```
341d91b1693dbbd10877bed632fbd228
```

### 5.3 Decrypted Hostname Pool

Applying the key to all 5 records in `0x4af804` slots 2-6:

| Slot | Ciphertext (first 16 bytes) | Decrypted Plaintext |
|---|---|---|
| 2 | `5c69e5c11a0794fe6016d7ba...` | `https://hail[.]cocova[.]co` |
| 3 | `5c69e5c11a0794fe7a02dcaf...` | `https://ruby[.]cocova[.]co` |
| 4 | `5c69e5c11a0794fe721ed0b5...` | `https://zinc[.]cocova[.]co` |
| 5 | `5c69e5c11a0794fe7b16d0b2...` | `https://sand[.]cocova[.]co` |
| 6 | `5c69e5c11a0794fe7a16d8a2...` | `https://raft[.]cocova[.]co` |

These five hostnames match the list previously shared by a peer.

---

## 6. Write History (Full Transaction Reconstruction)

The full transaction history was recovered via the Etherscan V2 API (`chainid=137`), then decoded locally. The following is the complete write log for the operator wallet.

### Phase 1 — Initial Setup and Rapid Rotation (March 2026)

| Date (UTC) | Nonce | Contract | Value | Status |
|---|---|---|---|---|
| 2026-03-11 19:46:47 | 1 | `0x56384E` | `https://cloudflare-check[.]cfd` | **REVERTED** |
| 2026-03-11 19:49:17 | 3 | `0x08207B` | `https://cloudflare-check[.]cfd` | OK |
| 2026-03-13 17:27:15 | 4 | `0x08207B` | `https://myverifyblog[.]sbs/` | OK |
| 2026-03-16 08:39:03 | 5 | `0x08207B` | `https://webanalytics-cdn[.]cfd/` | OK |
| 2026-03-18 21:51:45 | 6 | `0x08207B` | `https://myverifhouse[.]sbs` | OK |
| 2026-03-20 23:26:19 | 7 | `0x08207B` | `https://sitepromclop[.]click` | OK |
| 2026-03-20 23:33:03 | 8 | `0x08207B` | `https://sitepromclop[.]click/land/` | OK |
| 2026-03-21 00:01:05 | 9 | `0x08207B` | `https://sitepromclop[.]click` | OK |
| 2026-03-21 00:02:31 | 10 | `0x08207B` | `https://sitepromclop[.]click/land/` | OK |
| 2026-03-23 10:21:47 | 11 | `0x08207B` | `https://microblogver[.]bond` | OK |
| 2026-03-23 10:21:59 | 12 | `0x08207B` | `https://microblogver[.]bond/land/` | OK |
| 2026-03-23 11:33:53 | 13 | `0x08207B` | `https://mygoodblog[.]cfd` | OK |
| 2026-03-23 11:36:01 | 14 | `0x08207B` | `https://mygoodblog[.]bond` | OK |
| 2026-03-23 13:02:01 | 15 | `0x08207B` | `https://microloh[.]bond` | OK |
| 2026-03-23 13:02:01 | 16 | `0x08207B` | `https://microloh[.]bond` | OK |
| 2026-03-30 00:24:02 | 31 | `0x08207B` | `https://mybiggestjoy[.]bond` | OK |

**Pattern:** rapid domain rotation across four TLDs (`.cfd`, `.sbs`, `.click`, `.bond`) over 19 days, then a single write on March 30.

### Phase 2 — Silent Operation / Empty Writes (March-October 2026)

Nonces 17-30 and 32-269 are **almost entirely empty ABI-encoded writes**. The input pattern is:

```
0x77343408 0000...0020 0000...00 (truncated)
```

The selector is `0x77343408` (the `0x08207B` setter), but the string argument is empty or truncated. Approximately 240 of the 278 transactions follow this pattern.

**Interpretation:** Either the operator's tool writes empty strings as a heartbeat/check-in, or the string length field is being truncated in the API export. Confirming requires pulling the full raw input for one of these transactions.

### Phase 3 — Contract Switch (October 2026)

| Date (UTC) | Nonce | Contract | Value | Status |
|---|---|---|---|---|
| 2026-10-14 07:21:34 | 268 | `0x08207B` | (empty) | OK |
| 2026-10-14 07:39:56 | 269 | `0x08207B` | (empty) | OK |
| **2026-10-14 09:13:14** | **271** | **`0x4af804`** | **`https://year[.]calvinpreschooloffice[.]com`** | **OK** |
| 2026-10-14 09:58:35 | 272 | `0x4af804` | `https://hail[.]cocova[.]co` | OK |
| 2026-10-15 09:04:25 | 273 | `0x4af804` | `https://hail[.]cocova[.]co` | OK |
| 2026-10-15 09:42:37 | 274 | `0x08207B` | `https://hail[.]cocova[.]co` | OK |
| 2026-10-15 09:42:43 | 275 | `0x4af804` | `https://hail[.]cocova[.]co` | OK |

---

## 7. The `year[.]calvinpreschooloffice[.]com` Finding

**Transaction hash:** `0x15f3b206cbb898e910a63130ed3ff4dccff08599436a25e067e5170145e008f6`
**Block:** 95509254
**Nonce:** 271
**Timestamp:** 2026-10-14 09:13:14 UTC
**Target contract:** `0x4af804`
**Method:** `0x7d0c8f7a`

### 7.1 Raw Calldata

```
0x7d0c8f7a
0000000000000000000000000000000000000000000000000000000000000001
0000000000000000000000000000000000000000000000000000000000000060
00000000000000000000000000000000000000000000000000000000000000a0
0000000000000000000000000000000000000000000000000000000000000001
0000000000000000000000000000000000000000000000000000000000000001
0000000000000000000000000000000000000000000000000000000000000001
0000000000000000000000000000000000000000000000000000000000000020
0000000000000000000000000000000000000000000000000000000000000026
5c69e5c11a0794fe7112dfa41c98b3444274ffc11b58c8b26018d1ba5d9db4415778bfd2065
0000...0000
```

### 7.2 ABI Decode

- Selector: `0x7d0c8f7a` — the `0x4af804` setter
- Argument 1: `1` (uint256)
- Argument 2: array of length 1
- String argument: `0x26` = 38 bytes
- Data: `5c69e5c11a0794fe7112dfa41c98b3444274ffc11b58c8b26018d1ba5d9db4415778bfd2065`

### 7.3 XOR Decryption

XORing the 38-byte data with the recovered 16-byte key `341d91b1693dbbd10877bed632fbd228` (repeating):

```
5c 69 e5 c1 1a 07 94 fe 71 12 df a4 1c 98 b3 44 42 74 ff c1 1b 58 c8 b2 60 18 d1 ba 5d 9d b4 41 57 78 bf d2 06 50
XOR
34 1d 91 b1 69 3d bb d1 08 77 be d6 32 fb d2 28 34 1d 91 b1 69 3d bb d1 08 77 be d6 32 fb d2 28 34 1d 91
=
68 74 74 70 73 3a 2f 2f 79 65 61 72 2e 63 61 6c 76 69 6e 70 72 65 73 63 68 6f 6f 6c 6f 66 66 69 63 65 2e 63 6f 6d
```

Decoded ASCII:

```
https://year[.]calvinpreschooloffice[.]com
```

### 7.4 Assessment

The operator wrote this 38-byte domain to `0x4af804`, then 45 minutes later wrote `https://hail[.]cocova[.]co` (nonce 272). The write succeeded and the ciphertext is currently in the contract's storage.

This is a **deliberate, specific, operator-controlled C2 domain**:
- It is not on the peer's shared list
- It uses a different TLD (`.com`) than the current campaign (`.co`)
- It has a legitimate-looking domain format (`calvinpreschooloffice[.]com`) unlike the short codenames (`hail`, `ruby`, etc.)
- The XOR key for this write is the same as for the `cocova[.]co` pool

**Hypotheses:**

| Hypothesis | Evidence for | Evidence against |
|---|---|---|
| H1: Test of new infrastructure | Write followed by immediate revert to `hail[.]cocova[.]co` | None |
| H2: Abandoned migration | Same as H1 | None |
| H3: Different campaign from same wallet | Same wallet, same key | Would expect it to appear in subsequent writes |
| H4: Decoy / false signal | Isolated occurrence | The 38-byte payload is a valid domain, not random |

H1/H2 are most likely. Either way, the domain is a legitimate operator-controlled indicator.

---

## 8. Full Domain History

Combining the write history with the decrypted `0x4af804` pool, the operator has used the following domains over the campaign's lifetime.

### Current (October 2026)

```
https://hail[.]cocova[.]co
https://ruby[.]cocova[.]co
https://zinc[.]cocova[.]co
https://sand[.]cocova[.]co
https://raft[.]cocova[.]co
```

### Newly discovered

```
https://year[.]calvinpreschooloffice[.]com
```

### Historical (March 2026)

```
https://cloudflare-check[.]cfd
https://myverifyblog[.]sbs/
https://webanalytics-cdn[.]cfd/
https://myverifhouse[.]sbs
https://sitepromclop[.]click
https://sitepromclop[.]click/land/
https://microblogver[.]bond
https://microblogver[.]bond/land/
https://mygoodblog[.]cfd
https://mygoodblog[.]bond
https://microloh[.]bond
https://mybiggestjoy[.]bond
```

**Total: 17+ distinct domains across 6 TLDs.**

---

## 9. Technical Link to GuidePoint Campaign

Contract `0x56384E` (the operator's first deployment) shares two selectors with GuidePoint Security's published Template A contract `0xde2d34339C279A7a79bc4fC1C4F37d3C055211b7`:

| Selector | GuidePoint Template A | `0x56384E` | Match |
|---|---|---|---|
| `0xb68d1809` | C2 getter | Present | ✓ |
| `0xb249cd2d` | Setter (Update Domain) | Present | ✓ |

GuidePoint's Template A also has: `0x893d20e8`, `0x8da5cb5b`, `0xf2fde38b`. Those are **absent** from `0x56384E`, which instead uses `0xe096a091` and `0xf851a440` (`admin()`).

**Interpretation:** This is a **variant** of the GuidePoint Template A design. The core C2 selectors are preserved; the surrounding Ownable pattern is replaced with a proxy/admin pattern. The operator has access to the same codebase or a derivative.

---

## 10. Indicators of Compromise

### 10.1 Wallet

```
0x34c15320d6E8f59f1b66f6c191Aaa7F87B894B66
```

### 10.2 Contracts (Polygon)

```
0x56384Ef15734CcE9026D9e75ac3bE616513fe2Ae
0x08207B087F61d7e95E441E15fd6d40BEfd6eD308
0x2B2e30dA517b22a20Eb367a36b9cA725cf93e9E5
0x4af8048EdfE4523953E9907528BF5Cef7Fa8db09
```

### 10.3 Selectors

| Selector | Purpose |
|---|---|
| `0x77343408` | Setter on `0x08207B` (plaintext storage) |
| `0x7d0c8f7a` | Setter on `0x4af804` (XOR storage) |
| `0xd11db010` | Setter on `0x2B2e30` (control) |
| `0xb249cd2d` | Setter on `0x56384E` (Template A variant) |
| `0xb68d1809` | C2 getter on `0x56384E` |

### 10.4 Domains

**Current:** `hail`, `ruby`, `zinc`, `sand`, `raft` on `cocova[.]co`
**New:** `year[.]calvinpreschooloffice[.]com`
**Historical:** 11 domains across `.cfd`, `.sbs`, `.click`, `.bond`

### 10.5 Encryption Key

```
341d91b1693dbbd10877bed632fbd228
```

Repeating-key XOR, period 16 bytes.

---

## 11. Open Items

1. **Verify `year[.]calvinpreschooloffice[.]com` against the 25 HTML samples.** If it appears in the loader configuration, it's a direct malware-to-domain link.
2. **Check the historical March 2026 domains** against older intel. They may link this operator to prior campaigns.
3. **Trace funding source** of the operator wallet. First inbound transaction on Polygonscan. Cribl documented FixedFloat for their operator; this one may share a source.
4. **Confirm the empty-write pattern.** Pull the full raw input for nonce 274 (or any nonce in 17-269) and check whether the string argument is truly empty or truncated by the export.
5. **Monitor for new writes.** The operator is actively writing to both `0x08207B` and `0x4af804` as of 2026-10-15. New writes will be decodable with the recovered key.

---

## 12. OPSEC Notes

- All queries in this investigation were read-only `eth_call` requests to Alchemy RPC or the Etherscan V2 API.
- No direct contact with any `cocova[.]co` or `calvinpreschooloffice[.]com` domain was made.
- The TDS at `hail[.]cocova[.]co` is known to profile visitors. Do not query from any corporate or personal IP.
- This report is marked TLP:AMBER. Confirm sharing rules with the original case owner before distributing externally.

---

## 13. Tooling

Analysis was performed with the `etherhiding-tracker` toolset:

- `cli.py` — unified interface: fingerprint, wallet pivot, templates, scan
- `write_history.py` — fetch full transaction history via Etherscan V2 API and decode calldata
- `fetch_setter_calldata.py` — extract calldata from individual transaction hashes
- `analyze.py` — selector extraction and storage dump
- `decrypt.py` — XOR decryption of encrypted storage records

Source code: `https://github.com/luffytaro98uk-png/etherhiding-tracker`

---

## 14. Conclusion

The `cocova[.]co` operator's complete on-chain infrastructure has been reconstructed from public data:

- **Operator wallet:** `0x34c15320d6E8f59f1b66f6c191Aaa7F87B894B66`
- **Four contracts** with distinct roles (Template A variant, plaintext storage, control, XOR storage)
- **Seven months of transaction history**
- **XOR encryption key recovered**
- **Five current domains decrypted**
- **One new domain discovered: `year[.]calvinpreschooloffice[.]com`**
- **Eleven historical domains recovered from March 2026**
- **Technical link to GuidePoint campaign** via shared selectors

The operator is currently active. The most recent write was on **2026-10-15 09:42:43 UTC**, to `0x4af804`, value `https://hail[.]cocova[.]co`, decrypted with the recovered key.

The `year[.]calvinpreschooloffice[.]com` finding is the highest-value new indicator. It is not on the peer's list, it was deliberately written by the operator, and it was reverted 45 minutes later — suggesting a test or abandoned migration.

---

## 15. Verification

All findings in this report can be independently verified with the following public sources. URLs are defanged for safety.

### Etherscan V2 API (transaction history)

```
https://api[.]etherscan[.]io/v2/api?chainid=137&module=account&action=txlist&address=0x34c15320d6E8f59f1b66f6c191Aaa7F87B894B66&startblock=0&endblock=99999999&sort=asc
```

### Polygonscan (browser)

**Operator wallet:**
```
polygonscan[.]com/address/0x34c15320d6E8f59f1b66f6c191Aaa7F87B894B66
```

**Contracts:**
```
polygonscan[.]com/address/0x56384Ef15734CcE9026D9e75ac3bE616513fe2Ae
polygonscan[.]com/address/0x08207B087F61d7e95E441E15fd6d40BEfd6eD308
polygonscan[.]com/address/0x2B2e30dA517b22a20Eb367a36b9cA725cf93e9E5
polygonscan[.]com/address/0x4af8048EdfE4523953E9907528BF5Cef7Fa8db09
```

**The `year[.]calvinpreschooloffice[.]com` write (block 95509254):**
```
polygonscan[.]com/tx/0x15f3b206cbb898e910a63130ed3ff4dccff08599436a25e067e5170145e008f6
```

### GuidePoint Security (reference, safe to click)

```
https://www.guidepointsecurity.com/blog/etherhiding-exposed-deep-dive/
```

### Toolset (safe to click)

```
https://github.com/luffytaro98uk-png/etherhiding-tracker
```

### DO NOT VISIT

The following domains are live C2 infrastructure. Do not query from any corporate or personal IP. Use a sandbox if verification is required.

**Current `cocova[.]co` pool:**
```
hail[.]cocova[.]co
ruby[.]cocova[.]co
zinc[.]cocova[.]co
sand[.]cocova[.]co
raft[.]cocova[.]co
```

**Newly discovered:**
```
year[.]calvinpreschooloffice[.]com
```

**Historical (March 2026):**
```
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
```

---

*End of report. All C2 domains and infrastructure URLs are defanged with `[.]` notation.*

---

