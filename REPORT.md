# EtherHiding Contract Tracker — Investigation Report

**Analyst:** Himanshu Pandey
**Date:** 2026-10-13
**Chain:** Polygon Mainnet
**Tooling:** Python 3.13 · web3.py · Alchemy RPC (free tier)
**Status:** Complete — 15 contracts identified across 3 template generations

---

## Executive Summary

This report documents the reconstruction and extension of an EtherHiding
malware campaign's on-chain infrastructure, using only public blockchain
data and a free-tier RPC provider. The investigation began from three known
contract addresses published in GuidePoint Security's September 2026 deep
dive and expanded to cover the operator's full deployment history.

## Note on Novelty and Confidence

This work reproduces and extends GuidePoint Security's September 2026
EtherHiding investigation. Most structural findings — 15 contracts, 3
templates, 2 operator wallets, and the wallet-pivot methodology — are
replications of their published analysis. The value of replication is that
it confirms the original findings are accurate and provides a free,
indexer-independent implementation.

Two elements are genuinely new:

1. **An indexer-free implementation** of the wallet-pivot technique using
   only Alchemy's free tier and deterministic nonce derivation. The original
   investigation used a mix of chain-wide event sweeps and full wallet
   transaction pulls. This implementation reconstructs all 15 contracts
   from the two wallet addresses alone.

2. **The first published state snapshot of the 11 Template B contracts:**
   as of block 95,470,427, six return empty payloads and five return
   64–80 byte payloads.

The **purpose** of the Template B contracts is presented as a hypothesis,
not a finding. Several alternative explanations fit the current data
equally well:

| Hypothesis | Distinguishing test |
|---|---|
| H1: Reserve C2 slots awaiting activation | Writes occur after deployment, spaced over time |
| H2: Payloads written at deploy time, empty slots abandoned | Writes follow deployment immediately |
| H3: Slots were active and have since been cleared | Empty slots show a past write in transaction history |
| H4: Payload is not a C2 address (config, panel, key material) | Decryption, or a sample that references a B contract |
| H5: Decoy or test deployments | No sample references them; writes look irregular |

Confidence in H1 (the interpretation offered in Section 4.3) is currently
low to moderate. Section 4.5 describes the validation plan that would
distinguish these hypotheses.

**Key findings:**

1. All 15 contracts deployed by the two operator wallets were independently
   rediscovered using deterministic address derivation from wallet nonces —
   no indexed API or paid service required.
2. The three template generations described in the GuidePoint report were
   confirmed and characterized by their function selectors, bytecode sizes,
   and payload formats.
3. **The 11 Template B contracts — whose purpose GuidePoint explicitly left
   unresolved — show a mixed state:** six return empty payloads and five
   return 64–80 byte payloads as of block 95,470,427.
4. Template C is a hybrid design that shares selectors with both prior
   templates and holds a live 60-byte encrypted payload.

---

## 1. Background: What Is EtherHiding?

EtherHiding is a technique where malware retrieves its command-and-control
(C2) address by reading a smart contract on a public blockchain rather than
contacting a hardcoded domain. The read is performed with `eth_call`, which:

- Costs nothing (no gas, read-only)
- Leaves no on-chain trace
- Cannot be taken down by seizing a server or domain

The operator can rotate the C2 address for all infected machines with a
single contract write. The trade-off for the attacker: every rotation is
recorded permanently on a public ledger, making the infrastructure
reconstructable by defenders.

---

## 2. Seed Intelligence

Starting point: three contract addresses from GuidePoint Security's report,
"EtherHiding Exposed: Inside a Blockchain-powered Malware Campaign Hiding in
Plain Sight" (published 2026-09-17).

| Contract | Owner Wallet |
|---|---|
| `0xde2d34339c279a7a79bc4fc1c4f37d3c055211b7` | Wallet 1 |
| `0xa982e044217b6bbaa7b3123b670c1c0ca1138a37` | Wallet 1 |
| `0x308e9ecc849533a042f13fd77e5c82ec3c62e9f2` | Wallet 2 |

Operator wallets:

- **Wallet 1:** `0xd802C9427ce416B9DAb2db5aDD76EfAA6d9d826a`
- **Wallet 2:** `0x6a6e177dcf992ac16f7367c14b26a3cf4775dfde`

---

## 3. Methodology

### 3.1 Contract Fingerprinting

Each candidate contract was evaluated against a four-signal fingerprint:

1. **C2 getter selector present** — either `0xb68d1809` (Template A) or
   `0x3bc5de30` (Templates B/C) appearing in bytecode
2. **OpenZeppelin Ownable pattern** — selectors `0x8da5cb5b` (owner) and
   `0xf2fde38b` (transferOwnership) present
3. **Getter returns a payload** — `eth_call` to the getter returns an
   ABI-encoded blob; length reported is the actual string length, not the
   wrapper size
4. **Owner resolves to a known operator wallet**

A contract matching signals 1 and 2 is classified as suspicious. Matching
all four is a positive identification.

### 3.2 Wallet-to-Contract Pivot

Rather than relying on a block explorer API (Polygonscan V1 was deprecated
during this investigation), contract addresses were derived
**deterministically** from the operator wallets:

```python
contract_address = keccak256(rlp([deployer_address, nonce]))[12:]
```

Every nonce corresponds to a transaction from the wallet. Most are
deployments; some are zero-value function calls. The derivation iterates
over all nonces, computes the derived address for each, and skips any that
resolve to empty addresses.

The gaps in the nonce sequence (Wallet 2's 1–2, 10–11, 13–15, 17, 19, 21)
are the non-deployment transactions. Their analysis is described in
Section 4.5.

### 3.3 Event Scanning

Template A contracts emit a specific event on C2 rotation:

```
topic = 0x868f5f914e26b486c50b15494d56c6b2f2f17f6514343909bd36a034c19452cc
```

Scanning for this topic across block ranges detects rotations in real time.
Templates B and C emit no events, so they cannot be discovered this way —
only via the wallet pivot.

---

## 4. Findings

### 4.1 Complete Contract Inventory

Fifteen contracts were confirmed across the two operator wallets. Contract
addresses are grouped by the wallet that deployed them.

**Wallet 1** (`0xd802C9427ce416B9DAb2db5aDD76EfAA6d9d826a`) — 2 deployments:

| Nonce | Address | Template | On-chain state | Sample reference |
|---|---|---|---|---|
| 0 | `0xa982E044217b6Bbaa7b3123b670C1c0CA1138A37` | A | payload present (48 B) | unknown |
| 4 | `0xde2d34339C279A7a79bc4fC1C4F37d3C055211b7` | A | payload present (48 B) | **confirmed** (GuidePoint primary) |

**Wallet 2** (`0x6A6e177DcF992Ac16f7367C14b26a3Cf4775dfdE`) — 13 deployments:

| Nonce | Address | Template | On-chain state | Sample reference |
|---|---|---|---|---|
| 0 | `0x308e9ecc849533a042f13fD77E5C82eC3c62e9f2` | A | payload present (36 B) | unknown |
| 3 | `0x75A91aCdB3dd25B39fe0619d2A00DE49A8e56eb9` | B | payload empty | unknown |
| 4 | `0x4c7C35db1f8E23301a447801B019968D8b4A6329` | B | payload empty | unknown |
| 5 | `0x700121c474A1eF6b4BAC074e0B805F262a5BD46e` | B | payload empty | unknown |
| 6 | `0xd245e35d988244528F10582107Ce1BC38DA35a24` | B | payload empty | unknown |
| 7 | `0x96C90CD4E58718cb20A58e14b7931eD94Ad040C7` | B | payload empty | unknown |
| 8 | `0x0dC9f5de745394D98C0cE163D498043EB325AC45` | B | payload empty | unknown |
| 9 | `0xFad3F51fF70223CadeecCf8FCf2D362533f360eE` | B | payload present (80 B) | unknown |
| 12 | `0xB685a24587658989410D68500448f45467CA47D8` | B | payload present (76 B) | unknown |
| 16 | `0xed4417B3992A4e6613f734E720e24DE5630695f8` | B | payload present (80 B) | unknown |
| 18 | `0xA5517ea1914EbfcEcDe8528e0973D98E60178607` | B | payload present (64 B) | unknown |
| 20 | `0x5C4576E21809FfA8d265bB7385f044A693356c43` | B | payload present (64 B) | unknown |
| 22 | `0x46124F9F0f0d70c8b9e62258179574E05FbFF181` | C | payload present (60 B) | unknown |

### 4.2 Template Comparison

| Property | Template A | Template B | Template C |
|---|---|---|---|
| Deployed | Nov 2025 – Apr 2026 | May 2026 | May 2026 |
| Bytecode size | 2766–2786 B | 1856 B | 1441 B |
| External selectors | 5 | 2 | 5 |
| C2 getter | `0xb68d1809` | `0x3bc5de30` | `0x3bc5de30`, `0x73d4a13a` |
| Ownable pattern | Yes | No | Yes |
| Emits events | Yes | No | No |
| Payload format | base64-of-base64 | raw binary | raw binary |
| Payload size (as reported) | 48 / 48 / 36 B | 0 or 64–80 B | 60 B |

### 4.3 Template Selectors

**Template A** (`0xde2d34339C279A7a79bc4fC1C4F37d3C055211b7`):

```
0x893d20e8   owner-related getter
0x8da5cb5b   owner()
0xb249cd2d   unknown — likely setter
0xb68d1809   C2 getter  ← primary indicator
0xf2fde38b   transferOwnership(address)
```

**Template B** (`0x75A91aCdB3dd25B39fe0619d2A00DE49A8e56eb9`):

```
0x3bc5de30   C2 getter  ← returns empty string when dormant
0x47064d6a   reverts on arg-less call; setter behaviour untested
```

**Template C** (`0x46124F9F0f0d70c8b9e62258179574E05FbFF181`):

```
0x3bc5de30   C2 getter  ← returns 60-byte ciphertext
0x73d4a13a   C2 getter  ← returns the same 60-byte ciphertext
0x8da5cb5b   owner()
0xab62f0e1   reverts on arg-less call; unknown purpose
0xf2fde38b   transferOwnership(address)
```

### 4.4 The Mixed-State Template B Cluster

All 11 Template B contracts share identical bytecode (1856 bytes), expose
only two selectors (`0x3bc5de30`, `0x47064d6a`), and store the owner in
storage slot 1. However, their current states are not uniform.

Dormant (payload length = 0): **6 contracts**

```
0x75A91aCdB3dd25B39fe0619d2A00DE49A8e56eb9
0x4c7C35db1f8E23301a447801B019968D8b4A6329
0x700121c474A1eF6b4BAC074e0B805F262a5BD46e
0xd245e35d988244528F10582107Ce1BC38DA35a24
0x96C90CD4E58718cb20A58e14b7931eD94Ad040C7
0x0dC9f5de745394D98C0cE163D498043EB325AC45
```

Active (payload length in parentheses): **5 contracts**

```
0xFad3F51fF70223CadeecCf8FCf2D362533f360eE (80 B)
0xB685a24587658989410D68500448f45467CA47D8 (76 B)
0xed4417B3992A4e6613f734E720e24DE5630695f8 (80 B)
0xA5517ea1914EbfcEcDe8528e0973D98E60178607 (64 B)
0x5C4576E21809FfA8d265bB7385f044A693356c43 (64 B)
```

**Interpretation (hypothesis, not finding).** The operator deployed 11
reserve contracts in May 2026 (10 on May 5, 1 on May 7 per GuidePoint).
At block 95,470,427, five return non-empty payloads and six return empty.
The timing of the writes that populated the five active slots is not
recoverable from a single snapshot. See Section 4.5 for the validation
plan and alternative hypotheses.

**Detection signal:** poll `0x3bc5de30` on all 11 contracts. Any transition
from 0 to non-zero indicates a change in state that warrants investigation.

### 4.5 Validation Plan for the Mixed-State Cluster

The purpose of the Template B contracts is unresolved. The following
analyses would distinguish the five hypotheses listed in the Note on
Novelty and Confidence.

**1. Decode the non-deployment transactions.**

Wallet 2's nonce sequence has gaps at 1, 2, 10, 11, 13, 14, 15, 17, 19,
and 21. Pulling the `to` address, function selector, calldata, and block
timestamp for each will:

- Confirm or refute the `0x47064d6a` setter hypothesis if any of those
  transactions call that selector
- Reveal the calldata written to each contract, giving historical payloads
  without requiring an archive node
- Show whether any currently-empty contract was written to and then cleared
  (H3)

**2. Known-plaintext attack on the five active blobs.**

GuidePoint recovered a repeating XOR key (`$%)W$fgl34`) by anchoring on the
fixed `/UpdateCheck/` string. Applying the same technique across all five
active Template B blobs — including crib-dragging `https://`, `/UpdateCheck/`,
`.shop`, and `.online` — would decrypt the domains if the payloads use the
same scheme. Failure would be consistent with a stream cipher or per-blob
nonce.

**3. Link Template B contracts to a malware sample.**

GuidePoint published seven SHA-256 hashes of samples related to the
campaign. Searching those samples, or any sandbox runs available, for the
Template B addresses or the `0x3bc5de30` selector in `eth_call` data would
confirm whether these contracts are actually referenced by the malware.

**4. Confirm the setter behaviour.**

Decompiling the runtime bytecode (heimdall-rs, Dedaub) or calling
`0x47064d6a` with a properly ABI-encoded argument once from the owner
address and once from a random address would determine whether the
function is owner-gated.

Until these analyses are complete, the correct description of the
Template B cluster is **"11 contracts with a mixed payload state; purpose
unconfirmed."**

---

## 5. Detection Signatures

> These are CTI and research tooling artifacts. They are not enterprise
> detections. Section 5.5 describes how to bridge them into SOC workflows.

### 5.1 Template A

```
bytecode_size      between 2700 and 2800 bytes
required_selectors 0xb68d1809, 0x8da5cb5b, 0xf2fde38b
getter_result      ABI string from 0xb68d1809; length 36–48 bytes
event_topic        0x868f5f914e26b486c50b15494d56c6b2f2f17f6514343909bd36a034c19452cc
```

### 5.2 Template B

```
bytecode_size      exactly 1856 bytes
required_selectors 0x3bc5de30, 0x47064d6a
forbidden_selector 0x8da5cb5b (absent)
getter_result      ABI string from 0x3bc5de30
                   - 0 bytes  → empty
                   - > 0 bytes → payload present
```

### 5.3 Template C

```
bytecode_size      exactly 1441 bytes
required_selectors 0x3bc5de30, 0x73d4a13a, 0x8da5cb5b, 0xf2fde38b
getter_result      ABI string of exactly 60 bytes from both getters
```

### 5.4 Highest-Priority Signal

A Template B contract whose `0x3bc5de30` response changes from 0 bytes to
non-zero is the strongest single signal this dataset produces. A write
from the operator wallet to the setter selector is a high-confidence
operator action — treat it as warranting investigation, not as proof of
activation. It could still be a test, an overwrite, or a clear.

### 5.5 Bridging to Enterprise Detection

The full 15-address list can be used as a match set on proxy or
TLS-inspected HTTP POST bodies for JSON-RPC `eth_call` where the `to` field
is one of the known contracts. Scoped to non-browser processes
(`powershell.exe`, `pwsh.exe`) connecting to the public Polygon RPC
endpoints, this is a low-noise detection that the original GuidePoint
report does not provide.

---

## 6. Tooling

All scripts are in this repository and require only a free Alchemy account.

| Script | Purpose |
|---|---|
| `cli.py` | Unified command interface |
| `tracker.py` | Event scan + fingerprint of known contracts |
| `fingerprint.py` | Four-signal contract classification |
| `derive_contracts.py` | Deterministic contract discovery from wallet nonces |
| `monitor.py` | Template B state-change watcher |
| `analyze.py` | Selector extraction and storage dump |
| `probe_templates.py` | Function call probing for all selectors |
| `decode_template_c.py` | Payload extraction and transformation analysis |

All scripts run on the Alchemy free tier. No paid APIs are required.

---

## 7. Limitations

- **Payload decryption was not achieved.** Multiple trivial encodings were
  ruled out, but the algorithm and key remain unknown from on-chain data
  alone. Decryption would require either the malware sample or a successful
  known-plaintext attack.
- **Historical reads were not available.** Alchemy's free tier does not
  provide archive-node access, so the state of each contract at past blocks
  cannot be queried directly. Section 4.5 describes how transaction calldata
  can recover historical payloads without an archive node.
- **Domain attribution is not possible** without decryption. The
  identification rests on structural fingerprints, not on the C2 strings
  themselves.
- **The mixed-state snapshot reflects one point in time.** Findings are
  valid as of block 95,470,427. The current state may differ.

---

## 8. Recommendations

### For Defenders

1. **Add the Template A event topic to blockchain monitoring.** Any event
   with this topic indicates a C2 rotation.
2. **Watch the two operator wallets for nonce changes.** A nonce increase
   signals a new transaction, which can be fingerprinted immediately.
3. **Poll all 11 Template B contracts periodically.** Alert on any change
   in the `0x3bc5de30` response.
4. **Block outbound Polygon RPC traffic from endpoints that have no
   business reason to query Polygon.** Malware must reach an RPC endpoint
   to resolve its C2.

### For Threat Intelligence Sharing

The 15 contract addresses and 2 wallet addresses should be submitted to:

- Polygonscan (malicious address flagging)
- Chainabuse
- GuidePoint Security (as a follow-up to their September 2026 report)
- Any downstream consumer of blockchain threat intelligence

---

## 9. References

| Source | URL |
|---|---|
| GuidePoint Security — EtherHiding Exposed | https://www.guidepointsecurity.com/blog/etherhiding-exposed-deep-dive/ |
| DeFi Planet — EtherHiding overview | https://defi-planet.com/2026/04/why-etherhiding-may-be-one-of-the-most-dangerous-crypto-attacks-youve-ever-heard-of/ |

---

## 10. Conclusion

A complete EtherHiding campaign infrastructure was reproduced from public
blockchain data using only free tooling. The investigation confirmed the
three-template model described in prior reporting and provided the first
published state snapshot of the 11 Template B contracts: six empty, five
holding 64–80 byte payloads as of block 95,470,427.

The purpose of the Template B contracts remains a hypothesis. Section 4.5
describes the analyses that would confirm or refute it. Until then, the
correct statement is: **the payload state is documented; the operational
role is not.**

*End of report. This document is a point-in-time analysis reflecting the
state of the Polygon blockchain at block 95,470,427.*