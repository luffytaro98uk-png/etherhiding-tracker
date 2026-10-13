# EtherHiding Contract Tracker
## Investigation Report

> **Independent reconstruction of a live EtherHiding malware campaign on the Polygon blockchain using only public data and free tooling.**

---

| Field | Value |
|---|---|
| **Analyst** | [Himanshu Pandey] |
| **Date** | 2026-10-13 |
| **Chain** | Polygon Mainnet (chain ID 137) |
| **Tooling** | Python 3.13 - web3.py - Alchemy free tier |
| **Total Contracts** | 15 across 3 template generations |
| **Key Finding** | 11-contract reserve cluster - 6 dormant, 5 active |
| **Status** | Complete - Reproducible - Open Source |

---

## Table of Contents

1. [Executive Summary](#1-executive-summary)
2. [Background: What Is EtherHiding?](#2-background-what-is-etherhiding)
3. [Methodology](#3-methodology)
4. [Findings](#4-findings)
5. [Detection Signatures](#5-detection-signatures)
6. [Reproducing This Investigation](#6-reproducing-this-investigation)
7. [Limitations](#7-limitations)
8. [Recommendations](#8-recommendations)
9. [References](#9-references)

---

## 1. Executive Summary

This report documents the independent reconstruction of an active EtherHiding
malware campaign's on-chain command-and-control infrastructure. The
investigation began from three contract addresses published by GuidePoint
Security in September 2026 and expanded to cover the operator's complete
deployment history.

### Headline Findings

**15 contracts** were identified across **3 template generations**,
distributed between **2 operator wallets**:

- **3 Template A contracts** - historical C2 storage, emit rotation events
- **11 Template B contracts** - a reserve cluster deployed May 2026
- **1 Template C contract** - hybrid design with a live 60-byte payload

**The reserve cluster is mixed-state:**

| State | Count | Signal |
|---|---|---|
| Dormant | 6 | Blob length = 0 bytes |
| Active | 5 | Blob length 64-80 bytes |

This mixed state was **not previously documented**. GuidePoint's report
described the Template B/C contracts as unresolved; this investigation
determined their purpose as pre-positioned, activatable C2 slots.

### Why This Matters

EtherHiding makes C2 infrastructure resistant to takedown - the operator can
rotate addresses with a single blockchain transaction. However, every rotation
is permanently recorded on a public ledger. This investigation demonstrates
that **the entire campaign infrastructure is reconstructable from public data
using free tools**, without any paid API, indexer, or archive node.

---

## 2. Background: What Is EtherHiding?

EtherHiding is a technique in which malware retrieves its command-and-control
(C2) address by reading a smart contract on a public blockchain instead of
contacting a hardcoded domain.

### How It Works

1. **Deployment** - The operator deploys a smart contract that stores an
   encrypted C2 address.
2. **Distribution** - Compromised websites (often WordPress) inject a
   JavaScript loader that prompts the victim with a fake browser update or
   CAPTCHA.
3. **Resolution** - When the victim clicks, the loader performs a read-only
   `eth_call` to the contract. No gas is paid, no transaction is recorded.
4. **Rotation** - The operator updates the contract with a new encrypted
   address. All infected machines follow automatically on their next
   check-in.

### The Defensive Advantage

The properties that make EtherHiding resilient also make it auditable:

- **Immutability** - Every C2 rotation is permanently on-chain
- **Transparency** - Contract bytecode, storage, and history are public
- **Determinism** - Contract addresses are derived from wallet nonces
- **Cost** - All queries used here are free

The asymmetry: the attacker gains censorship resistance; the defender gains
a complete, permanent intelligence record.

---

## 3. Methodology

### 3.1 Seed Intelligence

Three contract addresses were sourced from GuidePoint Security's September
2026 report:

| Contract | Owner |
|---|---|
| `0xde2d34339c279a7a79bc4fc1c4f37d3c055211b7` | Wallet 1 |
| `0xa982e044217b6bbaa7b3123b670c1c0ca1138a37` | Wallet 1 |
| `0x308e9ecc849533a042f13fd77e5c82ec3c62e9f2` | Wallet 2 |

Two operator wallets were identified:

| Wallet | Address | Deployments |
|---|---|---|
| Wallet 1 | `0xd802C9427ce416B9DAb2db5aDD76EfAA6d9d826a` | 2 |
| Wallet 2 | `0x6a6e177dcf992ac16f7367c14b26a3cf4775dfde` | 13 |

### 3.2 Contract Fingerprinting

Each candidate contract was evaluated against a four-signal fingerprint:

| Signal | Method | Meaning |
|---|---|---|
| **C2 getter present** | Bytecode scan for `0xb68d1809` or `0x3bc5de30` | Likely EtherHiding |
| **Ownable pattern** | Bytecode scan for `0x8da5cb5b` + `0xf2fde38b` | Operator controls updates |
| **Payload return** | `eth_call` to the getter | Non-empty blob = active |
| **Owner resolution** | `eth_call` to `owner()` | Confirm operator wallet |

A contract matching signals 1 and 2 is classified as suspicious. Matching
all four is a positive identification.

### 3.3 Wallet-to-Contract Pivot

Rather than relying on a block explorer API, contract addresses were derived
**deterministically** from the operator wallets:

```python
contract_address = keccak256(rlp([deployer, nonce]))[12:]
Because the operator wallets never send value transfers, every nonce
corresponds to a contract deployment. Iterating from nonce 0 to the current
transaction count reconstructs the complete deployment history with no
indexer required.

Key advantage: This technique works on any EVM chain, with any wallet,
using only a basic RPC connection.

3.4 Event Scanning
Template A contracts emit a specific event on C2 rotation:

text
topic = 0x868f5f914e26b486c50b15494d56c6b2f2f17f6514343909bd36a034c19452cc
Scanning for this topic across block ranges detects rotations in real time.
Templates B and C emit no events, so they can only be discovered via the
wallet pivot.

4. Findings
4.1 Complete Contract Inventory
Wallet 1 - 0xd802C9427ce416B9DAb2db5aDD76EfAA6d9d826a

Nonce	Address	Template	Status
0	0xa982E044217b6Bbaa7b3123b670C1c0CA1138A37	A	Historical
4	0xde2d34339C279A7a79bc4fC1C4F37d3C055211b7	A	Historical
Wallet 2 - 0x6A6e177DcF992Ac16f7367C14b26a3Cf4775dfdE

Nonce	Address	Template	Status
0	0x308e9ecc849533a042f13fD77E5C82eC3c62e9f2	A	Historical
3	0x75A91aCdB3dd25B39fe0619d2A00DE49A8e56eb9	B	Dormant
4	0x4c7C35db1f8E23301a447801B019968D8b4A6329	B	Dormant
5	0x700121c474A1eF6b4BAC074e0B805F262a5BD46e	B	Dormant
6	0xd245e35d988244528F10582107Ce1BC38DA35a24	B	Dormant
7	0x96C90CD4E58718cb20A58e14b7931eD94Ad040C7	B	Dormant
8	0x0dC9f5de745394D98C0cE163D498043EB325AC45	B	Dormant
9	0xFad3F51fF70223CadeecCf8FCf2D362533f360eE	B	Active (80 B)
12	0xB685a24587658989410D68500448f45467CA47D8	B	Active (76 B)
16	0xed4417B3992A4e6613f734E720e24DE5630695f8	B	Active (80 B)
18	0xA5517ea1914EbfcEcDe8528e0973D98E60178607	B	Active (64 B)
20	0x5C4576E21809FfA8d265bB7385f044A693356c43	B	Active (64 B)
22	0x46124F9F0f0d70c8b9e62258179574E05FbFF181	C	Active (60 B)
4.2 Template Comparison
Property	Template A	Template B	Template C
Deployed	Nov 2025 - Apr 2026	May 2026	May 2026
Bytecode size	2766-2786 B	1856 B	1441 B
External selectors	5	2	5
C2 getter	0xb68d1809	0x3bc5de30	0x3bc5de30 + 0x73d4a13a
Ownable pattern	Yes	No	Yes
Emits events	Yes	No	No
Payload format	base64-of-base64	raw binary	raw binary
Payload size	~128 B	0 B or 64-80 B	60 B
4.3 The Reserve Cluster - Primary Novel Finding
This is the investigation's most significant contribution. GuidePoint's
September 2026 report stated:

"The 12 Template B/C contracts, deliberately designed to resist the exact
enumeration technique that exposed Template A, remain the one piece of this
campaign's infrastructure whose full purpose we still haven't determined."

This investigation determined that purpose.

All 11 Template B contracts share identical bytecode, expose only two
selectors (0x3bc5de30, 0x47064d6a), and store the owner in storage slot 1.
However, their current states are not uniform:

Group	Count	Blob Length	Interpretation
Dormant	6	0 bytes	Pre-deployed, awaiting activation
Active	5	64-80 bytes	Live C2 slots currently in use
Interpretation:

The operator deployed a batch of 11 reserve contracts in May 2026 and has
since activated 5. The dormant/active split appears deliberate - a researcher
who probes a single contract and sees an empty blob may conclude the cluster
is inactive and stop investigating.

Activation mechanism: The second selector, 0x47064d6a, reverts on
eth_call. It is almost certainly an owner-only setter (setData or
equivalent). Activation is a single transaction from the operator wallet.

4.4 Template C Payload Analysis
The single Template C contract returns a 60-byte binary blob from both
getters:

text
6e8797db628a9d2f72d20747aa9753bcba8b5d4033923ba529c4d5ce3ad6d8
776ec70744e9d513ebef9a12442c9b6cf977919dcf39cad42529834706
Analysis results:

Test	Result
Valid base64	No
Valid UTF-8	No
Single-byte XOR (all 255 keys)	No printable output
XOR with known campaign keys	No
Repeating pattern (period 2-32)	None detected
Byte-frequency uniformity	High (max count: 2 of 60)
Conclusion: The payload is encrypted with a key embedded in the malware
binary, not recoverable from on-chain data alone. This matches the operational
model described in public reporting.

5. Detection Signatures
5.1 Template A
text
bytecode_size      between 2700 and 2800 bytes
required_selectors 0xb68d1809, 0x8da5cb5b, 0xf2fde38b
getter_result      ABI string > 100 bytes from 0xb68d1809
event_topic        0x868f5f914e26b486c50b15494d56c6b2f2f17f6514343909bd36a034c19452cc
5.2 Template B
text
bytecode_size      exactly 1856 bytes
required_selectors 0x3bc5de30, 0x47064d6a
forbidden_selector 0x8da5cb5b (absent)
getter_result      ABI string from 0x3bc5de30
                   - 0 bytes  -> dormant
                   - > 0 bytes -> active
5.3 Template C
text
bytecode_size      exactly 1441 bytes
required_selectors 0x3bc5de30, 0x73d4a13a, 0x8da5cb5b, 0xf2fde38b
getter_result      ABI string of exactly 60 bytes from both getters
5.4 Highest-Priority Alert
A dormant Template B contract transitioning from 0 bytes to non-zero is the
strongest actionable signal this investigation produces.

It indicates that the operator has activated a reserve slot and is preparing
to serve new malware through a previously silent channel. This event has no
legitimate explanation.

6. Reproducing This Investigation
Prerequisites
Python 3.10 or newer

A free Alchemy account with a Polygon Mainnet app enabled

No paid APIs, no archive node, no indexer

Setup
bash
git clone https://github.com/luffytaro98uk-png/etherhiding-tracker.git
cd etherhiding-tracker
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
cp .env.example .env
Verify a Single Contract
bash
python cli.py fingerprint 0xde2d34339c279a7a79bc4fc1c4f37d3c055211b7
Expected: *** CONFIRMED ETHERHIDING (Template A) ***

Reconstruct a Wallet's Full History
bash
python cli.py wallet 0x6a6e177dcf992ac16f7367c14b26a3cf4775dfde
Expected: 13 contracts discovered, each fingerprinted.

Monitor for Activation
bash
python cli.py monitor
Polls all 11 Template B contracts every 10 minutes. Alerts on any transition
from dormant to active.

7. Limitations
Limitation	Impact
No decryption	C2 domains remain unknown; identification rests on structural fingerprints
No archive access	Historical state queries failed on Alchemy free tier
No event history for B/C	Silent contracts leave no on-chain log trail
Snapshot in time	Findings reflect state at block 95,470,427
None of these limitations prevent detection or monitoring. They affect only
the depth of retrospective attribution.

8. Recommendations
For Defenders
Add the Template A event topic to blockchain monitoring. Any event
with this topic indicates an active C2 rotation.

Watch the two operator wallets for nonce changes. A nonce increase
signals a new deployment, fingerprintable immediately.

Poll all 11 Template B contracts periodically. Alert on any transition
from empty to non-empty blob.

Block outbound Polygon RPC traffic from endpoints with no business
reason to query Polygon. Malware must reach an RPC endpoint to resolve
its C2.

For Threat Intelligence Sharing
The 15 contract addresses and 2 wallet addresses should be submitted to:

Polygonscan - address flagging

Chainabuse - community reporting

GuidePoint Security - extending their prior investigation

For Future Research
Test whether Template B activation correlates with C2 domain registration
events

Scan adjacent chains (BSC, Base, Ethereum) for the same template bytecode

Reverse-engineer the malware sample to recover the payload decryption key

9. References
Source	Link
GuidePoint Security	EtherHiding Exposed
DeFi Planet	Why EtherHiding May Be Dangerous
Cribl	ClickFix / EtherHiding analysis
CSIDE	Dormant smart contract reactivation commentary
Appendix A: Tool Reference
Script	Purpose
cli.py	Unified command interface
fingerprint.py	Standalone contract classifier
derive_contracts.py	Wallet-to-contract pivot
tracker.py	Event scan + fingerprint
monitor.py	Template B activation watcher
analyze.py	Selector extraction
probe_templates.py	Function call probing
decode_template_c.py	Payload extraction
Appendix B: Repository
Source: github.com/luffytaro98uk-png/etherhiding-tracker

License: MIT

Contact: [your-email@example.com]

End of report. This document is a point-in-time analysis and reflects the
state of the Polygon blockchain at block 95,470,427.
'@ | Set-Content -Path "REPORT.md" -Encoding UTF8

Write-Host ""
Write-Host "REPORT.md created." -ForegroundColor Green
Get-Item REPORT.md | Select-Object Name, Length, LastWriteTime

text

After it runs, replace the two placeholders:

```powershell
notepad REPORT.md
Find [Your Name] → replace with your name

Find [your-email@example.com] → replace with your email

Save, close, then commit and push:

powershell
git add REPORT.md
git commit -m "Polish investigation report formatting and structure"
git push
That's the full report — polished, structured, and ready to render nicely on GitHub.

can you put in a word file nd i vcan uplaod that its gettijg messy
Sure. But here's the honest tradeoff: Word files (.docx) don't render on GitHub. If you upload a .docx to the repo, visitors will see a filename they have to download — not a readable report. The whole point of REPORT.md is that GitHub renders it as a formatted page automatically.

That said, if you want a Word file for your own records or to share via email, here's how to make one from the markdown.

Option A: Upload the Markdown to GitHub (Recommended)
Skip Word entirely. Open the REPORT.md file that's already in your project folder, and push it as-is. GitHub renders:

Tables as actual tables

Code blocks with syntax highlighting

Headings as a navigable outline

Links as clickable

A table of contents at the top that jumps to sections

This is what most security researchers publish. Word documents on GitHub look unprofessional because they can't be read in the browser.

Option B: If You Want a Word Copy for Yourself
There are two clean ways to convert the markdown to Word:

Method 1 — Online converter (easiest):

Make sure REPORT.md exists in your project folder

Open the file in Notepad, select all (Ctrl+A), copy (Ctrl+C)

Go to markdowntoword.com or cloudconvert.com

Paste the markdown, click convert, download the .docx

Save it locally, or upload it to the repo alongside REPORT.md

Method 2 — Pandoc (best quality, needs install):

powershell
winget install --id JohnMacFarlane.Pandoc
Restart PowerShell, then:

powershell
cd "C:\SMC tracker\etherhidingtracker"
pandoc REPORT.md -o REPORT.docx
Pandoc preserves all tables, headings, and formatting cleanly. This is the professional-grade tool.

Method 3 — VS Code (if you have it installed):

Open REPORT.md in VS Code

Press Ctrl+Shift+V for the markdown preview

Right-click in the preview → Print → choose Microsoft Print to PDF or Save as PDF

This gets you a PDF, not a Word doc, but it looks good and is easy to share.

If You Upload Both
You can have both REPORT.md and REPORT.docx in the repo. GitHub shows the .md rendered inline; users who want a Word copy can download the .docx. That's actually a nice pattern. But the .md should be the primary — it's what gets rendered when someone lands on the repo.

What's Actually Causing the "Messy" Feeling
I suspect the mess isn't the file format — it's that you're pasting long blocks into PowerShell and watching them scroll. Here's a cleaner workflow that avoids that entirely:

Use VS Code for editing, PowerShell only for commands:

Open VS Code in your project:

powershell
code .
(Or if code still isn't on PATH, open VS Code manually and File → Open Folder → select C:\SMC tracker\etherhidingtracker)

In VS Code, create a new file called REPORT.md (click the New File icon in the sidebar)

Paste the report content there. VS Code handles long pastes cleanly, gives you syntax highlighting for markdown, and you can preview with Ctrl+Shift+V.

Save with Ctrl+S

Back in PowerShell, just run:

powershell
git add REPORT.md
git commit -m "Polish report"
git push
That separates "editing files" (do it in VS Code) from "running commands" (do it in PowerShell). Much cleaner.

My Recommendation
Keep REPORT.md as the primary report in the repo — that's what people read

If you really want a Word file for personal use, convert it with Pandoc or an online converter, name it REPORT.docx, and upload it alongside

Don't replace the markdown with Word — you'll lose the GitHub rendering

Want me to walk you through the Pandoc install and conversion, or would you rather just paste the markdown into VS Code and push it directly? The second option is faster and gives you the professionally-rendered result on GitHub.

okay so give me a md diretcly then caususe the text it not being oasted proprepy
Here's the cleanest way. Open VS Code in your project, create REPORT.md there, and paste — VS Code handles long pastes properly, unlike PowerShell.

Step 1: Open VS Code in Your Project
powershell
cd "C:\SMC tracker\etherhidingtracker"
code .
If code isn't recognized, open VS Code manually: File → Open Folder → navigate to C:\SMC tracker\etherhidingtracker.

Step 2: Create the File in VS Code
In the VS Code sidebar (left):

Right-click on the folder name

Click New File

Type REPORT.md and press Enter

An empty editor opens.

Step 3: Paste the Report
Copy the block below and paste it into the VS Code editor. Do not paste it into PowerShell.

markdown
# EtherHiding Contract Tracker
## Investigation Report

> **Independent reconstruction of a live EtherHiding malware campaign on the Polygon blockchain using only public data and free tooling.**

---

| Field | Value |
|---|---|
| **Analyst** | [Your Name] |
| **Date** | 2026-10-13 |
| **Chain** | Polygon Mainnet (chain ID 137) |
| **Tooling** | Python 3.13 · web3.py · Alchemy free tier |
| **Total Contracts** | 15 across 3 template generations |
| **Key Finding** | 11-contract reserve cluster — 6 dormant, 5 active |
| **Status** | Complete · Reproducible · Open Source |

---

## Table of Contents

1. [Executive Summary](#1-executive-summary)
2. [Background: What Is EtherHiding?](#2-background-what-is-etherhiding)
3. [Methodology](#3-methodology)
4. [Findings](#4-findings)
5. [Detection Signatures](#5-detection-signatures)
6. [Reproducing This Investigation](#6-reproducing-this-investigation)
7. [Limitations](#7-limitations)
8. [Recommendations](#8-recommendations)
9. [References](#9-references)

---

## 1. Executive Summary

This report documents the independent reconstruction of an active EtherHiding malware campaign's on-chain command-and-control infrastructure. The investigation began from three contract addresses published by GuidePoint Security in September 2026 and expanded to cover the operator's complete deployment history.

### Headline Findings

**15 contracts** were identified across **3 template generations**, distributed between **2 operator wallets**:

- **3 Template A contracts** — historical C2 storage, emit rotation events
- **11 Template B contracts** — a reserve cluster deployed May 2026
- **1 Template C contract** — hybrid design with a live 60-byte payload

**The reserve cluster is mixed-state:**

| State | Count | Signal |
|---|---|---|
| Dormant | 6 | Blob length = 0 bytes |
| Active | 5 | Blob length 64–80 bytes |

This mixed state was **not previously documented**. GuidePoint's report described the Template B/C contracts as unresolved; this investigation determined their purpose as pre-positioned, activatable C2 slots.

### Why This Matters

EtherHiding makes C2 infrastructure resistant to takedown — the operator can rotate addresses with a single blockchain transaction. However, every rotation is permanently recorded on a public ledger. This investigation demonstrates that **the entire campaign infrastructure is reconstructable from public data using free tools**, without any paid API, indexer, or archive node.

---

## 2. Background: What Is EtherHiding?

EtherHiding is a technique in which malware retrieves its command-and-control (C2) address by reading a smart contract on a public blockchain instead of contacting a hardcoded domain.

### How It Works

1. **Deployment** — The operator deploys a smart contract that stores an encrypted C2 address.
2. **Distribution** — Compromised websites (often WordPress) inject a JavaScript loader that prompts the victim with a fake browser update or CAPTCHA.
3. **Resolution** — When the victim clicks, the loader performs a read-only `eth_call` to the contract. No gas is paid, no transaction is recorded.
4. **Rotation** — The operator updates the contract with a new encrypted address. All infected machines follow automatically on their next check-in.

### The Defensive Advantage

The properties that make EtherHiding resilient also make it auditable:

- **Immutability** — Every C2 rotation is permanently on-chain
- **Transparency** — Contract bytecode, storage, and history are public
- **Determinism** — Contract addresses are derived from wallet nonces
- **Cost** — All queries used here are free

The asymmetry: the attacker gains censorship resistance; the defender gains a complete, permanent intelligence record.

---

## 3. Methodology

### 3.1 Seed Intelligence

Three contract addresses were sourced from GuidePoint Security's September 2026 report:

| Contract | Owner |
|---|---|
| `0xde2d34339c279a7a79bc4fc1c4f37d3c055211b7` | Wallet 1 |
| `0xa982e044217b6bbaa7b3123b670c1c0ca1138a37` | Wallet 1 |
| `0x308e9ecc849533a042f13fd77e5c82ec3c62e9f2` | Wallet 2 |

Two operator wallets were identified:

| Wallet | Address | Deployments |
|---|---|---|
| Wallet 1 | `0xd802C9427ce416B9DAb2db5aDD76EfAA6d9d826a` | 2 |
| Wallet 2 | `0x6a6e177dcf992ac16f7367c14b26a3cf4775dfde` | 13 |

### 3.2 Contract Fingerprinting

Each candidate contract was evaluated against a four-signal fingerprint:

| Signal | Method | Meaning |
|---|---|---|
| **C2 getter present** | Bytecode scan for `0xb68d1809` or `0x3bc5de30` | Likely EtherHiding |
| **Ownable pattern** | Bytecode scan for `0x8da5cb5b` + `0xf2fde38b` | Operator controls updates |
| **Payload return** | `eth_call` to the getter | Non-empty blob = active |
| **Owner resolution** | `eth_call` to `owner()` | Confirm operator wallet |

A contract matching signals 1 and 2 is classified as suspicious. Matching all four is a positive identification.

### 3.3 Wallet-to-Contract Pivot

Rather than relying on a block explorer API, contract addresses were derived **deterministically** from the operator wallets:

```python
contract_address = keccak256(rlp([deployer, nonce]))[12:]
```

Because the operator wallets never send value transfers, every nonce corresponds to a contract deployment. Iterating from nonce 0 to the current transaction count reconstructs the complete deployment history with no indexer required.

**Key advantage:** This technique works on any EVM chain, with any wallet, using only a basic RPC connection.

### 3.4 Event Scanning

Template A contracts emit a specific event on C2 rotation:

```
topic = 0x868f5f914e26b486c50b15494d56c6b2f2f17f6514343909bd36a034c19452cc
```

Scanning for this topic across block ranges detects rotations in real time. Templates B and C emit no events, so they can only be discovered via the wallet pivot.

---

## 4. Findings

### 4.1 Complete Contract Inventory

**Wallet 1** — `0xd802C9427ce416B9DAb2db5aDD76EfAA6d9d826a`

| Nonce | Address | Template | Status |
|---|---|---|---|
| 0 | `0xa982E044217b6Bbaa7b3123b670C1c0CA1138A37` | A | Historical |
| 4 | `0xde2d34339C279A7a79bc4fC1C4F37d3C055211b7` | A | Historical |

**Wallet 2** — `0x6A6e177DcF992Ac16f7367C14b26a3Cf4775dfdE`

| Nonce | Address | Template | Status |
|---|---|---|---|
| 0 | `0x308e9ecc849533a042f13fD77E5C82eC3c62e9f2` | A | Historical |
| 3 | `0x75A91aCdB3dd25B39fe0619d2A00DE49A8e56eb9` | B | Dormant |
| 4 | `0x4c7C35db1f8E23301a447801B019968D8b4A6329` | B | Dormant |
| 5 | `0x700121c474A1eF6b4BAC074e0B805F262a5BD46e` | B | Dormant |
| 6 | `0xd245e35d988244528F10582107Ce1BC38DA35a24` | B | Dormant |
| 7 | `0x96C90CD4E58718cb20A58e14b7931eD94Ad040C7` | B | Dormant |
| 8 | `0x0dC9f5de745394D98C0cE163D498043EB325AC45` | B | Dormant |
| 9 | `0xFad3F51fF70223CadeecCf8FCf2D362533f360eE` | B | Active (80 B) |
| 12 | `0xB685a24587658989410D68500448f45467CA47D8` | B | Active (76 B) |
| 16 | `0xed4417B3992A4e6613f734E720e24DE5630695f8` | B | Active (80 B) |
| 18 | `0xA5517ea1914EbfcEcDe8528e0973D98E60178607` | B | Active (64 B) |
| 20 | `0x5C4576E21809FfA8d265bB7385f044A693356c43` | B | Active (64 B) |
| 22 | `0x46124F9F0f0d70c8b9e62258179574E05FbFF181` | C | Active (60 B) |

### 4.2 Template Comparison

| Property | Template A | Template B | Template C |
|---|---|---|---|
| **Deployed** | Nov 2025 – Apr 2026 | May 2026 | May 2026 |
| **Bytecode size** | 2766–2786 B | 1856 B | 1441 B |
| **External selectors** | 5 | 2 | 5 |
| **C2 getter** | `0xb68d1809` | `0x3bc5de30` | `0x3bc5de30` + `0x73d4a13a` |
| **Ownable pattern** | Yes | No | Yes |
| **Emits events** | Yes | No | No |
| **Payload format** | base64-of-base64 | raw binary | raw binary |
| **Payload size** | ~128 B | 0 B or 64–80 B | 60 B |

### 4.3 The Reserve Cluster — Primary Novel Finding

This is the investigation's most significant contribution. GuidePoint's September 2026 report stated:

> *"The 12 Template B/C contracts, deliberately designed to resist the exact enumeration technique that exposed Template A, remain the one piece of this campaign's infrastructure whose full purpose we still haven't determined."*

**This investigation determined that purpose.**

All 11 Template B contracts share identical bytecode, expose only two selectors (`0x3bc5de30`, `0x47064d6a`), and store the owner in storage slot 1. However, their current states are **not uniform**:

| Group | Count | Blob Length | Interpretation |
|---|---|---|---|
| **Dormant** | 6 | 0 bytes | Pre-deployed, awaiting activation |
| **Active** | 5 | 64–80 bytes | Live C2 slots currently in use |

**Interpretation:**

The operator deployed a batch of 11 reserve contracts in May 2026 and has since activated 5. The dormant/active split appears deliberate — a researcher who probes a single contract and sees an empty blob may conclude the cluster is inactive and stop investigating.

**Activation mechanism:** The second selector, `0x47064d6a`, reverts on `eth_call`. It is almost certainly an owner-only setter (`setData` or equivalent). Activation is a single transaction from the operator wallet.

### 4.4 Template C Payload Analysis

The single Template C contract returns a 60-byte binary blob from both getters:

```
6e8797db628a9d2f72d20747aa9753bcba8b5d4033923ba529c4d5ce3ad6d8
776ec70744e9d513ebef9a12442c9b6cf977919dcf39cad42529834706
```

Analysis results:

| Test | Result |
|---|---|
| Valid base64 | No |
| Valid UTF-8 | No |
| Single-byte XOR (all 255 keys) | No printable output |
| XOR with known campaign keys | No |
| Repeating pattern (period 2–32) | None detected |
| Byte-frequency uniformity | High (max count: 2 of 60) |

**Conclusion:** The payload is encrypted with a key embedded in the malware binary, not recoverable from on-chain data alone. This matches the operational model described in public reporting.

---

## 5. Detection Signatures

### 5.1 Template A

```
bytecode_size      between 2700 and 2800 bytes
required_selectors 0xb68d1809, 0x8da5cb5b, 0xf2fde38b
getter_result      ABI string > 100 bytes from 0xb68d1809
event_topic        0x868f5f914e26b486c50b15494d56c6b2f2f17f6514343909bd36a034c19452cc
```

### 5.2 Template B

```
bytecode_size      exactly 1856 bytes
required_selectors 0x3bc5de30, 0x47064d6a
forbidden_selector 0x8da5cb5b (absent)
getter_result      ABI string from 0x3bc5de30
                   - 0 bytes  → dormant
                   - > 0 bytes → active
```

### 5.3 Template C

```
bytecode_size      exactly 1441 bytes
required_selectors 0x3bc5de30, 0x73d4a13a, 0x8da5cb5b, 0xf2fde38b
getter_result      ABI string of exactly 60 bytes from both getters
```

### 5.4 Highest-Priority Alert

**A dormant Template B contract transitioning from 0 bytes to non-zero is the strongest actionable signal this investigation produces.**

It indicates that the operator has activated a reserve slot and is preparing to serve new malware through a previously silent channel. This event has no legitimate explanation.

---

## 6. Reproducing This Investigation

### Prerequisites

- Python 3.10 or newer
- A free Alchemy account with a Polygon Mainnet app enabled
- No paid APIs, no archive node, no indexer

### Setup

```bash
git clone https://github.com/luffytaro98uk-png/etherhiding-tracker.git
cd etherhiding-tracker
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
cp .env.example .env
```

### Verify a Single Contract

```bash
python cli.py fingerprint 0xde2d34339c279a7a79bc4fc1c4f37d3c055211b7
```

Expected: `*** CONFIRMED ETHERHIDING (Template A) ***`

### Reconstruct a Wallet's Full History

```bash
python cli.py wallet 0x6a6e177dcf992ac16f7367c14b26a3cf4775dfde
```

Expected: 13 contracts discovered, each fingerprinted.

### Monitor for Activation

```bash
python cli.py monitor
```

Polls all 11 Template B contracts every 10 minutes. Alerts on any transition from dormant to active.

---

## 7. Limitations

| Limitation | Impact |
|---|---|
| **No decryption** | C2 domains remain unknown; identification rests on structural fingerprints |
| **No archive access** | Historical state queries failed on Alchemy free tier |
| **No event history for B/C** | Silent contracts leave no on-chain log trail |
| **Snapshot in time** | Findings reflect state at block 95,470,427 |

None of these limitations prevent detection or monitoring. They affect only the depth of retrospective attribution.

---

## 8. Recommendations

### For Defenders

1. **Add the Template A event topic to blockchain monitoring.** Any event with this topic indicates an active C2 rotation.
2. **Watch the two operator wallets for nonce changes.** A nonce increase signals a new deployment, fingerprintable immediately.
3. **Poll all 11 Template B contracts periodically.** Alert on any transition from empty to non-empty blob.
4. **Block outbound Polygon RPC traffic from endpoints with no business reason to query Polygon.** Malware must reach an RPC endpoint to resolve its C2.

### For Threat Intelligence Sharing

The 15 contract addresses and 2 wallet addresses should be submitted to:

- [Polygonscan](https://polygonscan.com) — address flagging
- [Chainabuse](https://www.chainabuse.com) — community reporting
- GuidePoint Security — extending their prior investigation

### For Future Research

- Test whether Template B activation correlates with C2 domain registration events
- Scan adjacent chains (BSC, Base, Ethereum) for the same template bytecode
- Reverse-engineer the malware sample to recover the payload decryption key

---

## 9. References

| Source | Link |
|---|---|
| GuidePoint Security | [EtherHiding Exposed](https://www.guidepointsecurity.com/blog/etherhiding-exposed-deep-dive/) |
| DeFi Planet | [Why EtherHiding May Be Dangerous](https://defi-planet.com/2026/04/why-etherhiding-may-be-one-of-the-most-dangerous-crypto-attacks-youve-ever-heard-of/) |
| Cribl | ClickFix / EtherHiding analysis |
| CSIDE | Dormant smart contract reactivation commentary |

---

## Appendix A: Tool Reference

| Script | Purpose |
|---|---|
| `cli.py` | Unified command interface |
| `fingerprint.py` | Standalone contract classifier |
| `derive_contracts.py` | Wallet-to-contract pivot |
| `tracker.py` | Event scan + fingerprint |
| `monitor.py` | Template B activation watcher |
| `analyze.py` | Selector extraction |
| `probe_templates.py` | Function call probing |
| `decode_template_c.py` | Payload extraction |

## Appendix B: Repository

- **Source:** [github.com/luffytaro98uk-png/etherhiding-tracker](https://github.com/luffytaro98uk-png/etherhiding-tracker)
- **License:** MIT
- **Contact:** [luffy.taro98uk@gmail.com]

---

*End of report. This document is a point-in-time analysis and reflects the state of the Polygon blockchain at block 95,470,427.*