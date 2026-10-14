EtherHiding Contract Tracker - Investigation Report
Analyst: Himanshu Pandey
Date: 2026-10-13
Chain: Polygon Mainnet
Tooling: Python 3.13 · web3.py · Alchemy RPC (free tier)
Status: Complete - 15 contracts identified across 3 template generations

Executive Summary
This report documents the reconstruction and extension of an EtherHiding
malware campaign's on-chain infrastructure, using only public blockchain
data and a free-tier RPC provider. The investigation began from three known
contract addresses published in GuidePoint Security's September 2026 deep
dive and expanded to cover the operator's full deployment history.

Note on Novelty and Confidence
This work reproduces and extends GuidePoint Security's September 2026
EtherHiding investigation. Most structural findings - 15 contracts, 3
templates, 2 operator wallets, and the wallet-pivot methodology - are
replications of their published analysis. The value of replication is that
it confirms the original findings are accurate and provides a free,
indexer-independent implementation.

### Course Corrections During This Investigation

Two interpretations were proposed during the course of this work and later
refuted by additional evidence. They are documented here so the reasoning
trail is transparent.

**Correction 1 — "Template B contracts are dormant reserve slots."**

The initial observation was based on a state snapshot: when the 11
Template B contracts were first queried, 6 returned empty payloads and 5
returned 64–80 byte payloads. The interpretation proposed was that the
empty contracts were reserve slots awaiting future activation (H1 in the
hypothesis table).

This interpretation was refuted by decoding the setData calldata for every
write. The evidence showed that 4 of the 5 active contracts were written to
within minutes of deployment — not weeks or months later. A "reserve slot
awaiting activation" model predicts delayed writes; the actual pattern is
immediate writes with subsequent rotation on one contract only. The correct
description of the 6 empty contracts is most likely "deployed but never
written to."

**Correction 2 — "The C2 domains can be recovered by cryptanalysis."**

After discovering that the payloads are base64-encoded binary, the initial
hypothesis was that a known-plaintext attack against fixed URL markers
would recover the encryption key — following the approach GuidePoint
described.

This hypothesis was refuted by three tests:

1. Applying the two known campaign keys (`$%)W$fgl34`, `!sdf$&G321`)
   produced no readable output.
2. Crib-dragging `https://`, `/UpdateCheck/`, and common TLDs across all
   payloads produced no coherent candidate.
3. Multi-ciphertext XOR (`C1 XOR C2 = P1 XOR P2`) on same-contract write
   pairs produced random-looking output (25–40% printable, statistically
   indistinguishable from noise).

The conclusion is that the payloads use per-write keys. The specific C2
domains remain unrecovered and are not recoverable from on-chain data
alone.

**Why documenting this matters.**

The final report reflects the corrected interpretation, not the initial
one. Publishing only the corrected version would hide the reasoning that
led there; publishing only the initial version would present a hypothesis
as a finding. Both versions are shown so readers can see the evidence that
changed the conclusion.

Three elements are genuinely new:

An indexer-free implementation of the wallet-pivot technique using
only Alchemy's free tier and deterministic nonce derivation. The original
investigation used a mix of chain-wide event sweeps and full wallet
transaction pulls. This implementation reconstructs all 15 contracts
from the two wallet addresses alone.

The first published state snapshot of the 11 Template B contracts,
paired with a calldata-derived write history that confirms the setter
selector (0x47064d6a = setData(string)) and documents rotation
cadence per contract.

A multi-ciphertext cryptanalysis result: the payloads use per-write
keys and are not trivially XOR-encoded, consistent with AES-CTR/CBC.

Key findings:

All 15 contracts deployed by the two operator wallets were independently
rediscovered using deterministic address derivation from wallet nonces -
no indexed API or paid service required.

The three template generations described in the GuidePoint report were
confirmed and characterized by their function selectors, bytecode sizes,
and payload formats.

The setter selector is confirmed: 0x47064d6a is setData(string).
Writes occur at or near deployment for the 5 active Template B
contracts; one contract (0x5C4576E2) received two additional writes
over a 77-day window.

The "reserve slot awaiting activation" hypothesis is refuted by
calldata analysis. The 6 empty Template B contracts were most likely
never written to, not held in reserve.

Payload encryption uses per-write keys. Multi-ciphertext XOR
analysis produced random-looking output; repeating-key XOR and known
campaign keys both fail. Consistent with AES-CTR or AES-CBC.

1. Background: What Is EtherHiding?
EtherHiding is a technique where malware retrieves its command-and-control
(C2) address by reading a smart contract on a public blockchain rather than
contacting a hardcoded domain. The read is performed with eth_call, which:

Costs nothing (no gas, read-only)

Leaves no on-chain trace

Cannot be taken down by seizing a server or domain

The operator can rotate the C2 address for all infected machines with a
single contract write. The trade-off for the attacker: every rotation is
recorded permanently on a public ledger, making the infrastructure
reconstructable by defenders.

2. Seed Intelligence
Starting point: three contract addresses from GuidePoint Security's report,
"EtherHiding Exposed: Inside a Blockchain-powered Malware Campaign Hiding in
Plain Sight" (published 2026-09-17).

Contract	Owner Wallet
0xde2d34339c279a7a79bc4fc1c4f37d3c055211b7	Wallet 1
0xa982e044217b6bbaa7b3123b670c1c0ca1138a37	Wallet 1
0x308e9ecc849533a042f13fd77e5c82ec3c62e9f2	Wallet 2
Operator wallets:

Wallet 1: 0xd802C9427ce416B9DAb2db5aDD76EfAA6d9d826a

Wallet 2: 0x6a6e177dcf992ac16f7367c14b26a3cf4775dfde

3. Methodology
3.1 Contract Fingerprinting
Each candidate contract was evaluated against a four-signal fingerprint:

C2 getter selector present - either 0xb68d1809 (Template A) or
0x3bc5de30 (Templates B/C) appearing in bytecode

OpenZeppelin Ownable pattern - selectors 0x8da5cb5b (owner) and
0xf2fde38b (transferOwnership) present

Getter returns a payload - eth_call to the getter returns an
ABI-encoded blob; length reported is the actual string length, not the
wrapper size

Owner resolves to a known operator wallet

A contract matching signals 1 and 2 is classified as suspicious. Matching
all four is a positive identification.

3.2 Wallet-to-Contract Pivot
Rather than relying on a block explorer API (Polygonscan V1 was deprecated
during this investigation), contract addresses were derived
deterministically from the operator wallets:

python
contract_address = keccak256(rlp([deployer_address, nonce]))[12:]
Every nonce corresponds to a transaction from the wallet. Most are
deployments; some are zero-value function calls. The derivation iterates
over all nonces, computes the derived address for each, and skips any that
resolve to empty addresses.

The gaps in the nonce sequence (Wallet 2's 1–2, 10–11, 13–15, 17, 19, 21)
are the non-deployment transactions. Their analysis is described in
Section 4.5.

3.3 Event Scanning
Template A contracts emit a specific event on C2 rotation:

text
topic = 0x868f5f914e26b486c50b15494d56c6b2f2f17f6514343909bd36a034c19452cc
Scanning for this topic across block ranges detects rotations in real time.
Templates B and C emit no events, so they cannot be discovered this way -
only via the wallet pivot.

4. Findings
4.1 Complete Contract Inventory
Fifteen contracts were confirmed across the two operator wallets. Contract
addresses are grouped by the wallet that deployed them.

Wallet 1 (0xd802C9427ce416B9DAb2db5aDD76EfAA6d9d826a) - 2 deployments:

Nonce	Address	Template	On-chain state	Sample reference
0	0xa982E044217b6Bbaa7b3123b670C1c0CA1138A37	A	payload present (48 B)	unknown
4	0xde2d34339C279A7a79bc4fC1C4F37d3C055211b7	A	payload present (48 B)	confirmed (GuidePoint primary)
Wallet 2 (0x6A6e177DcF992Ac16f7367C14b26a3Cf4775dfdE) - 13 deployments:

Nonce	Address	Template	On-chain state	Sample reference
0	0x308e9ecc849533a042f13fD77E5C82eC3c62e9f2	A	payload present (36 B)	unknown
3	0x75A91aCdB3dd25B39fe0619d2A00DE49A8e56eb9	B	payload empty	unknown
4	0x4c7C35db1f8E23301a447801B019968D8b4A6329	B	payload empty	unknown
5	0x700121c474A1eF6b4BAC074e0B805F262a5BD46e	B	payload empty	unknown
6	0xd245e35d988244528F10582107Ce1BC38DA35a24	B	payload empty	unknown
7	0x96C90CD4E58718cb20A58e14b7931eD94Ad040C7	B	payload empty	unknown
8	0x0dC9f5de745394D98C0cE163D498043EB325AC45	B	payload empty	unknown
9	0xFad3F51fF70223CadeecCf8FCf2D362533f360eE	B	payload present (80 B)	unknown
12	0xB685a24587658989410D68500448f45467CA47D8	B	payload present (76 B)	unknown
16	0xed4417B3992A4e6613f734E720e24DE5630695f8	B	payload present (80 B)	unknown
18	0xA5517ea1914EbfcEcDe8528e0973D98E60178607	B	payload present (64 B)	unknown
20	0x5C4576E21809FfA8d265bB7385f044A693356c43	B	payload present (64 B)	unknown
22	0x46124F9F0f0d70c8b9e62258179574E05FbFF181	C	payload present (60 B)	unknown
4.2 Template Comparison
Property	Template A	Template B	Template C
Deployed	Nov 2025 – Apr 2026	May 2026	May 2026
Bytecode size	2766–2786 B	1856 B	1441 B
External selectors	5	2	5
C2 getter	0xb68d1809	0x3bc5de30	0x3bc5de30, 0x73d4a13a
Setter	0xb249cd2d	0x47064d6a	0xab62f0e1 (unverified)
Ownable pattern	Yes	No	Yes
Emits events	Yes	No	No
Payload format	base64-of-base64	base64 binary	raw binary
Payload size (as reported)	25–48 B	0 or 46–80 B	60 B
4.3 Template Selectors
Template A (0xde2d34339C279A7a79bc4fC1C4F37d3C055211b7):

text
0x893d20e8   owner-related getter
0x8da5cb5b   owner()
0xb249cd2d   setter - decoded as "Update Domain" on Polygonscan
0xb68d1809   C2 getter  ← primary indicator
0xf2fde38b   transferOwnership(address)
Template B (0x75A91aCdB3dd25B39fe0619d2A00DE49A8e56eb9):

text
0x3bc5de30   C2 getter  ← returns empty string when unwritten
0x47064d6a   setData(string)  ← confirmed setter
Template C (0x46124F9F0f0d70c8b9e62258179574E05FbFF181):

text
0x3bc5de30   C2 getter  ← returns 60-byte ciphertext
0x73d4a13a   C2 getter  ← returns the same 60-byte ciphertext
0x8da5cb5b   owner()
0xab62f0e1   reverts on arg-less call; setter behaviour unverified
0xf2fde38b   transferOwnership(address)
4.4 The Mixed-State Template B Cluster
All 11 Template B contracts share identical bytecode (1856 bytes), expose
only two selectors (0x3bc5de30, 0x47064d6a), and store the owner in
storage slot 1. However, their current states are not uniform.

Empty (payload length = 0): 6 contracts

text
0x75A91aCdB3dd25B39fe0619d2A00DE49A8e56eb9
0x4c7C35db1f8E23301a447801B019968D8b4A6329
0x700121c474A1eF6b4BAC074e0B805F262a5BD46e
0xd245e35d988244528F10582107Ce1BC38DA35a24
0x96C90CD4E58718cb20A58e14b7931eD94Ad040C7
0x0dC9f5de745394D98C0cE163D498043EB325AC45
With payload (length in parentheses): 5 contracts

text
0xFad3F51fF70223CadeecCf8FCf2D362533f360eE (80 B)
0xB685a24587658989410D68500448f45467CA47D8 (76 B)
0xed4417B3992A4e6613f734E720e24DE5630695f8 (80 B)
0xA5517ea1914EbfcEcDe8528e0973D98E60178607 (64 B)
0x5C4576E21809FfA8d265bB7385f044A693356c43 (64 B)
Interpretation. The operator deployed 11 contracts in May 2026 (10 on
May 5, 1 on May 7 per GuidePoint). Five received a payload at or near
deployment; six did not. One of the five (0x5C4576E2) received two
additional writes over a 77-day window. The write history is recovered
from setData calldata in Section 4.5. The purpose of the 6 empty
contracts remains uncertain.

4.5 Confirmed Rotation Mechanism
Analysis of Wallet 2's non-deployment transactions - decoded from on-chain
calldata - confirms the mechanism that populates the Template B contracts.

The setter selector is confirmed.

Every write to a Template B contract uses selector 0x47064d6a. ABI
decoding of the calldata on Polygonscan resolves this to
setData(string newData). The argument is a base64-encoded binary
payload.

For example, the most recent write to 0x5C4576E2 (block 90694377,
83 days ago) stored the following string:

text
NYDtSzP8SgCynDVgIpXhVTE4HOYOU/7PANItAbucz+5tNA63oyJyGPs2KeDcYOw==
which base64-decodes to 46 bytes of high-entropy binary.

The write history is recoverable from calldata.

Each setData transaction's calldata contains the exact payload written
at that block. This gives a complete write history without requiring an
archive node:

Contract	Block	Age	Payload size
0x5C4576E2	86520883	160 days	48 B
0x5C4576E2	90334311	89 days	51 B
0x5C4576E2	90694377	83 days	46 B
0xFad3F51f	86434237	161 days	48 B
0xFad3F51f	86434239	161 days	55 B
0xFad3F51f	86434517	161 days	59 B
0xB685a245	86434300	161 days	55 B
0xed4417B3	86434564	161 days	58 B
0xA5517ea1	86435182	161 days	48 B
0x308e9ecc (A)	80401978	301 days	30 B
0x308e9ecc (A)	80402130	301 days	25 B
Rotation cadence varies by contract.

0xFad3F51f received three writes within a single hour of its
deployment (blocks 86434237 through 86434517).

0x5C4576E2 received three writes spread across 77 days
(blocks 86520883 through 90694377).

Four of the five active Template B contracts received exactly one write
at or near deployment.

This refutes the "reserve slot awaiting activation" hypothesis.

An earlier interpretation based on state-snapshot data suggested that the
6 empty Template B contracts were reserve slots awaiting activation. The
calldata analysis shows a different pattern: for the 5 contracts that hold
payloads, the writes happen at or near deployment, not weeks or months
later. The 6 empty contracts most likely reflect deployments that were
never written to, not slots held in reserve.

The correct description is:

Eleven Template B contracts were deployed in a single wave in May 2026.
Five received a payload at or near deployment; six did not. One of the
five (0x5C4576E2) received two subsequent writes over a 77-day
window, indicating an ongoing rotation cadence on that contract.

The mixed state of the cluster is documented. The operational role of the
6 empty contracts remains uncertain.

4.6 Cryptanalysis Results
An attempt was made to decrypt the payloads using multi-ciphertext
cryptanalysis. The following tests were run against the 7 payloads
extracted from setData calldata.

Test 1 - Single-key XOR with known campaign keys.

Both the GuidePoint XOR key ($%)W$fgl34) and the traffic key
(!sdf$&G321) were applied to each payload. Neither produced readable
output.

Test 2 - Repeating-key XOR crib-drag.

Common URL markers (https://, http://, /UpdateCheck/, .shop,
.online, .site, .xyz, .top, .com, .net, .biz) were
crib-dragged across all payloads. No crib produced a coherent plaintext
candidate.

Test 3 - Multi-ciphertext XOR on same-contract writes.

If two writes to the same contract used the same keystream,
C1 XOR C2 = P1 XOR P2. Three write pairs to 0x5C4576E2 and three to
0xFad3F51f were XORed. Printable output ratios ranged from 25% to 40%
- statistically indistinguishable from random byte output.

Test 4 - Shared prefix analysis.

The two Template A payloads to 0x308e9ecc share an 8-byte prefix
(4c19435a01635f5d) before diverging. This is consistent with a fixed or
semi-fixed header, but the remaining bytes show no structure.

Conclusion.

The payloads are encrypted with a per-write key. The absence of any
repeating pattern and the lack of structure in XOR-pair output are
consistent with AES-CTR, AES-CBC, or a similar authenticated stream
cipher using a per-write nonce. Decryption is not feasible from on-chain
data alone. Recovery of the plaintext would require either the malware
binary (to extract the key or key-derivation logic) or a successful
known-plaintext attack with a much larger corpus.

5. Detection Signatures
These are CTI and research tooling artifacts. They are not enterprise
detections. Section 5.5 describes how to bridge them into SOC workflows.

5.1 Template A
text
bytecode_size      between 2700 and 2800 bytes
required_selectors 0xb68d1809, 0x8da5cb5b, 0xf2fde38b
setter_selector    0xb249cd2d
getter_result      ABI string from 0xb68d1809; length 25–48 bytes
event_topic        0x868f5f914e26b486c50b15494d56c6b2f2f17f6514343909bd36a034c19452cc
5.2 Template B
text
bytecode_size      exactly 1856 bytes
required_selectors 0x3bc5de30, 0x47064d6a
forbidden_selector 0x8da5cb5b (absent)
setter_selector    0x47064d6a - setData(string)
getter_result      ABI string from 0x3bc5de30
                   - 0 bytes  → never written
                   - > 0 bytes → payload present
5.3 Template C
text
bytecode_size      exactly 1441 bytes
required_selectors 0x3bc5de30, 0x73d4a13a, 0x8da5cb5b, 0xf2fde38b
getter_result      ABI string of exactly 60 bytes from both getters
5.4 Highest-Priority Signal
A Template B contract whose 0x3bc5de30 response changes from 0 bytes to
non-zero indicates a state change worth investigating. A write from the
operator wallet to 0x47064d6a on any Template B contract is a
high-confidence operator action.

5.5 Bridging to Enterprise Detection
The full 15-address list can be used as a match set on proxy or
TLS-inspected HTTP POST bodies for JSON-RPC eth_call where the to field
is one of the known contracts. Scoped to non-browser processes
(powershell.exe, pwsh.exe) connecting to the public Polygon RPC
endpoints, this is a low-noise detection that the original GuidePoint
report does not provide.

6. Tooling
All scripts are in this repository and require only a free Alchemy account.

Script	Purpose
cli.py	Unified command interface
tracker.py	Event scan + fingerprint of known contracts
fingerprint.py	Four-signal contract classification
derive_contracts.py	Deterministic contract discovery from wallet nonces
monitor.py	Template B state-change watcher
analyze.py	Selector extraction and storage dump
probe_templates.py	Function call probing for all selectors
decode_template_c.py	Payload extraction and transformation analysis
fetch_setter_calldata.py	Extract historical payloads from transaction calldata
cryptanalysis.py	Multi-ciphertext XOR analysis
All scripts run on the Alchemy free tier. No paid APIs are required.

7. Limitations
Payload decryption was not achieved. Multi-ciphertext cryptanalysis
ruled out repeating-key XOR, but the algorithm and key remain unknown
from on-chain data alone. Recovery would require the malware binary or a
known-plaintext attack against a much larger corpus.

Historical state reads were not available. Alchemy's free tier does
not provide archive-node access. Transaction calldata (Section 4.5)
substitutes for historical state reads on the contracts where writes
occurred.

Domain attribution is not possible without decryption.

The mixed-state snapshot reflects one point in time. Findings are
valid as of block 95,470,427.

8. Recommendations
For Defenders
Monitor the Template A event topic. Any event with topic
0x868f5f91... indicates a C2 rotation on a Template A contract.

Watch the two operator wallets for nonce changes. A nonce increase
signals a new transaction, which can be fingerprinted immediately.

Poll all 11 Template B contracts periodically. Alert on any change
in the 0x3bc5de30 response.

Block outbound Polygon RPC traffic from endpoints with no business
reason to query Polygon. Malware must reach an RPC endpoint to
resolve its C2.

For Threat Intelligence Sharing
The 15 contract addresses and 2 wallet addresses should be submitted to:

Polygonscan (malicious address flagging)

Chainabuse

GuidePoint Security (as a follow-up to their September 2026 report)

9. References
Source	URL
GuidePoint Security - EtherHiding Exposed	https://www.guidepointsecurity.com/blog/etherhiding-exposed-deep-dive/
DeFi Planet - EtherHiding overview	https://defi-planet.com/2026/04/why-etherhiding-may-be-one-of-the-most-dangerous-crypto-attacks-youve-ever-heard-of/
10. Conclusion
A complete EtherHiding campaign infrastructure was reproduced from public
blockchain data using only free tooling. The investigation confirmed the
three-template model described in prior reporting, recovered the full
write history of the active contracts from transaction calldata, confirmed
the setter selector 0x47064d6a as setData(string), and ruled out
repeating-key XOR encryption.

The "reserve slot" interpretation was refuted by the calldata analysis.
The 6 empty Template B contracts were most likely never written to, not
held in reserve for future activation. The C2 domains stored in the active
contracts remain encrypted and are not recoverable from on-chain data
alone.

End of report. This document is a point-in-time analysis reflecting the
state of the Polygon blockchain at block 95,470,427.