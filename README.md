# EtherHiding Contract Tracker

A defensive tool for detecting and tracking [EtherHiding](https://www.guidepointsecurity.com/blog/etherhiding-exposed-deep-dive/) malware infrastructure on the Polygon blockchain.

EtherHiding is a technique where malware resolves its command-and-control (C2) address by reading a smart contract on a public blockchain instead of a hardcoded domain. This tool fingerprints such contracts, reconstructs the operator's full deployment history, and extracts historical payloads from transaction calldata.

## What It Does

- **Event scanning** — detects C2 rotations by scanning for the operator's specific event topic
- **Contract fingerprinting** — classifies any address against four independent on-chain signals
- **Wallet pivot** — deterministically derives every contract a wallet has ever deployed, using only its nonce
- **Calldata extraction** — recovers historical payloads from `setData` transaction calldata without needing an archive node
- **State monitor** — watches the 11 Template B contracts and alerts on state changes

## Findings

This project reproduces and extends GuidePoint Security's September 2026 EtherHiding investigation. Key results:

- **15 contracts** across 3 template generations confirmed via an indexer-free wallet-pivot technique using only Alchemy's free tier.
- **Setter selector `0x47064d6a` (`setData(string)`) is confirmed** by decoding transaction calldata.
- **Full write history recovered from calldata** without an archive node:
  - `0x5C4576E2` was written to three times over 77 days.
  - `0xFad3F51f` was written three times within one hour.
  - Four of the five active Template B contracts received exactly one write at deployment.
- **Multi-ciphertext cryptanalysis** rules out repeating-key XOR. The payloads use per-write keys, consistent with AES-CTR/CBC.
- **The "reserve slot awaiting activation" hypothesis is refuted** — writes occur at or near deployment, not weeks later.

Full detail is in [REPORT.md](./REPORT.md).

## Requirements

- Python 3.10 or newer
- A free [Alchemy](https://dashboard.alchemy.com) account with a Polygon Mainnet app enabled
- No paid APIs required

## Installation

```bash
git clone https://github.com/luffytaro98uk-png/etherhiding-tracker.git
cd etherhiding-tracker

python -m venv .venv
# Windows:
.\.venv\Scripts\Activate.ps1
# macOS/Linux:
source .venv/bin/activate

pip install -r requirements.txt
Configuration
Copy .env.example to .env and fill in your Alchemy RPC URL:

bash
cp .env.example .env
Edit .env:

text
ALCHEMY_RPC_URL=https://polygon-mainnet.g.alchemy.com/v2/YOUR_KEY_HERE
Make sure your Alchemy app has Polygon Mainnet enabled in the dashboard.

Usage
Unified CLI
bash
python cli.py fingerprint 0xde2d34339c279a7a79bc4fc1c4f37d3c055211b7
python cli.py wallet 0xd802C9427ce416B9DAb2db5aDD76EfAA6d9d826a
python cli.py scan --blocks 1000
python cli.py templates
python cli.py monitor
python cli.py report
Standalone Tools
Script	Purpose
cli.py	Unified command interface
tracker.py	Event scan + fingerprint of known contracts
fingerprint.py	Four-signal contract classification
derive_contracts.py	Deterministic contract discovery from wallet nonces
monitor.py	Template B state-change watcher
fetch_setter_calldata.py	Extract historical payloads from transaction calldata
cryptanalysis.py	Multi-ciphertext XOR analysis
analyze.py	Selector extraction and storage dump
probe_templates.py	Function call probing for all selectors
decode_template_c.py	Payload extraction and transformation analysis
Detection Signatures
Template	Bytecode	Key Selectors	State Signal
A	2766–2786 B	0xb68d1809, 0xb249cd2d, 0x8da5cb5b, 0xf2fde38b	Emits event topic 0x868f5f91... on rotation
B	1856 B	0x3bc5de30, 0x47064d6a	Getter returns 0 bytes = unwritten; > 0 = payload present
C	1441 B	0x3bc5de30, 0x73d4a13a, 0x8da5cb5b, 0xf2fde38b	Getter returns exactly 60 bytes
The setter selector for Template B is 0x47064d6a = setData(string). Any transaction from an operator wallet calling this selector on a Template B contract is a high-confidence operator action.

Limitations
The C2 payloads are encrypted with a per-write key. Multi-ciphertext cryptanalysis ruled out repeating-key XOR, but decryption is not possible from on-chain data alone.

Historical state reads require an archive node. Transaction calldata analysis (via fetch_setter_calldata.py) is the free-tier workaround.

The tool identifies structural infrastructure, not the specific C2 domains currently in use.

References
GuidePoint Security — EtherHiding Exposed

DeFi Planet — Why EtherHiding May Be Dangerous

License
MIT — use freely for defensive security research.

Contributing
If you observe activation of any previously-empty Template B contract, or if you successfully decrypt a payload, please open an issue with the contract address, block number, and any recovered plaintext.
