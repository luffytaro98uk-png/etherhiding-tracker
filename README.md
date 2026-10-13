# EtherHiding Contract Tracker

A defensive tool for detecting and tracking EtherHiding malware infrastructure on the Polygon blockchain.

EtherHiding is a technique where malware resolves its command-and-control (C2) address by reading a smart contract on a public blockchain instead of a hardcoded domain. This tool fingerprints such contracts, reconstructs the operator's full deployment history, and alerts on activation of dormant reserve slots.

## What It Does

- Event scanning - detects C2 rotations by scanning for the operator's specific event topic
- Contract fingerprinting - classifies any address against four independent on-chain signals
- Wallet pivot - deterministically derives every contract a wallet has ever deployed, using only its nonce
- Dormancy detection - identifies reserve contracts that have been deployed but not yet activated

## Requirements

- Python 3.10 or newer
- A free Alchemy account with a Polygon Mainnet app enabled
- No paid APIs required

## Installation

    git clone <your-repo-url>
    cd etherhiding-tracker

    python -m venv .venv
    # Windows:
    .\.venv\Scripts\Activate.ps1
    # macOS/Linux:
    source .venv/bin/activate

    pip install -r requirements.txt

## Configuration

Copy .env.example to .env and fill in your Alchemy RPC URL:

    cp .env.example .env

Edit .env:

    ALCHEMY_RPC_URL=https://polygon-mainnet.g.alchemy.com/v2/YOUR_KEY_HERE

Make sure your Alchemy app has Polygon Mainnet enabled in the dashboard.

## Usage

### Fingerprint a single contract

    python fingerprint.py 0xde2d34339c279a7a79bc4fc1c4f37d3c055211b7

### Discover all contracts deployed by a wallet

    python derive_contracts.py 0xd802C9427ce416B9DAb2db5aDD76EfAA6d9d826a

### Scan recent blocks for C2 rotation events

    python tracker.py

### Full analysis of known contracts

    python analyze_template_b.py
    python probe_templates.py
    python decode_template_c.py

## Detection Signatures

| Template | Bytecode | Key Selectors | Status Signal |
|---|---|---|---|
| A | 2766-2786 B | 0xb68d1809, 0x8da5cb5b, 0xf2fde38b | Emits events on rotation |
| B | 1856 B | 0x3bc5de30, 0x47064d6a | Empty blob = dormant, non-empty = activated |
| C | 1441 B | 0x3bc5de30, 0x73d4a13a, 0x8da5cb5b | 60-byte live ciphertext |

A Template B contract transitioning from empty to non-empty is the strongest actionable alert this tool produces.

## Known Operator Wallets

- 0xd802C9427ce416B9DAb2db5aDD76EfAA6d9d826a
- 0x6a6e177dcf992ac16f7367c14b26a3cf4775dfde

## Limitations

- Encrypted C2 payloads cannot be decrypted without the malware sample
- Historical block queries require an archive node
- Tool identifies structural infrastructure, not specific C2 domains

## License

MIT - use freely for defensive security research.
