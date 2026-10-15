# EtherHiding Contract Tracker

**Detect and track blockchain-based malware C2 infrastructure.**

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](https://opensource.org/licenses/MIT)
[![Python 3.10+](https://img.shields.io/badge/python-3.10+-blue.svg)](https://www.python.org/downloads/)
[![Chain: Polygon](https://img.shields.io/badge/chain-polygon-8247e5)](https://polygon.technology/)
[![Free Tier](https://img.shields.io/badge/Alchemy-free%20tier-00cc83)](https://www.alchemy.com/)

EtherHiding is a technique where malware retrieves its C2 address by reading a smart contract on a public blockchain - no hardcoded domain, no takedown surface. This tool fingerprints those contracts, reconstructs the operator deployment history, decrypts stored payloads, and tracks state changes.

> **Case study in production:** Used to map a live cocova.co operator on Polygon - 4 contracts, 7 months of history, and a recovered XOR key. [Read the case](./CASE_cocova.md).

---

## Quick Start

    git clone https://github.com/luffytaro98uk-png/etherhiding-tracker.git
    cd etherhiding-tracker
    python -m venv .venv
    pip install -r requirements.txt
    cp .env.example .env
    python cli.py report

If that prints an intelligence summary of 15 known contracts, you are set.

---

## What It Does

| Capability | Command | Output |
|---|---|---|
| Fingerprint a contract | `cli.py fingerprint <address>` | Template match, owner, payload size |
| Pivot from a wallet | `cli.py wallet <address>` | Every contract that wallet deployed |
| Scan for rotations | `cli.py scan --blocks 1000` | C2 rotation events |
| Watch for state change | `cli.py monitor` | Alerts on dormant-to-active transitions |
| Dump storage | `analyze.py <address>` | Selectors + storage slots |
| Decrypt XOR storage | `decrypt.py` | Plaintext hostnames |

---

## Findings

Two investigations are documented in this repo. Both are reproducible from public data.

### 1. GuidePoint Replication (2026-10)

Reproduced GuidePoint Security's EtherHiding enumeration using an indexer-free wallet-pivot technique.

- **15 contracts** across 3 template generations reconstructed from public data
- **Setter `0x47064d6a` (`setData(string)`)** confirmed via calldata decode
- **Full write history** recovered without an archive node
- **Multi-ciphertext cryptanalysis** rules out repeating-key XOR

See [REPORT.md](./REPORT.md) for the full report.

### 2. cocova.co Operator (2026-10-15)

Mapped a live EtherHiding operator's complete infrastructure.

- **4 contracts**, 278 transactions, 7 months of history
- **XOR key recovered:** `341d91b1693dbbd10877bed632fbd228`
- **New domain discovered:** `year[.]calvinpreschooloffice[.]com`
- **Technical link to GuidePoint campaign** via shared selectors

See [CASE_cocova.md](./CASE_cocova.md) and [CASE_REPORT_2026-10-15.md](./CASE_REPORT_2026-10-15.md).

---

## Requirements

- **Python** 3.10 or newer
- **Alchemy** account (free tier - no paid APIs required)
- **Chain:** Polygon Mainnet (chain ID 137)

---

## Installation

### 1. Clone the repository

    git clone https://github.com/luffytaro98uk-png/etherhiding-tracker.git
    cd etherhiding-tracker

### 2. Create a virtual environment

Windows PowerShell:

    python -m venv .venv
    .\.venv\Scripts\Activate.ps1

macOS / Linux:

    python -m venv .venv
    source .venv/bin/activate

### 3. Install dependencies

    pip install -r requirements.txt

### 4. Get an Alchemy RPC URL

Sign up at dashboard.alchemy.com, create a Polygon Mainnet app, copy the HTTPS URL.

### 5. Configure

    cp .env.example .env

Edit `.env`:

    ALCHEMY_RPC_URL=https://polygon-mainnet.g.alchemy.com/v2/YOUR_KEY_HERE

Make sure Polygon Mainnet is enabled on your Alchemy app dashboard.

### 6. Verify

    python cli.py fingerprint 0xde2d34339c279a7a79bc4fc1c4f37d3c055211b7

Expected output:

    Contract: 0xde2d34339C279A7a79bc4fC1C4F37d3C055211b7
      Bytecode:      2783 bytes
      C2 getter:     True
      Ownable:       True
      Owner:         0xd802C9427ce416B9DAb2db5aDD76EfAA6d9d826a
      Verdict:       *** CONFIRMED ETHERHIDING (Template A) ***

---

## Usage

### Unified CLI

    python cli.py fingerprint <address>
    python cli.py wallet <address>
    python cli.py scan --blocks 1000
    python cli.py templates
    python cli.py monitor
    python cli.py report

### Standalone Tools

| Script | Purpose |
|---|---|
| `cli.py` | Unified command interface |
| `tracker.py` | Event scan + fingerprint of known contracts |
| `fingerprint.py` | Four-signal contract classification |
| `derive_contracts.py` | Deterministic contract discovery from wallet nonces |
| `monitor.py` | State-change watcher |
| `fetch_setter_calldata.py` | Extract payloads from transaction calldata |
| `write_history.py` | Full transaction history + calldata decode |
| `decrypt.py` | XOR decryption of encrypted storage |
| `cryptanalysis.py` | Multi-ciphertext XOR analysis |
| `analyze.py` | Selector extraction and storage dump |
| `probe_templates.py` | Function call probing |
| `decode_template_c.py` | Payload extraction |

---

## Detection Signatures

Known EtherHiding templates observed in the wild:

| Template | Bytecode | Key Selectors | State Signal |
|---|---|---|---|
| A | 2766-2786 B | `0xb68d1809`, `0xb249cd2d`, `0x8da5cb5b`, `0xf2fde38b` | Emits event `0x868f5f91...` on rotation |
| B | 1856 B | `0x3bc5de30`, `0x47064d6a` | Getter returns 0 bytes when unwritten |
| C | 1441 B | `0x3bc5de30`, `0x73d4a13a`, `0x8da5cb5b`, `0xf2fde38b` | Getter returns exactly 60 bytes |

**High-priority signal:** a Template B contract whose `0x3bc5de30` response changes from 0 bytes to non-zero indicates a live C2 rotation.

---

## Watchlist

The watchlist.json file is the shared list of tracked contracts and operator wallets. Contribute new entries via pull request.

    {
      "contracts": [
        {
          "address": "0x4af8048EdfE4523953E9907528BF5Cef7Fa8db09",
          "chain": "polygon",
          "label": "cocova case - XOR-encrypted C2 storage",
          "getter": "0x7d0c8f7a",
          "cipher": { "type": "repeating_xor", "period": 16 }
        }
      ]
    }

---

## Limitations

| Limitation | Impact |
|---|---|
| Encrypted payloads | Decryption requires the malware sample or a known-plaintext pair |
| No archive node | Historical state requires calldata analysis (see `write_history.py`) |
| Structural detection only | The tool identifies infrastructure, not specific C2 domains |

---

## References

- [GuidePoint Security - EtherHiding Exposed](https://www.guidepointsecurity.com/blog/etherhiding-exposed-deep-dive/)
- [DeFi Planet - Why EtherHiding May Be Dangerous](https://defi-planet.com/2026/04/why-etherhiding-may-be-one-of-the-most-dangerous-crypto-attacks-youve-ever-heard-of/)

---

## License

MIT - use freely for defensive security research.

---

## Contributing

If you observe activation of a previously-empty contract, decrypt a payload, or discover a new template, please open an issue or PR:

- **Issue:** contract address, block number, observed change
- **PR to watchlist.json:** new entry with label and role

---

**Built for defenders. Free tier only. No paid APIs required.**
