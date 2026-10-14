# EtherHiding Contract Tracker

A defensive tool for detecting and tracking EtherHiding malware infrastructure on the Polygon blockchain.

## What It Does

- Event scanning - detects C2 rotations via the operator's event topic
- Contract fingerprinting - classifies any address against four on-chain signals
- Wallet pivot - derives every contract a wallet has deployed from its nonce
- Calldata extraction - recovers historical payloads from setData calldata
- State monitor - watches the 11 Template B contracts for changes

## Findings

- 15 contracts across 3 templates reconstructed from public data
- Setter selector 0x47064d6a (setData) confirmed via calldata
- Write history recovered: 0x5C4576E2 was written 3 times over 77 days
- Multi-ciphertext cryptanalysis rules out repeating-key XOR
- The "reserve slot" hypothesis is refuted

See REPORT.md for full details.

## Requirements

- Python 3.10 or newer
- A free Alchemy account with a Polygon Mainnet app enabled

## Installation

    git clone https://github.com/luffytaro98uk-png/etherhiding-tracker.git
    cd etherhiding-tracker
    python -m venv .venv
    pip install -r requirements.txt

## Configuration

Copy .env.example to .env and add your Alchemy RPC URL.

## Usage

    python cli.py fingerprint <address>
    python cli.py wallet <address>
    python cli.py templates
    python cli.py monitor
    python cli.py report

## Tools

- cli.py - unified command interface
- tracker.py - event scan and fingerprint
- derive_contracts.py - wallet-to-contract pivot
- fetch_setter_calldata.py - extract payloads from transaction calldata
- cryptanalysis.py - multi-ciphertext XOR analysis
- monitor.py - Template B state watcher

## Known Operator Wallets

- 0xd802C9427ce416B9DAb2db5aDD76EfAA6d9d826a
- 0x6a6e177dcf992ac16f7367c14b26a3cf4775dfde

## License

MIT