"""
Template B Activation Monitor.

Polls all known dormant Template B contracts for their C2 getter response.
Alerts on any transition from empty blob (dormant) to non-empty blob (activated).

Run continuously:
    python monitor.py

Run a single check:
    python monitor.py --once

Custom interval (seconds):
    python monitor.py --interval 300
"""
import os
import sys
import time
import json
import argparse
from datetime import datetime, timezone
from web3 import Web3
from dotenv import load_dotenv

load_dotenv()

# ==== CONFIGURATION ====

# All 11 Template B contracts from the investigation
TEMPLATE_B_CONTRACTS = [
    '0x75A91aCdB3dd25B39fe0619d2A00DE49A8e56eb9',
    '0x4c7C35db1f8E23301a447801B019968D8b4A6329',
    '0x700121c474A1eF6b4BAC074e0B805F262a5BD46e',
    '0xd245e35d988244528F10582107Ce1BC38DA35a24',
    '0x96C90CD4E58718cb20A58e14b7931eD94Ad040C7',
    '0x0dC9f5de745394D98C0cE163D498043EB325AC45',
    '0xFad3F51fF70223CadeecCf8FCf2D362533f360eE',
    '0xB685a24587658989410D68500448f45467CA47D8',
    '0xed4417B3992A4e6613f734E720e24DE5630695f8',
    '0xA5517ea1914EbfcEcDe8528e0973D98E60178607',
    '0x5C4576E21809FfA8d265bB7385f044A693356c43',
]

# Template B C2 getter selector
C2_GETTER = '3bc5de30'

# State file (remembers last observed state between runs)
STATE_FILE = 'monitor_state.json'
ALERT_LOG = 'monitor_alerts.log'

# Default polling interval (seconds)
DEFAULT_INTERVAL = 600  # 10 minutes

# ==== SETUP ====

RPC_URL = os.getenv('ALCHEMY_RPC_URL')
if not RPC_URL or RPC_URL.endswith('/v2/'):
    print("ERROR: ALCHEMY_RPC_URL is missing or incomplete in .env")
    sys.exit(1)

w3 = Web3(Web3.HTTPProvider(RPC_URL))
if not w3.is_connected():
    print("ERROR: Could not connect to Polygon RPC.")
    sys.exit(1)


# ==== STATE MANAGEMENT ====

def load_state():
    """Load last-observed blob lengths from disk."""
    if os.path.exists(STATE_FILE):
        try:
            with open(STATE_FILE, 'r') as f:
                return json.load(f)
        except Exception:
            return {}
    return {}


def save_state(state):
    """Write current state to disk."""
    with open(STATE_FILE, 'w') as f:
        json.dump(state, f, indent=2)


def log_alert(message):
    """Append a timestamped alert to the log and print it."""
    timestamp = datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')
    line = f"[{timestamp}] {message}"
    print(line)
    with open(ALERT_LOG, 'a') as f:
        f.write(line + '\n')


# ==== CORE LOGIC ====

def get_blob_length(contract_address):
    """
    Call the C2 getter and return the length of the returned ABI string.
    Returns:
        int: blob length in bytes (0 = empty/dormant)
        None: call failed
    """
    try:
        addr = Web3.to_checksum_address(contract_address)
        result = w3.eth.call({'to': addr, 'data': '0x' + C2_GETTER})

        if len(result) < 64:
            return None

        offset = int.from_bytes(result[0:32], 'big')
        if offset + 32 > len(result):
            return None

        length = int.from_bytes(result[offset:offset+32], 'big')
        return length

    except Exception:
        return None


def check_all_contracts(state):
    """Check every Template B contract and return updated state + alerts."""
    alerts = []
    new_state = dict(state)

    current_block = w3.eth.block_number

    for contract in TEMPLATE_B_CONTRACTS:
        addr = Web3.to_checksum_address(contract)
        prev = state.get(addr, {})
        prev_len = prev.get('blob_length', None)

        current_len = get_blob_length(addr)

        # Detect transitions
        if current_len is not None:
            if prev_len is None:
                # First observation
                status = 'DORMANT' if current_len == 0 else 'ACTIVE'
                print(f"  [INIT] {addr}  blob={current_len}  ({status})")
            elif prev_len == 0 and current_len > 0:
                # *** ACTIVATION ***
                msg = (
                    f"*** ACTIVATION DETECTED ***\n"
                    f"    Contract: {addr}\n"
                    f"    Previous blob length: {prev_len}\n"
                    f"    New blob length:      {current_len}\n"
                    f"    Block:                {current_block}\n"
                    f"    Time:                 {datetime.now(timezone.utc).isoformat()}\n"
                    f"    Action:               Contract has transitioned from dormant to active."
                )
                log_alert(msg)
                alerts.append({'contract': addr, 'prev': prev_len, 'new': current_len})
            elif prev_len > 0 and current_len == 0:
                # Contract was cleared (unusual)
                msg = f"[CLEARED] {addr} went from blob={prev_len} to 0"
                log_alert(msg)
            elif prev_len > 0 and current_len > 0 and prev_len != current_len:
                # Blob changed size - new payload
                msg = f"[CHANGED] {addr} blob size {prev_len} -> {current_len}"
                log_alert(msg)

            new_state[addr] = {
                'blob_length': current_len,
                'last_checked_block': current_block,
                'last_checked': datetime.now(timezone.utc).isoformat(),
            }
        else:
            # Call failed - leave previous state intact
            print(f"  [ERROR] {addr}  (call failed, retaining previous state)")

    return new_state, alerts


def print_summary(state):
    """Print a one-line summary of all contracts."""
    dormant = 0
    active = 0
    errors = 0

    for contract in TEMPLATE_B_CONTRACTS:
        addr = Web3.to_checksum_address(contract)
        entry = state.get(addr, {})
        length = entry.get('blob_length')

        if length is None:
            errors += 1
        elif length == 0:
            dormant += 1
        else:
            active += 1

    print()
    print(f"  Summary: {dormant} dormant, {active} active, {errors} errors")
    print(f"  Log file: {ALERT_LOG}")
    print()


# ==== MAIN ====

def main():
    parser = argparse.ArgumentParser(description='Template B activation monitor')
    parser.add_argument('--once', action='store_true',
                        help='Run a single check and exit')
    parser.add_argument('--interval', type=int, default=DEFAULT_INTERVAL,
                        help=f'Seconds between checks (default: {DEFAULT_INTERVAL})')
    args = parser.parse_args()

    print("=" * 70)
    print("Template B Activation Monitor")
    print("=" * 70)
    print(f"Monitoring {len(TEMPLATE_B_CONTRACTS)} contracts")
    print(f"Getter selector: 0x{C2_GETTER}")
    print(f"Interval: {args.interval}s")
    print(f"Connected block: {w3.eth.block_number}")
    print()

    state = load_state()

    while True:
        print(f"--- Check at {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')} ---")

        try:
            new_state, alerts = check_all_contracts(state)
            save_state(new_state)
            state = new_state
            print_summary(state)

            if alerts:
                print(f"!!! {len(alerts)} ALERT(S) FIRED !!!")
                print()

        except KeyboardInterrupt:
            print("\nInterrupted by user.")
            break
        except Exception as e:
            print(f"[ERROR] Monitor loop: {e}")

        if args.once:
            print("--once specified, exiting.")
            break

        print(f"Sleeping {args.interval} seconds...")
        time.sleep(args.interval)


if __name__ == "__main__":
    main()