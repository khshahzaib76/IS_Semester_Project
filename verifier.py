"""
Secure Logging System - Verifier Module

This module validates the integrity of a hash-chained log file.
It detects:
- modified entries
- deleted entries (chain break)
- inserted/fake entries (hash mismatch)
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path


LOG_FILE = Path("log.txt")
GENESIS_PREV_HASH = "0" * 64


def compute_hash(timestamp: str, level: str, event: str, previous_hash: str) -> str:
    """Recompute SHA-256 for one entry."""
    payload = f"{timestamp}|{level}|{event}|{previous_hash}"
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def verify_log(log_path: Path = LOG_FILE) -> bool:
    """
    Verify full chain integrity.
    Returns True if valid, False if tampered or malformed.
    """
    if not log_path.exists():
        print("No log file found (log.txt).")
        return False

    with log_path.open("r", encoding="utf-8") as file:
        lines = [line.strip() for line in file if line.strip()]

    if not lines:
        # For this project, an empty log is treated as suspicious because
        # full deletion of entries should be flagged as tampering.
        print("Tampering detected: log file is empty (possible full deletion).")
        return False

    expected_previous_hash = GENESIS_PREV_HASH

    for index, line in enumerate(lines, start=1):
        try:
            entry = json.loads(line)
            timestamp = entry["timestamp"]
            level = entry["level"]
            event = entry["event"]
            stored_previous_hash = entry["previous_hash"]
            stored_current_hash = entry["current_hash"]
        except (json.JSONDecodeError, KeyError):
            print(f"Tampering detected at entry {index}: malformed entry.")
            return False

        if stored_previous_hash != expected_previous_hash:
            print(
                f"Tampering detected at entry {index}: previous hash mismatch "
                "(possible deletion/insertion)."
            )
            return False

        recalculated_hash = compute_hash(timestamp, level, event, stored_previous_hash)
        if recalculated_hash != stored_current_hash:
            print(
                f"Tampering detected at entry {index}: current hash mismatch "
                "(entry may be modified)."
            )
            return False

        expected_previous_hash = stored_current_hash

    print("Log integrity verified.")
    return True


if __name__ == "__main__":
    print("=== Secure Log Verifier ===")
    verify_log()
