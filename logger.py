"""
Secure Logging System - Logger Module

This module appends hash-chained log entries to log.txt.
Each new entry includes:
- timestamp
- level
- event
- previous hash
- current hash

Hash rule:
current_hash = SHA256(timestamp + "|" + level + "|" + event + "|" + previous_hash)
"""

from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path


LOG_FILE = Path("log.txt")
GENESIS_PREV_HASH = "0" * 64
ALLOWED_LEVELS = {"INFO", "WARNING", "SECURITY"}


def compute_hash(timestamp: str, level: str, event: str, previous_hash: str) -> str:
    """Compute SHA-256 for one log entry."""
    payload = f"{timestamp}|{level}|{event}|{previous_hash}"
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def get_last_hash(log_path: Path = LOG_FILE) -> str:
    """
    Return current_hash from the last log line.
    If file does not exist or is empty, return genesis hash.
    """
    if not log_path.exists() or log_path.stat().st_size == 0:
        return GENESIS_PREV_HASH

    with log_path.open("r", encoding="utf-8") as file:
        lines = [line.strip() for line in file if line.strip()]

    if not lines:
        return GENESIS_PREV_HASH

    try:
        last_entry = json.loads(lines[-1])
        return last_entry["current_hash"]
    except (json.JSONDecodeError, KeyError):
        # If existing file is malformed, avoid silently continuing chain.
        raise ValueError("Existing log file is malformed. Please verify log integrity first.")


def append_log(event: str, level: str = "INFO", log_path: Path = LOG_FILE) -> dict:
    """Append one secure log entry and return it."""
    clean_event = event.strip()
    clean_level = level.strip().upper()

    if not clean_event:
        raise ValueError("Event description cannot be empty.")
    if clean_level not in ALLOWED_LEVELS:
        raise ValueError(f"Invalid level: {clean_level}. Use one of {sorted(ALLOWED_LEVELS)}.")

    timestamp = datetime.now(timezone.utc).isoformat()
    previous_hash = get_last_hash(log_path)
    current_hash = compute_hash(timestamp, clean_level, clean_event, previous_hash)

    entry = {
        "timestamp": timestamp,
        "level": clean_level,
        "event": clean_event,
        "previous_hash": previous_hash,
        "current_hash": current_hash,
    }

    with log_path.open("a", encoding="utf-8") as file:
        file.write(json.dumps(entry, separators=(",", ":")) + "\n")

    return entry


def export_logs(source: Path = LOG_FILE, export_path: Path = Path("log_export.txt")) -> Path:
    """
    Optional bonus utility:
    Copy current logs to another file for sharing/archive.
    """
    if not source.exists():
        raise FileNotFoundError("No log file found to export.")
    export_path.write_text(source.read_text(encoding="utf-8"), encoding="utf-8")
    return export_path


def interactive_menu() -> None:
    """Simple CLI menu for educational demo."""
    print("\n=== Secure Logger ===")
    print("1) Add predefined event")
    print("2) Add custom event")
    print("3) Export log file")
    print("4) Exit")

    choice = input("Choose option (1-4): ").strip()

    if choice == "1":
        predefined = [
            ("INFO", "User login success"),
            ("WARNING", "Multiple failed login attempts"),
            ("SECURITY", "Unauthorized access to admin panel"),
        ]
        print("\nPredefined events:")
        for i, (lvl, msg) in enumerate(predefined, start=1):
            print(f"{i}) [{lvl}] {msg}")
        idx = input("Select event (1-3): ").strip()
        if idx not in {"1", "2", "3"}:
            print("Invalid selection.")
            return
        level, event = predefined[int(idx) - 1]
        entry = append_log(event=event, level=level)
        print("Log appended successfully.")
        print(f"Current hash: {entry['current_hash']}")

    elif choice == "2":
        level = input("Enter level (INFO/WARNING/SECURITY): ").strip().upper()
        event = input("Enter event description: ").strip()
        entry = append_log(event=event, level=level)
        print("Log appended successfully.")
        print(f"Current hash: {entry['current_hash']}")

    elif choice == "3":
        destination = input("Enter export filename (default: log_export.txt): ").strip()
        path = Path(destination) if destination else Path("log_export.txt")
        exported_to = export_logs(export_path=path)
        print(f"Logs exported to: {exported_to}")

    elif choice == "4":
        print("Exiting.")
        raise SystemExit(0)

    else:
        print("Invalid option.")


if __name__ == "__main__":
    while True:
        try:
            interactive_menu()
        except Exception as exc:  # broad for demo simplicity
            print(f"Error: {exc}")
