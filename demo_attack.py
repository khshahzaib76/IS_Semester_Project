"""
Demo Attack Script for Secure Logging System

Creates tampered copies of log.txt and runs integrity verification on each:
1) modified entry
2) deleted entry
3) inserted fake entry

This keeps the original log.txt untouched.
"""

from __future__ import annotations

import json
from pathlib import Path

from verifier import verify_log


SOURCE_LOG = Path("log.txt")


def load_lines(path: Path) -> list[str]:
    if not path.exists():
        raise FileNotFoundError(f"Missing source log file: {path}")
    return [line.strip() for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]


def write_lines(path: Path, lines: list[str]) -> None:
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def attack_modify(lines: list[str]) -> list[str]:
    tampered = lines.copy()
    if not tampered:
        return tampered
    entry = json.loads(tampered[0])
    entry["event"] = "[TAMPERED] Event text changed by attacker"
    # Intentionally keep current_hash unchanged to trigger verification failure.
    tampered[0] = json.dumps(entry, separators=(",", ":"))
    return tampered


def attack_delete(lines: list[str]) -> list[str]:
    tampered = lines.copy()
    if len(tampered) >= 2:
        del tampered[1]
    elif tampered:
        del tampered[0]
    return tampered


def attack_insert(lines: list[str]) -> list[str]:
    tampered = lines.copy()
    fake_entry = {
        "timestamp": "2026-01-01T00:00:00+00:00",
        "level": "SECURITY",
        "event": "[FAKE] Attacker inserted this line",
        "previous_hash": "f" * 64,
        "current_hash": "e" * 64,
    }
    tampered.insert(1 if len(tampered) >= 1 else 0, json.dumps(fake_entry, separators=(",", ":")))
    return tampered


def run_demo() -> None:
    print("=== Demo Attack Runner ===")
    lines = load_lines(SOURCE_LOG)
    if not lines:
        print("log.txt is empty. Add logs first using logger.py")
        return

    scenarios = [
        ("modified entry", "log_attack_modified.txt", attack_modify),
        ("deleted entry", "log_attack_deleted.txt", attack_delete),
        ("inserted fake entry", "log_attack_inserted.txt", attack_insert),
    ]

    for title, filename, attack_func in scenarios:
        print(f"\n[Scenario] {title}")
        attack_path = Path(filename)
        attacked_lines = attack_func(lines)
        write_lines(attack_path, attacked_lines)
        print(f"Created tampered file: {attack_path}")
        print("Verifier result:")
        verify_log(attack_path)

    print("\nDone. Original log.txt was not modified.")


if __name__ == "__main__":
    run_demo()
