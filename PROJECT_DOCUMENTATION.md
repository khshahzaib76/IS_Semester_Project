# Secure Logging System with Tamper Detection

## 1) Project Overview

This project is an Information Security mini-system that demonstrates **log integrity protection** using **SHA-256 hash chaining**.

The idea is simple:
- Every log entry stores the hash of the previous entry.
- Any change to old data breaks the chain.
- A verifier recalculates all hashes and detects tampering.

This simulates core ideas behind tamper-evident systems and blockchain-style integrity chaining in an educational way.

---

## 2) Security Objective

The goal is to detect unauthorized changes in logs, including:
- **Modification** of an existing log entry
- **Deletion** of a log entry
- **Insertion** of a fake log entry

If logs are untouched, verifier should print:
- `Log integrity verified.`

If logs are tampered, verifier should print:
- `Tampering detected at entry X: ...`

---

## 3) Project Files

The project includes:

- `logger.py`  
  Creates hash-chained logs in `log.txt`.

- `verifier.py`  
  Verifies full log chain and detects tampering.

- `demo_attack.py`  
  Automatically creates tampered copies and runs verification.

- `log.txt`  
  Main secure log file (JSON Lines format).

- `log_attack_modified.txt`  
  Tampered copy where event text is modified.

- `log_attack_deleted.txt`  
  Tampered copy where one line is deleted.

- `log_attack_inserted.txt`  
  Tampered copy where a fake line is inserted.

- `PROJECT_DOCUMENTATION.md`  
  This full explanation file.

---

## 4) Core Security Design

### 4.1 Hash Chaining Formula

For each log entry:

`current_hash = SHA256(timestamp + "|" + level + "|" + event + "|" + previous_hash)`

Where:
- `timestamp` = event time in UTC ISO format
- `level` = INFO / WARNING / SECURITY
- `event` = event message
- `previous_hash` = `current_hash` from previous entry

### 4.2 Genesis Entry Rule

For the very first entry, no previous entry exists.  
So the system uses:

- `previous_hash = "0000000000000000000000000000000000000000000000000000000000000000"` (64 zeros)

This is called the **genesis previous hash**.

### 4.3 Why This Detects Tampering

- If attacker edits one entry, that entry's stored hash no longer matches recalculated hash.
- If attacker deletes an entry, next entry points to missing hash chain value.
- If attacker inserts a fake entry, chain link mismatch appears.

So tampering becomes evident during verification.

---

## 5) Log Format (JSON Lines)

Each line in `log.txt` is one JSON object.

Example:

```json
{"timestamp":"2026-04-21T17:48:59.216669+00:00","level":"INFO","event":"System boot","previous_hash":"0000000000000000000000000000000000000000000000000000000000000000","current_hash":"ad9bcbfec3a20f56e4f44d0f50c6e3772af51745ea83acd73e9d7efb78935e3a"}
```

Field meaning:
- `timestamp`: when event was logged
- `level`: severity/category
- `event`: event description
- `previous_hash`: hash of previous log entry
- `current_hash`: hash of this entry's content plus `previous_hash`

---

## 6) Detailed Module Explanation

## 6.1 `logger.py`

Responsibilities:
- Create and append secure log entries
- Keep chain continuity
- Offer interactive CLI for easy testing
- Support export (bonus requirement)

Main parts:

1. **`compute_hash(...)`**  
   Uses `hashlib.sha256()` and returns 64-char hex digest.

2. **`get_last_hash(...)`**  
   Reads last log line and returns its `current_hash`, or genesis hash if file is empty/new.

3. **`append_log(event, level)`**  
   - Validates input
   - Creates UTC timestamp
   - Gets previous hash
   - Computes current hash
   - Appends JSON object to `log.txt`

4. **`export_logs(...)`** (Bonus)  
   Copies log file to another filename for reporting/sharing.

5. **`interactive_menu()`**  
   Menu options:
   - Add predefined event
   - Add custom event
   - Export logs
   - Exit

## 6.2 `verifier.py`

Responsibilities:
- Recompute chain from first line to last
- Validate each entry step-by-step
- Stop and report where tampering begins

Main verification logic:

For each entry:
1. Parse JSON entry
2. Check `stored_previous_hash == expected_previous_hash`
3. Recompute hash from fields
4. Compare recomputed hash with `stored_current_hash`
5. Move to next entry by setting `expected_previous_hash = stored_current_hash`

Detection outcomes:
- Malformed JSON -> tampering/malformed entry
- Previous hash mismatch -> likely deletion/insertion
- Current hash mismatch -> likely modified entry

Includes:
- `print_tamper_simulation_instructions()` for manual attack testing.

## 6.3 `demo_attack.py`

Responsibilities:
- Simulate attacks safely on copied files
- Demonstrate that verifier catches all attacks

Scenarios:
1. **Modified entry**  
   Changes event text but keeps old hash => current hash mismatch.

2. **Deleted entry**  
   Removes one line => broken chain at next entry.

3. **Inserted fake entry**  
   Adds fabricated JSON with fake hashes => previous hash mismatch.

Safety:
- Original `log.txt` is not modified.

---

## 7) How to Run (Step-by-Step)

Open terminal in project folder:

`F:\IS_Project`

### Step 1: Add log entries

```bash
python logger.py
```

Use menu to add predefined/custom events.

### Step 2: Verify integrity

```bash
python verifier.py
```

Expected (when untampered):
- `Log integrity verified.`

### Step 3: Manual tampering test

1. Open `log.txt`
2. Modify or delete one line (or insert fake line)
3. Save
4. Run:

```bash
python verifier.py
```

Expected:
- `Tampering detected at entry X ...`

### Step 4: Automated attack demonstration

```bash
python demo_attack.py
```

Expected:
- Detect tampering for all 3 generated attack files.

---

## 8) Example Console Output

Normal verification:

```text
=== Secure Log Verifier ===
Log integrity verified.
```

Tampered verification example:

```text
Tampering detected at entry 2: previous hash mismatch (possible deletion/insertion).
```

Demo attack script sample:

```text
[Scenario] modified entry
Tampering detected at entry 1: current hash mismatch (entry may be modified).
```

---


## 9) Quick Commands Reference

```bash
# Add logs interactively
python logger.py

# Verify original log integrity
python verifier.py

# Run automated tamper demo
python demo_attack.py
```

---

## 10) Conclusion

This project is a clean educational implementation of a secure logging concept:
- append-only style entries
- SHA-256 hash chaining
- tamper detection through verification