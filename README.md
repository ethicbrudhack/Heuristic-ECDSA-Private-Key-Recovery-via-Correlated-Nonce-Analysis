# 🔐 Heuristic ECDSA Private Key Recovery via Correlated Nonce Analysis

This research-oriented Python script demonstrates a **heuristic approach** to recovering an ECDSA private key `d` under the assumption of a **correlation between the nonce `k` and the signature parameters (`r`, `z`)**.

It is a safe, self-contained prototype for **academic and cryptographic analysis** — designed to test whether patterns in `(r, z)` can be exploited to approximate or partially reconstruct `k`, and consequently deduce `d`.

---

## 🧩 Concept Overview

In ECDSA, each signature `(r, s)` is computed from:
s = (z + r*d) * k⁻¹ mod n

If the nonce `k` is *not fully random* — for instance, if `k` correlates with `r` or `z` — then an attacker may be able to estimate `k` as a function of observable data.

This script assumes such a correlation and defines a **weighted linear estimator**:



k ≈ ((1 - weight) * r + weight * z) mod n


It then explores small integer offsets (Δk) around this base estimate to identify candidate private keys that yield consistent results across multiple signatures.

---

## ⚙️ Algorithm Summary

1. **For each signature**:
   - Compute a base nonce estimate `k_base` from `r` and `z`.
   - Search around that base (`Δk ∈ [-50, +50]`).
   - For each candidate `k`, compute:
     ```
     d_candidate = (s * k - z) * r⁻¹ mod n
     ```
   - Collect valid `d_candidate` values.

2. **Across all signatures**:
   - Identify candidate `d` values that occur in at least `threshold` signatures (by default: half the dataset).
   - Report any consistent private-key candidates.

---

## 🧠 Key Functions

| Function | Description |
|-----------|-------------|
| `compute_k_from_rz(r, z, weight)` | Heuristic nonce estimator based on a linear combination of `r` and `z`. |
| `recover_d_from_signature(sig)` | Searches a neighborhood around `k_base` for valid `d` candidates. |
| `common_candidate(candidates_list, threshold)` | Finds private-key candidates consistent across multiple signatures. |
| `recover_private_key(signatures)` | Main orchestrator combining all steps. |
| `main()` | Entry point: loads data, executes recovery, prints any recovered `d` values. |

---

## 🧪 Example Output

Running the script (`python3 recover_d_heuristic.py`) yields log output like:



2025-11-09 14:32:00 - INFO - Starting private key recovery...
2025-11-09 14:32:01 - INFO - For txid 9e3b66... found 101 candidates.
2025-11-09 14:32:01 - INFO - For txid e41214... found 102 candidates.
2025-11-09 14:32:02 - INFO - Common d candidates found in ≥12 signatures: [337ab41eaa0c...]
2025-11-09 14:32:02 - INFO - ✅ Recovered private key d: 0x337ab41eaa0c4d7b9d1...


If no consistent candidate is found:


2025-11-09 14:35:15 - WARNING - No common d candidates meeting threshold.


---

## 🧰 Adjustable Parameters

| Parameter | Description | Default |
|------------|-------------|----------|
| `delta_range` | Range of Δk values to test around estimated nonce | `[-50, +50]` |
| `weight` | Weight used in k estimation formula | `0.3653` |
| `threshold` | Minimum number of signatures a `d` must appear in | `len(signatures) // 2` |

You can modify these constants directly in the script or expose them as command-line parameters for batch runs.

---

## ⚗️ Mathematical Insight

The recovery works because:


d = (s*k - z) * r⁻¹ mod n

If multiple signatures were signed with nonces that can be approximated from `r` and `z` in a predictable way, then the true `d` should appear consistently as the same modular solution across independent signatures.

This script tests that hypothesis empirically — it **does not brute-force `k`**, only samples near the heuristic estimate.

---

## ⚠️ Ethical & Legal Notice

This tool is for **research, education, and authorized security auditing only**.  
Do **not** attempt to recover or analyze private keys belonging to others — that is illegal and unethical.

Run this only on:
- test networks (regtest, testnet, signet)
- controlled lab environments
- or data you own or have explicit permission to test

---

## 🧾 Requirements

Install dependencies:
```bash
pip install numpy sympy

🧩 Potential Extensions

Add adaptive weighting (optimize weight based on observed (r, z) variance).

Integrate machine-learning regression for nonce estimation.

Visualize distribution of recovered d candidates.

Export recovered candidate space as JSON for further post-analysis.

📜 License

MIT License
© 2025 — Author: [ethicbrudhack]
BTC donation address: bc1q4nyq7kr4nwq6zw35pg0zl0k9jmdmtmadlfvqhr



🧠 TL;DR Summary

This script explores whether predictable relationships between ECDSA nonce k and public signature parameters (r, z) can leak information about the private key d.
It uses a hybrid analytical + heuristic approach, scanning small Δk offsets around an estimated k, and checks consistency across many signatures.
A useful sandbox for anyone studying nonce leakage and partial-correlation attacks in ECDSA.

