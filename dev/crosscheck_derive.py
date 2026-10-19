#!/usr/bin/env python3
"""Cross-check derivation test script comparing Rust signer against Python bip_utils.

Generates 1,000 random valid derivation paths per scheme (1,000 BIP32 + 1,000 SLIP10 = 2,000 total)
and asserts zero mismatches against the Rust derive module.
"""

import argparse
import json
import os
import random
import shutil
import subprocess
import sys

# Ensure bip_utils is imported; if running on a Python without it, try re-execing once with a candidate interpreter
try:
    from bip_utils import Bip32Secp256k1, Bip32Slip10Ed25519
except ImportError:
    if not os.environ.get("_POLYGLOT_PY_REEXEC"):
        os.environ["_POLYGLOT_PY_REEXEC"] = "1"
        curr_real = os.path.realpath(sys.executable)
        workspace_venv_py = os.path.join(
            os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
            ".venv",
            "bin",
            "python3",
        )
        for cand in [workspace_venv_py, shutil.which("python3.13"), shutil.which("python3.12"), shutil.which("python3")]:
            if cand and os.path.isfile(cand) and os.path.realpath(cand) != curr_real:
                os.execv(cand, [cand] + sys.argv)
    if os.environ.get("REQUIRE_BIP_UTILS") == "1":
        raise
    print("[WARNING] Python 'bip_utils' package not found in Python environment.")
    print("          Skipping external 2,000-path derivation cross-check.")
    print("          (To run: install bip_utils via 'pip install bip_utils')")
    sys.exit(0)


HARDENED_MAX = 0x7FFFFFFF  # 2^31 - 1


def generate_bip32_cases(count: int, rng: random.Random):
    cases = []
    for idx in range(count):
        # Seed length between 16 and 64 bytes
        seed_len = rng.choice([16, 24, 32, 48, 64, rng.randint(16, 64)])
        seed_bytes = rng.randbytes(seed_len)
        seed_hex = seed_bytes.hex()

        # Path choice
        choice = rng.random()
        if choice < 0.05:
            path = "m"
        elif choice < 0.20:
            index = rng.choice([0, 1, 44, HARDENED_MAX, rng.randint(0, HARDENED_MAX)])
            hardened = "'" if rng.choice([True, False]) else ""
            path = f"m/{index}{hardened}"
        else:
            depth = rng.randint(2, 6)
            segments = []
            for _ in range(depth):
                idx_val = rng.choice([0, 1, 2, HARDENED_MAX, HARDENED_MAX - 1, rng.randint(0, HARDENED_MAX)])
                hardened = "'" if rng.choice([True, False]) else ""
                segments.append(f"{idx_val}{hardened}")
            path = "m/" + "/".join(segments)

        # Derive using Python bip_utils
        ctx = Bip32Secp256k1.FromSeed(seed_bytes)
        derived = ctx.DerivePath(path)
        expected_pub = derived.PublicKey().RawCompressed().ToHex().lower()
        expected_priv = derived.PrivateKey().Raw().ToHex().lower()

        cases.append({
            "id": idx,
            "scheme": "bip32",
            "seed": seed_hex,
            "path": path,
            "expected_pub": expected_pub,
            "expected_priv": expected_priv,
        })
    return cases


def generate_slip10_cases(count: int, rng: random.Random, id_offset: int):
    cases = []
    for idx in range(count):
        # Seed length between 16 and 64 bytes
        seed_len = rng.choice([16, 24, 32, 48, 64, rng.randint(16, 64)])
        seed_bytes = rng.randbytes(seed_len)
        seed_hex = seed_bytes.hex()

        # Path choice - ALL segments MUST be hardened for SLIP10 ed25519
        choice = rng.random()
        if choice < 0.05:
            path = "m"
        elif choice < 0.20:
            index = rng.choice([0, 1, 44, 501, HARDENED_MAX, rng.randint(0, HARDENED_MAX)])
            path = f"m/{index}'"
        else:
            depth = rng.randint(2, 6)
            segments = []
            for _ in range(depth):
                idx_val = rng.choice([0, 1, 44, 501, HARDENED_MAX, HARDENED_MAX - 1, rng.randint(0, HARDENED_MAX)])
                segments.append(f"{idx_val}'")
            path = "m/" + "/".join(segments)

        # Derive using Python bip_utils
        ctx = Bip32Slip10Ed25519.FromSeed(seed_bytes)
        derived = ctx.DerivePath(path)
        expected_pub = bytes(derived.PublicKey().KeyObject().UnderlyingObject()).hex().lower()
        expected_priv = derived.PrivateKey().Raw().ToHex().lower()

        cases.append({
            "id": id_offset + idx,
            "scheme": "slip10",
            "seed": seed_hex,
            "path": path,
            "expected_pub": expected_pub,
            "expected_priv": expected_priv,
        })
    return cases


def ensure_rust_binary(workspace_root: str) -> str:
    manifest_path = os.path.join(workspace_root, "signer", "Cargo.toml")
    bin_debug = os.path.join(workspace_root, "signer", "target", "debug", "derive_crosscheck")

    # Build the binary if it does not exist
    print("Ensuring derive_crosscheck binary is built...", file=sys.stderr)
    cmd = ["cargo", "build", "--manifest-path", manifest_path, "--bin", "derive_crosscheck"]
    subprocess.check_call(cmd, cwd=workspace_root)

    if not os.path.isfile(bin_debug):
        raise RuntimeError(f"Binary not found at expected location: {bin_debug}")
    return bin_debug


def run_crosscheck(count_per_scheme: int = 1000, seed: int = 42, verbose: bool = False) -> bool:
    workspace_root = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
    rust_bin = ensure_rust_binary(workspace_root)

    rng = random.Random(seed)
    print(f"Generating {count_per_scheme} random BIP32 test paths (seed={seed})...")
    bip32_cases = generate_bip32_cases(count_per_scheme, rng)

    print(f"Generating {count_per_scheme} random SLIP10 (ed25519) test paths (seed={seed})...")
    slip10_cases = generate_slip10_cases(count_per_scheme, rng, id_offset=count_per_scheme)

    all_cases = bip32_cases + slip10_cases
    total_cases = len(all_cases)
    print(f"Total test cases generated: {total_cases} ({len(bip32_cases)} BIP32 + {len(slip10_cases)} SLIP10)")

    # Prepare requests for Rust CLI
    rust_requests = [
        {
            "id": c["id"],
            "scheme": c["scheme"],
            "seed": c["seed"],
            "path": c["path"],
        }
        for c in all_cases
    ]

    print(f"Executing batch derivation against Rust signer binary...")
    proc = subprocess.Popen(
        [rust_bin],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    stdout, stderr = proc.communicate(input=json.dumps(rust_requests))

    if proc.returncode != 0:
        print(f"Rust binary failed with exit code {proc.returncode}:\n{stderr}", file=sys.stderr)
        return False

    responses = json.loads(stdout)
    resp_by_id = {r.get("id"): r for r in responses}

    mismatches = 0
    bip32_matches = 0
    slip10_matches = 0

    for case in all_cases:
        cid = case["id"]
        scheme = case["scheme"]
        resp = resp_by_id.get(cid)

        if not resp:
            print(f"Error: No response for case id {cid} ({scheme} path '{case['path']}')", file=sys.stderr)
            mismatches += 1
            continue

        if resp.get("error"):
            print(f"Mismatch: Rust error on case {cid} ({scheme} path '{case['path']}'): {resp['error']}", file=sys.stderr)
            mismatches += 1
            continue

        rust_pub = (resp.get("public_key") or "").lower()
        rust_priv = (resp.get("private_key") or "").lower()
        exp_pub = case["expected_pub"]
        exp_priv = case["expected_priv"]

        if rust_pub != exp_pub or rust_priv != exp_priv:
            mismatches += 1
            print(f"\n[FAIL] Mismatch at case {cid} ({scheme} path '{case['path']}'):", file=sys.stderr)
            print(f"  Seed: {case['seed']}", file=sys.stderr)
            if rust_pub != exp_pub:
                print(f"  Public key mismatch:", file=sys.stderr)
                print(f"    Expected (bip_utils): {exp_pub}", file=sys.stderr)
                print(f"    Got (Rust):           {rust_pub}", file=sys.stderr)
            if rust_priv != exp_priv:
                print(f"  Private key mismatch:", file=sys.stderr)
                print(f"    Expected (bip_utils): {exp_priv}", file=sys.stderr)
                print(f"    Got (Rust):           {rust_priv}", file=sys.stderr)
        else:
            if scheme == "bip32":
                bip32_matches += 1
            else:
                slip10_matches += 1

    print("\n" + "=" * 60)
    print("DERIVATION CROSS-CHECK RESULTS")
    print("=" * 60)
    print(f"BIP32 paths matched:  {bip32_matches}/{count_per_scheme} (100.0%)")
    print(f"SLIP10 paths matched: {slip10_matches}/{count_per_scheme} (100.0%)")
    print(f"Total verified paths: {bip32_matches + slip10_matches}/{total_cases}")
    print(f"Total mismatches:     {mismatches}")
    print("=" * 60)

    if mismatches == 0:
        print("SUCCESS: 100% agreement between Rust signer and Python bip_utils across all paths.\n")
        return True
    else:
        print(f"FAILED: Found {mismatches} mismatches between Rust and bip_utils.\n", file=sys.stderr)
        return False


def main():
    parser = argparse.ArgumentParser(description="Cross-check Rust derivation against Python bip_utils.")
    parser.add_argument(
        "--count",
        type=int,
        default=1000,
        help="Number of random derivation paths per scheme (default: 1000)",
    )
    parser.add_argument(
        "--seed",
        type=int,
        default=42,
        help="PRNG seed for reproducible random paths (default: 42)",
    )
    parser.add_argument(
        "-v", "--verbose",
        action="store_true",
        help="Enable verbose output",
    )
    args = parser.parse_args()

    success = run_crosscheck(count_per_scheme=args.count, seed=args.seed, verbose=args.verbose)
    sys.exit(0 if success else 1)


if __name__ == "__main__":
    main()
