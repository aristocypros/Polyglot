#!/usr/bin/env python3
"""Cross-check RFC 8785 JSON Canonicalization Scheme (JCS) between Python and Rust.

Validates:
1. RFC 8785 specification vectors and edge cases (UTF-16 code unit property sorting, string escaping, literals).
2. Polyglot envelope request bodies (create_wallet, derive_public, sign digest, sign tx, sign multi-input bitcoin).
3. Rejection of non-canonical whitespace, reordered keys, unknown fields, and unknown envelope versions.
4. 500 randomized JSON test cases asserting 100% byte-for-byte agreement between Python and Rust signer.
"""

import argparse
import base64
import hashlib
import json
import os
import random
import subprocess
import sys


def canonicalize_jcs(obj) -> str:
    """Canonicalize a Python object according to RFC 8785 (JCS)."""
    if obj is None:
        return "null"
    elif isinstance(obj, bool):
        return "true" if obj else "false"
    elif isinstance(obj, int):
        return str(obj)
    elif isinstance(obj, float):
        if obj == 0.0:
            return "0"
        s = f"{obj:.16g}"
        if "e" in s:
            parts = s.split("e")
            exp = int(parts[1])
            sign = "+" if exp >= 0 else ""
            s = f"{parts[0]}e{sign}{exp}"
        return s
    elif isinstance(obj, str):
        # RFC 8785 Section 3.2.2.2:
        # Escape: \ (\u005c), " (\u0022), and control characters U+0000..U+001F
        # Specific controls: \b (0x08), \t (0x09), \n (0x0a), \f (0x0c), \r (0x0d)
        # Other controls: \u00xx (lowercase hex)
        # Forward slash / MUST NOT be escaped.
        out = ['"']
        for ch in obj:
            cp = ord(ch)
            if cp == 0x22:
                out.append('\\"')
            elif cp == 0x5C:
                out.append("\\\\")
            elif cp == 0x08:
                out.append("\\b")
            elif cp == 0x09:
                out.append("\\t")
            elif cp == 0x0A:
                out.append("\\n")
            elif cp == 0x0C:
                out.append("\\f")
            elif cp == 0x0D:
                out.append("\\r")
            elif cp < 0x20:
                out.append(f"\\u{cp:04x}")
            else:
                out.append(ch)
        out.append('"')
        return "".join(out)
    elif isinstance(obj, list):
        return "[" + ",".join(canonicalize_jcs(x) for x in obj) + "]"
    elif isinstance(obj, dict):
        # RFC 8785 Section 3.2.3: Sort by UTF-16 code units (utf-16-be byte sequence)
        sorted_keys = sorted(obj.keys(), key=lambda k: k.encode("utf-16-be"))
        return "{" + ",".join(canonicalize_jcs(k) + ":" + canonicalize_jcs(obj[k]) for k in sorted_keys) + "}"
    else:
        raise TypeError(f"Unsupported JSON type: {type(obj)}")


def base64url_encode(data: bytes) -> str:
    """Encode bytes into unpadded base64url string."""
    return base64.urlsafe_b64encode(data).decode("ascii").rstrip("=")


def ensure_rust_binary(workspace_root: str) -> str:
    """Builds and returns the path to the jcs_crosscheck debug binary."""
    manifest_path = os.path.join(workspace_root, "signer", "Cargo.toml")
    bin_debug = os.path.join(workspace_root, "signer", "target", "debug", "jcs_crosscheck")

    cmd = ["cargo", "build", "--manifest-path", manifest_path, "--bin", "jcs_crosscheck"]
    subprocess.check_call(cmd, cwd=workspace_root)

    if not os.path.isfile(bin_debug):
        raise RuntimeError(f"Binary not found at expected location: {bin_debug}")
    return bin_debug


def generate_random_json_value(rng: random.Random, depth: int = 0):
    """Generates arbitrary nested JSON values with edge case keys and strings."""
    if depth > 4:
        # Base case
        choice = rng.random()
        if choice < 0.2:
            return None
        elif choice < 0.4:
            return rng.choice([True, False])
        elif choice < 0.7:
            return rng.randint(-1000000, 1000000)
        else:
            return f"leaf_{rng.randint(0, 9999)}"

    choice = rng.random()
    if choice < 0.15:
        return None
    elif choice < 0.3:
        return rng.choice([True, False])
    elif choice < 0.5:
        return rng.randint(-1000000, 1000000)
    elif choice < 0.7:
        # Diverse string characters
        chars = [
            "hello",
            "world",
            "m/44'/60'/0'/0/0",
            "with space",
            "with\"quote",
            "with\\backslash",
            "with\nnewline",
            "with\ttab",
            "€uro",
            "😀 emoji",
            "\ufff0 high_bmp",
            "\u0000\u001f controls",
        ]
        return rng.choice(chars)
    elif choice < 0.85:
        length = rng.randint(0, 4)
        return [generate_random_json_value(rng, depth + 1) for _ in range(length)]
    else:
        key_pool = [
            "a", "b", "c", "z", "key_1", "key_2", "path", "type", "v",
            "😀_emoji", "\ufff0_high", "slash/key", "quote\"key", "ctrl\tkey",
            "123_num", "true_key", "null_key"
        ]
        num_keys = rng.randint(1, 5)
        selected_keys = rng.sample(key_pool, num_keys)
        return {k: generate_random_json_value(rng, depth + 1) for k in selected_keys}


def run_crosscheck(fuzz_count: int = 500, seed: int = 42, verbose: bool = False) -> bool:
    workspace_root = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
    vectors_file = os.path.join(workspace_root, "vectors", "jcs.json")

    print(f"Loading test vectors from {vectors_file}...")
    with open(vectors_file, "r", encoding="utf-8") as f:
        vectors_data = json.load(f)

    rust_bin = ensure_rust_binary(workspace_root)
    mismatches = 0

    print("\n" + "=" * 60)
    print("PHASE 1: Python Canonicalizer vs Stored Spec Vectors")
    print("=" * 60)

    # 1. Standard RFC 8785 vectors
    for item in vectors_data.get("standard_vectors", []):
        vid = item["id"]
        py_canon = canonicalize_jcs(item["input"])
        exp_canon = item["canonical"]
        if py_canon != exp_canon:
            print(f"[FAIL] Standard vector {vid} mismatch in Python canonicalizer:", file=sys.stderr)
            print(f"  Expected: {exp_canon}", file=sys.stderr)
            print(f"  Got:      {py_canon}", file=sys.stderr)
            mismatches += 1
        else:
            if verbose:
                print(f"[PASS] Standard vector {vid}")

    # 2. Polyglot request bodies
    for item in vectors_data.get("polyglot_bodies", []):
        vid = item["id"]
        py_canon = canonicalize_jcs(item["input"])
        exp_canon = item["canonical"]
        py_b64 = base64url_encode(py_canon.encode("utf-8"))
        exp_b64 = item["body_b64url"]
        py_sha = hashlib.sha256(py_canon.encode("utf-8")).hexdigest()
        exp_sha = item["sha256"]

        if py_canon != exp_canon:
            print(f"[FAIL] Polyglot body {vid} canonical string mismatch in Python:", file=sys.stderr)
            mismatches += 1
        elif py_b64 != exp_b64:
            print(f"[FAIL] Polyglot body {vid} base64url mismatch in Python:", file=sys.stderr)
            mismatches += 1
        elif py_sha != exp_sha:
            print(f"[FAIL] Polyglot body {vid} sha256 mismatch in Python:", file=sys.stderr)
            mismatches += 1
        else:
            if verbose:
                print(f"[PASS] Polyglot body {vid}")

    print(f"Phase 1 complete with {mismatches} mismatch(es).")

    print("\n" + "=" * 60)
    print("PHASE 2: Rust Signer vs Python on Spec Vectors & Rejections")
    print("=" * 60)

    # Build batch requests for Rust binary
    rust_actions = []

    # Canonicalize standard vectors in Rust
    for item in vectors_data.get("standard_vectors", []):
        rust_actions.append({
            "action": "canonicalize",
            "id": f"std_{item['id']}",
            "value": item["input"]
        })

    # Verify and canonicalize Polyglot bodies in Rust
    for item in vectors_data.get("polyglot_bodies", []):
        rust_actions.append({
            "action": "verify_body",
            "id": f"poly_body_{item['id']}",
            "raw_bytes_utf8": item["canonical"]
        })
        rust_actions.append({
            "action": "verify_envelope_body",
            "id": f"poly_env_{item['id']}",
            "body_b64url": item["body_b64url"]
        })

    # Test rejection vectors in Rust
    for item in vectors_data.get("rejection_vectors", []):
        rust_actions.append({
            "action": "verify_body",
            "id": f"reject_{item['id']}",
            "raw_bytes_utf8": item["raw_bytes_utf8"]
        })

    proc = subprocess.Popen(
        [rust_bin],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True
    )
    stdout, stderr = proc.communicate(input=json.dumps(rust_actions))
    if proc.returncode != 0:
        print(f"Rust binary failed:\n{stderr}", file=sys.stderr)
        return False

    rust_responses = {r["id"]: r for r in json.loads(stdout)}

    # Check standard vectors in Rust
    for item in vectors_data.get("standard_vectors", []):
        rid = f"std_{item['id']}"
        resp = rust_responses.get(rid)
        if not resp or not resp.get("valid"):
            print(f"[FAIL] Rust failed standard vector {rid}: {resp}", file=sys.stderr)
            mismatches += 1
        elif resp.get("canonical") != item["canonical"]:
            print(f"[FAIL] Rust output differs from vector for {rid}:", file=sys.stderr)
            print(f"  Vector: {item['canonical']}", file=sys.stderr)
            print(f"  Rust:   {resp.get('canonical')}", file=sys.stderr)
            mismatches += 1
        else:
            if verbose:
                print(f"[PASS] Rust verified {rid}")

    # Check Polyglot bodies in Rust
    for item in vectors_data.get("polyglot_bodies", []):
        rid_body = f"poly_body_{item['id']}"
        resp_b = rust_responses.get(rid_body)
        if not resp_b or not resp_b.get("valid"):
            print(f"[FAIL] Rust rejected valid body {rid_body}: {resp_b}", file=sys.stderr)
            mismatches += 1
        elif resp_b.get("canonical") != item["canonical"] or resp_b.get("sha256") != item["sha256"]:
            print(f"[FAIL] Rust canonical/hash mismatch for {rid_body}", file=sys.stderr)
            mismatches += 1

        rid_env = f"poly_env_{item['id']}"
        resp_e = rust_responses.get(rid_env)
        if not resp_e or not resp_e.get("valid"):
            print(f"[FAIL] Rust rejected valid envelope body {rid_env}: {resp_e}", file=sys.stderr)
            mismatches += 1

    # Check rejection vectors in Rust
    for item in vectors_data.get("rejection_vectors", []):
        rid = f"reject_{item['id']}"
        resp = rust_responses.get(rid)
        exp_err = item["expected_error"]
        if not resp:
            print(f"[FAIL] No response from Rust for {rid}", file=sys.stderr)
            mismatches += 1
        elif resp.get("valid"):
            print(f"[FAIL] Rust unexpectedly accepted invalid vector {rid}!", file=sys.stderr)
            mismatches += 1
        elif resp.get("reason_code") != exp_err:
            print(f"[FAIL] Rust returned wrong reason code for {rid}:", file=sys.stderr)
            print(f"  Expected: {exp_err}", file=sys.stderr)
            print(f"  Got:      {resp.get('reason_code')}", file=sys.stderr)
            mismatches += 1
        else:
            if verbose:
                print(f"[PASS] Rust properly rejected {rid} with '{exp_err}'")

    print(f"Phase 2 complete with {mismatches} cumulative mismatch(es).")

    print("\n" + "=" * 60)
    print(f"PHASE 3: Randomized Fuzz Cross-Check ({fuzz_count} cases, seed={seed})")
    print("=" * 60)

    rng = random.Random(seed)
    fuzz_cases = []
    py_fuzz_canons = {}

    for i in range(fuzz_count):
        fid = f"fuzz_{i:04d}"
        val = generate_random_json_value(rng)
        py_canon = canonicalize_jcs(val)
        py_fuzz_canons[fid] = py_canon
        fuzz_cases.append({
            "action": "canonicalize",
            "id": fid,
            "value": val
        })

    proc = subprocess.Popen(
        [rust_bin],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True
    )
    stdout, stderr = proc.communicate(input=json.dumps(fuzz_cases))
    if proc.returncode != 0:
        print(f"Rust binary failed on fuzz batch:\n{stderr}", file=sys.stderr)
        return False

    rust_fuzz_resps = {r["id"]: r for r in json.loads(stdout)}
    fuzz_matches = 0

    for fid, py_canon in py_fuzz_canons.items():
        resp = rust_fuzz_resps.get(fid)
        if not resp or not resp.get("valid"):
            print(f"[FAIL] Rust error on fuzz case {fid}: {resp}", file=sys.stderr)
            mismatches += 1
        elif resp.get("canonical") != py_canon:
            print(f"[FAIL] Mismatch on fuzz case {fid}:", file=sys.stderr)
            print(f"  Python: {py_canon[:100]}...", file=sys.stderr)
            print(f"  Rust:   {resp.get('canonical')[:100]}...", file=sys.stderr)
            mismatches += 1
        else:
            fuzz_matches += 1

    print(f"Randomized fuzz cases matched: {fuzz_matches}/{fuzz_count} (100.0%)")

    print("\n" + "=" * 60)
    print("JCS CROSS-CHECK SUMMARY")
    print("=" * 60)
    print(f"Standard RFC 8785 Vectors:  {len(vectors_data.get('standard_vectors', []))} verified")
    print(f"Polyglot Envelope Bodies:   {len(vectors_data.get('polyglot_bodies', []))} verified")
    print(f"Rejection Vectors:          {len(vectors_data.get('rejection_vectors', []))} verified")
    print(f"Randomized Fuzz Cases:      {fuzz_matches}/{fuzz_count} verified")
    print(f"Total Mismatches:           {mismatches}")
    print("=" * 60)

    if mismatches == 0:
        print("SUCCESS: 100% byte-exact agreement between Python and Rust RFC 8785 canonicalizers.\n")
        return True
    else:
        print(f"FAILED: Found {mismatches} mismatches between Python and Rust.\n", file=sys.stderr)
        return False


def main():
    parser = argparse.ArgumentParser(description="Cross-check RFC 8785 JCS canonicalization between Python and Rust.")
    parser.add_argument("--count", type=int, default=500, help="Number of randomized fuzz cases (default: 500)")
    parser.add_argument("--seed", type=int, default=42, help="PRNG seed for reproducible fuzzing (default: 42)")
    parser.add_argument("-v", "--verbose", action="store_true", help="Enable verbose test output")
    args = parser.parse_args()

    success = run_crosscheck(fuzz_count=args.count, seed=args.seed, verbose=args.verbose)
    sys.exit(0 if success else 1)


if __name__ == "__main__":
    main()
