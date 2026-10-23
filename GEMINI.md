# GEMINI.md — Polyglot Project Context & Dispatcher Operating Manual

## 1. Project Identity & Mission

**Polyglot** is a vendor-neutral, multi-chain Hierarchical Deterministic (HD) wallet signing middleware built for institutional custody and automated transaction workflows.

It enforces a **zero-trust boundary** between untrusted orchestration (`api/` in Go + `app` schema in PostgreSQL) and isolated cryptographic execution (`signer/` in Rust + PKCS#11 HSM via SoftHSMv2 + `signer` schema in PostgreSQL). Even a fully compromised API gateway or database cannot forge a signature, swap `wrapped_seed` blobs across wallets, replay an old authorization, or extract a master seed.

---

## 2. Primary Session Agent: Dispatcher Protocol (`Gemini 4 Argon Medium`)

The agent running in the user's primary conversation session operates on **Gemini 4 Argon (Medium)** and serves as the **Dispatcher & Lead Security Architect**.

### Core Responsibilities of the Dispatcher
1. **Assess & Decompose**: Evaluate every user request across three dimensions before writing code or running heavy commands:
   - **Complexity & Security Criticality**: Does this touch cryptographic primitives, PKCS#11 lifecycle, the 9-step envelope verifier, chain sighash codecs, or SQL role isolation?
   - **Token Consumption & Context Hygiene**: Will this task require grepping across many files, inspecting large test vector JSONs (`vectors/*.json`), reading `docs/index.html`, or parsing verbose `cargo test` / Docker logs?
   - **Task Scope**: Is it a read-only reconnaissance task, a bounded implementation/test task, or a deep cross-component architectural change?
2. **Dispatch to Right-Sized Subagents**: Delegate work to subagents using the model tiering matrix defined in [`AGENTS.md`](AGENTS.md):
   - **Gemini 3.8 Flash (Low)** (`flash_lite`): File discovery, `grep`/symbol lookups, log triage, config checks, and concise recaps.
   - **Gemini 3.8 Flash (Medium)** (`flash`): Scoped Go API changes, CLI tooling (`tools/pe-sim`), test execution & failure summarization, documentation/UI updates (`docs/index.html`, `README.md`), and standard test authoring.
   - **Gemini 4 Argon** (`inherit` / `pro`): Rust Signer cryptography (`derive/`, `pkcs11session/`, `envelope/`), blockchain transaction codecs (`chains/`), HSM conformance (`backend/`), SQL security boundaries (`migrations/`), and threat-model verification.
3. **Verify & Synthesize**: Review subagent outputs against Polyglot's non-negotiable security invariants before presenting results or committing changes.

> See [`AGENTS.md`](AGENTS.md) for the complete dispatch decision matrix, subagent role templates, handoff contracts, and token-budget rules.

---

## 3. Architecture & Hard-Won Engineering Invariants

Every change to Polyglot must preserve the following invariants established during its construction:

### 3.1 Trust Zones & Network Topology
- **Go API (`api/`)**: Dual-port HTTP server.
  - Public listener (`:8080`): `/healthz`, `/v1/signer`, `/v1/wallets`, `/v1/wallets/{id}`, `/v1/requests`, `/v1/requests/{id}`.
  - Internal listener (`:8081`, Docker `backend` network `internal: true`): `/internal/claim` (25s long-poll via `SELECT ... FOR UPDATE SKIP LOCKED` with 60s lease) and `/internal/results`.
- **Rust Signer (`signer/`)**: Opens **zero inbound ports** and has **no internet access**. Polls `/internal/claim` outbound and posts signed responses to `/internal/results`.
- **PostgreSQL 16 (`migrations/`)**:
  - `api_role` has access strictly to `app.*` (`api_keys`, `wallets`, `requests`, `audit_log`) and zero permissions on `signer.*`.
  - `signer_role` owns `signer.replay`, `signer.results`, and `signer.signer_audit` (plus read-only `SELECT` on `app.wallets`).
  - Both `app.audit_log` and `signer.signer_audit` are SHA-256 hash-chained under an advisory lock with `BEFORE UPDATE OR DELETE` triggers that forbid mutation.

### 3.2 The Signer 9-Step Fail-Closed Checklist (`signer/src/envelope/processor.rs`)
No cryptographic unwrap or signature may occur unless Steps 1–8 succeed in exact order:
1. **Strict Parse & RFC 8785 JCS Verification**: Reject unknown fields (`deny_unknown_fields`), verify `v == 1`, and verify the raw `body_canonical` bytes match RFC 8785 canonical JSON byte-for-byte (`non_canonical_body` on mismatch).
2. **Audience Check**: `body.audience == config.signer_id` (`audience_mismatch`).
3. **Expiry & Lifetime Check**: Not expired, total lifetime (`expires_at` window) $\le 600\text{s}$, clock skew tolerance $\le 30\text{s}$.
4. **Policy Engine Signature Verification**: Verify against pinned keys in read-only `/etc/polyglot/signer.yaml` (`kid`, `alg` pinned to `ed25519` or `es256`, `not_before`/`not_after` window). Reject `alg: "none"`, mismatched algorithms, or unknown `crit` headers.
5. **Replay & Idempotency Barrier**: Check `signer.results` for cached idempotent response; otherwise `INSERT (request_id, nonce) INTO signer.replay` **before** any cryptographic operation (`409 Conflict` / `replayed` on unique violation).
6. **Derivation Path Validation**: Depth $\le 255$; `slip10` (`ed25519`) strictly requires hardened-only indices ($\ge 2^{31}$).
7. **Payload & Chain Codec Verification**:
   - `payload_encoding == "tx"`: Decode raw unsigned transaction via the native codec in `signer/src/chains/`, enforce CAIP-2 chain ID agreement, compute sighash, and set `blind_sign: false`.
   - `payload_encoding == "digest"` or `"message"`: Reject with `digest_signing_disabled` unless `allow_digest_signing: true` in `signer.yaml` (sets `blind_sign: true`).
8. **AEAD Seed Unwrap (`CKM_AES_GCM`)**: Reconstruct the canonical Associated Data (`AAD`) **strictly from the verified request body** (`"{wallet_id}|{scheme}|{curve}|{seed_version}|{kek_label}"`), never from untrusted database metadata. Unwrap the 92-byte `wrapped_seed` (`IV[12] || Ciphertext[64] || Tag[16]`) under `kek-v1` into a `Zeroizing<[u8; 64]>` buffer.
9. **Derive, Sign, Wipe & Persist**:
   - Derive child key (BIP32 `secp256k1` or SLIP10 `ed25519`) inside `Zeroizing` memory.
   - Load child private key into the HSM as an ephemeral session object (`CKA_TOKEN=false`, `CKA_EXTRACTABLE=false`, `CKA_SENSITIVE=true`) guarded by RAII `SessionKeyGuard`, invoke `C_Sign`, and immediately call `C_DestroyObject`.
   - *Exception*: Bitcoin Taproot (`P2TR`) key-path inputs use BIP86 tweak + BIP340 Schnorr in `Zeroizing` software memory because PKCS#11 lacks BIP340; responses must honestly set `"signing_in_hsm": false`.
   - Normalize signatures (low-$S$ for ECDSA, recovery ID $v$ for EVM/Tron, canonical DER for BTC/XRPL), sign the canonical response with the Signer's Ed25519 identity key (`signer_sig`), and persist to `signer.results` and `signer.signer_audit`.

### 3.3 Supported Chains & Codec Invariants (`signer/src/chains/`)
- **Bitcoin (`bitcoin:mainnet`, `bitcoin:testnet`)**: BIP174 PSBT. Non-Taproot inputs (`P2PKH`, `P2WPKH`, `P2SH-P2WPKH`) **must** carry `PSBT_IN_NON_WITNESS_UTXO`, verified via double-SHA256 against the prevout `txid` to prevent fee spoofing. Taproot (`P2TR`) commits to all input amounts/scripts via BIP341 sighash. Multisig, P2WSH, and script-path inputs are rejected (`unsupported_transaction`).
- **Ethereum & EVM (`eip155:<chain_id>`)**: EIP-1559 (`0x02`) and Legacy EIP-155 native transfers and ERC-20 `transfer(address,uint256)`. Enforces `tx.chain_id == chain`.
- **Solana (`solana:mainnet`, `solana:devnet`)**: Legacy wire message restricted to System Program `Transfer` (instruction index `2`) or `TransferWithSeed` (`11`).
- **Tron (`tron:mainnet`)**: Protobuf `raw_data` restricted to `TransferContract` (TRX) or `TriggerSmartContract` TRC-20 `transfer`.
- **XRP Ledger (`xrpl:mainnet`)**: Canonical binary `Payment` (`TransactionType = 0`), hashed with `SHA-512Half` over prefix `STX\0` (`0x53545800`).

---

## 4. Repository Layout

| Path | Language / Tech | Purpose |
|---|---|---|
| `signer/` | Rust (2021) | Trusted Signer daemon, PKCS#11 session wrapper, BIP32/SLIP10 derivation, 5 chain codecs, JCS verifier, startup probe, and conformance tests. |
| `api/` | Go (1.24+) | Untrusted HTTP gateway (`:8080` public, `:8081` internal), SHA-256 Bearer auth, RFC 9457 Problem Details, Postgres queue & lease manager. |
| `tools/pe-sim/` | Rust | Host CLI Policy Engine stand-in (`keygen`, `sign`, and 5-chain end-to-end `demo`). |
| `migrations/` | PostgreSQL 16 SQL | Schema definitions (`app`, `signer`), role isolation (`api_role`, `signer_role`), and immutable hash-chained audit triggers. |
| `vectors/` | JSON | Golden test vectors (`bip32.json`, `slip10.json`, `jcs.json`, `tx_bitcoin.json`, `tx_evm.json`, `tx_solana.json`, `tx_tron.json`, `tx_xrpl.json`). |
| `deploy/` | Docker / YAML | Hardened `compose.yaml` (`read_only`, `cap_drop: [ALL]`, isolated networks) and read-only `signer.yaml`. |
| `dev/` | Bash / Python 3 | `bootstrap.sh`, `demo.sh`, `test_migrations.sh`, `crosscheck_jcs.py`, `crosscheck_derive.py`. |
| `docs/` | HTML / CSS / JS | Interactive visual architecture explainer (`docs/index.html`). |

---

## 5. Standard Build, Test & Verification Commands

Always run verification commands inside the sandbox first (`BypassSandbox: false`):

```bash
# Full offline test suite (Rust Signer + pe-sim + Go API + Python JCS & BIP32/SLIP10 cross-checks)
make test

# Targeted Rust Signer unit & integration tests
cargo test --manifest-path signer/Cargo.toml

# Vendor PKCS#11 & zeroization heap-scanning conformance test
cargo test --manifest-path signer/Cargo.toml --test conformance

# Targeted Go API tests
cd api && go test -v ./...

# Cross-language verification (Python vs Rust)
python3 dev/crosscheck_jcs.py
python3 dev/crosscheck_derive.py

# Live Docker stack lifecycle & 5-chain E2E verification
make bootstrap
make up
make demo
./dev/test_migrations.sh
make down
```

---

## 6. Hard Workspace & Security Rules

1. **Forbidden Paths**: Never read, inspect, or reference `.auto-claude/`, `.auto-claude-security.json`, or `.auto-claude-status`.
2. **Secret Hygiene**: Never log, commit, or print contents of `./secrets/` (except public `.pub` / `.yaml` snippets when verifying `kid` pins) or expose `wrapped_seed` in any API response.
3. **Cross-Language Sync**: Any modification to JCS canonicalization, envelope fields, or key derivation must pass `python3 dev/crosscheck_jcs.py`, `python3 dev/crosscheck_derive.py`, `signer` tests, and `tools/pe-sim` tests.
4. **Error Contract**: All API and Signer rejections must map cleanly to RFC 9457 Problem Details (`application/problem+json`) with stable `code` and `reason` values.
