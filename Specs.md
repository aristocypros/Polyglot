# Prototype Spec: HD Wallet Signing Middleware (Generic Tier)

Oct 16, 2026 

## 1. Purpose and scope

The prototype proves one thing: a vendor-neutral signing service can derive BIP32/SLIP10 keys on demand from a KEK-wrapped seed, run fully on a laptop in Docker, and refuse any request that lacks valid signed authorization. It uses only standard PKCS#11 against SoftHSMv2, which is the **generic tier** from our earlier discussion.

**In scope**

- Wallet creation: the seed is generated in the signer, wrapped under an HSM KEK with AEAD, and stored in Postgres.
- Derivation by full path in one call, for BIP32 secp256k1 and SLIP10 ed25519.
- Operations: derive public key, sign a digest, sign a raw transaction.
- Signing inside the HSM through PKCS#11: the derived child key is loaded as a short-lived session object, signed with, and destroyed. Where the HSM lacks a curve, the signer signs in software and says so.
- Raw transaction signing for five chains: Bitcoin (all four single-key input types, including Taproot), Ethereum (and other EVM networks), Solana, Tron and XRP Ledger. The signer decodes the transaction, computes the signing input itself, and returns a summary in one common shape.
- One authorization signature from the client's policy engine on every request (Ed25519, or ES256 as a JWS), verified by the signer, plus replay protection and signed responses.
- A capability probe and a `protection_level` label on every result.
- REST API only, Postgres only, Docker Compose only.

**Out of scope for the prototype**

- Approvals, quorum and business rules: the client's policy engine owns them. This product only verifies that engine's signature.
- Native derive backends (IBM, Thales, Utimaco, Fortanix): next phase, once vendor access exists.
- TEE, attestation, network isolation beyond Compose networks.
- UI, broker, events, Redis, clustering, high availability.
- More chains and transaction types than the five supported.
- Seed import (BIP39 words or raw seeds), key rotation, BLS signatures, and Bitcoin multisig or script-path spends.

**Done means**

1. `docker compose up` brings the stack up on a clean laptop, with a documented bootstrap script.
2. The published BIP32 and SLIP10 test vectors pass through the full API path.
3. A request forged or replayed by a compromised API process is rejected by the signer.
4. The demo signs one transfer on each of the five chains, and the returned summary matches what was submitted.
5. Every result states honestly that it came from the generic tier, and whether signing happened in the HSM.

## 2. Architecture

Three services (API, signer, Postgres) and one setup job run locally. The client's policy engine sits outside the product and decides what is allowed. The API and Postgres sit in an untrusted zone: they can delay or drop requests but cannot produce a signature. Only the signer, with its HSM token and a pinned copy of the policy engine's public key, can sign.

&#91;embedded content: architecture · 4 services, 2 trust zones\]

The signer opens no port. It reaches out to the API to claim work, so the most sensitive process has no inbound attack surface.

**Request flow**

1. The client asks its policy engine to evaluate the operation. If allowed, the policy engine signs the canonical request body.
2. The client submits the signed envelope to the API, which checks its shape, stores it, and queues it.
3. The signer polls, claims the request, and runs the verification checklist from section 5.
4. For a signing request the signer unwraps the seed with the HSM, derives the key at the path, and decodes the transaction if one was sent.
5. The signer loads the child key into the HSM as a session object, has the HSM sign, destroys the object, and wipes memory.
6. The signer signs its response and posts it back through the API.
7. The client reads the result and verifies the signer's signature.

## 3. Security model of the generic tier

In the generic tier the signer holds the clear seed in memory during each request, and the HSM protects the seed only at rest. The controls below exist to limit who can make the signer sign, and to keep a compromised neighbor from doing so.

| Threat | Control | Residual risk |
| --- | --- | --- |
| Compromised API or orchestrator | Signer verifies the policy engine's signature itself and never trusts the API | API can deny service, not sign |
| Database stolen | Seeds are AEAD-wrapped under a non-extractable KEK held in the HSM | Attacker with HSM access can still unwrap |
| Operator swaps seeds between wallets | AEAD associated data binds wallet ID, scheme, curve, version | None if AAD is checked |
| Replay of an old authorization | Unique request ID, expiry and nonce, checked in a signer-owned table | Needs the signer DB role kept separate |
| Compromised policy engine key | Signer pins key IDs in a read-only config. Rotation and revocation are config changes. | Whoever holds the key can authorize any operation. Protecting it is the client's job. |
| Compromised signer process | Not prevented in this tier | Seed readable from memory; closed by native backend or TEE later |

**Honest limits in Docker.**

- SoftHSMv2 is software. Its KEK lives in token files protected by a PIN and file permissions, so it shows the flow, not HSM-grade protection.
- There is no attestation: nothing proves the signer binary is the approved build.
- Memory hygiene is best effort even in Rust: zeroize buffers, disable core dumps, lock pages. There is no garbage collector copying secrets, but registers, swap and crash dumps can still hold copies.
- HSM-side signing moves the signing operation, not the exposure: the seed and the child key still pass through the signer's memory before the child key is loaded into the HSM.

**Protection labels.** Every signed response carries `protection_level` and `backend`:

| Value | Meaning |
| --- | --- |
| `generic-dev` | SoftHSM, derivation in the signer. Prototype only. |
| `generic-hsm` | Real PKCS#11 HSM, derivation in the signer |
| `native` | Derivation inside the HSM (future) |

## 4. Cryptographic specification

v1 supports two schemes. Both are derived in the signer and signed in the HSM, and seeds are stored wrapped with AES-256-GCM under an HSM KEK.

| Scheme | Curve | Child derivation | Signature | Notes |
| --- | --- | --- | --- | --- |
| BIP32 | secp256k1 | Hardened and non-hardened | ECDSA, low-S, normalized by the signer | An invalid child index fails the request and names the index |
| SLIP10 | ed25519 | Hardened only | Ed25519 | Non-hardened indices are rejected |

SLIP10 on P-256 is a post-prototype addition. The scheme and curve are stored per wallet, because some HSMs cannot tell BIP32 from SLIP10 on secp256k1.

**Paths.** Accepted as `m/44'/0'/0'/0/5` or with `h`. Parsed into an array of 32-bit indices, with 0x80000000 marking hardened. Maximum depth is 255, which matches Thales Luna. The API and the signer both validate the path.

**Seed.** 64 random bytes from the HSM (`C_GenerateRandom`), generated inside the signer at wallet creation. The seed never leaves the signer unwrapped.

**Wrapping.**

- Mechanism: `CKM_AES_GCM`, 256-bit KEK, non-extractable, label `kek-v1`, fresh 96-bit IV per wrap taken from the HSM.
- Stored blob: IV, ciphertext, tag.
- Associated data: `wallet_id | scheme | curve | seed_version | kek_label`. Unwrapping with any other context fails, so seeds cannot be swapped between wallets.
- Unwrapping is a `C_Decrypt` call whose output goes to the signer. That is the defining property of the generic tier.
- SoftHSM has supported `CKM_AES_GCM` since version 2.4.0 (February 2018), so no CBC fallback is planned. The startup probe still self-tests the installed build.

**Derivation and signing.**

- BIP32 and SLIP10 are implemented in Rust on audited crates. Candidates are `k256`, `ed25519-dalek`, `hmac` and `sha2`, to be confirmed in milestone 1. SLIP10 ed25519 is about 60 lines (HMAC-SHA512 with key `ed25519 seed`, hardened only). Both must pass the published vectors before anything else is built.
- Signing happens in the HSM. The signer loads the derived child key as a non-extractable session object (`CKA_TOKEN` false, `CKA_EXTRACTABLE` false), signs with `CKM_ECDSA` (secp256k1) or `CKM_EDDSA` (ed25519), and destroys the object. Each request uses its own PKCS#11 session, and closing a session also destroys any session objects left in it.
- If the HSM cannot sign on a curve, the capability probe marks that scheme as software signing and the signer signs itself. Every response says `signing_in_hsm` true or false. SoftHSM support depends on its build and OpenSSL version. Bitcoin Taproot is the exception: it uses BIP340 Schnorr signatures, for which PKCS#11 has no mechanism, so it is always signed in software and the response says so.
- ECDSA signatures from the HSM come back as raw `r` and `s` and are not deterministic. The signer normalizes `s` to low-S and finds the recovery ID where the chain needs one (Ethereum, Tron) by testing both parities against the known public key. It also formats the signature per chain, as DER for Bitcoin and XRP Ledger.
- ECDSA signs a 32-byte digest. Ed25519 signs the raw message bytes. For raw transactions the signer computes the signing input itself (section 5).
- Outputs are compressed public keys (33 bytes secp256k1, 32 bytes ed25519). Chain codes are never returned. Extended public key export is deferred.
- All key material is zeroized after each request (the `zeroize` crate, locked memory where available), and every error path zeroizes too.

## 5. Chain of trust with the client policy engine

The signer accepts a request only if the client's policy engine signed the exact request body, and it verifies this itself. The API only carries the envelope. This product does not evaluate rules, collect approvals or count quorums: the policy engine decides, and the signer proves that the decision came from it.

**Envelope.** `{ body, authorization }`. The client builds the body, the policy engine signs it, and the client submits both. The body is encoded with JSON Canonicalization (RFC 8785). Exactly one valid signature from a pinned key is required, in one of two formats:

| `alg` | Pinned key type | Wire format | What is signed |
| --- | --- | --- | --- |
| `ed25519` | Ed25519 | `{ kid, alg, sig }`, 64-byte signature in base64url | SHA-256 of the canonical body bytes |
| `ES256` | ECDSA P-256 | `{ kid, alg, jws }`, a JWS compact string with detached payload (RFC 7515, appendix F) | The JWS signing input over the canonical body bytes |

| Body field | Purpose |
| --- | --- |
| `v` | Envelope version. Unknown versions are rejected. |
| `type` | `create_wallet`, `derive_public`, or `sign` |
| `request_id` | UUID, unique, the replay key |
| `nonce` | 16 random bytes, hex |
| `audience` | ID of the signer this is for |
| `expires_at` | UTC time, maximum lifetime 10 minutes |
| `decision_id` | Opaque ID from the policy engine, copied into audit logs and the response |
| `wallet_id`, `scheme`, `curve` | Bind the request to one wallet and one scheme |
| `path` | Array of 32-bit indices. Bitcoin transactions send input\_paths instead: one path per input to sign. |
| `payload_encoding`, `payload` | For `sign`: `digest` (32 bytes, ECDSA), `message` (bytes, Ed25519) or `tx` (a raw transaction) |
| `chain` | CAIP-2 chain ID such as `eip155:1`. Required when `payload_encoding` is `tx`. |

**Trust anchors.** The policy engine's public keys (key ID, algorithm, validity window), the signer ID and the maximum request lifetime live in a read-only config file mounted into the signer. They are not in Postgres, so a compromised API or database cannot add or swap a key. The algorithm is fixed per key ID in that config. A JWS header whose `alg` differs, `none`, or an unknown critical header is rejected, so a header cannot steer the verifier to a weaker algorithm. Several key IDs can be valid at once, so rotation is a config change with an overlap window, and revoking a key means removing it.

**Response.** The signer signs `{ request_id, decision_id, request_hash, status, result, parsed, protection_level, backend, signing_in_hsm, blind_sign, signed_at }` with its own Ed25519 identity key. For transactions, `parsed` lists the decoded fields and `result` carries the signature and the signer's address. Clients fetch the signer's public key from `GET /v1/signer` and verify it. The signer also stores each signed result, so a retry of the same `request_id` returns the same answer.

**Signer verification checklist, in order:**

1. Parse strictly. Reject unknown fields and versions, and re-encode to confirm the bytes are canonical.
2. `audience` equals this signer's ID.
3. Not expired, lifetime within the maximum, clock skew within 30 seconds.
4. The key ID is pinned and currently valid, the algorithm matches the pinned one, and the signature verifies (Ed25519 over the body hash, or ES256 over the JWS signing input).
5. Replay: insert `request_id` and `nonce` into the signer-owned table. A unique violation rejects the request. If a stored result exists for this `request_id`, return it instead.
6. Every path is valid for the scheme (ed25519 hardened only, depth at most 255).
7. For `tx`: decode with the chain codec, reject unsupported types and instructions, check that network identifiers inside the transaction (such as the Ethereum chain ID) match `chain`, and compute the signing input. For Bitcoin, identify each input as P2PKH, P2SH-P2WPKH, P2WPKH or Taproot key-path from its previous output script, reject any other script type, and check that it belongs to the key derived at the input's path. For `digest` or `message`: require `allow_digest_signing`, which is on in the dev profile and off in the production profile.
8. Unwrap the seed using AAD built from the body, not from the database row. Any mismatch fails.
9. Derive, sign in the HSM, destroy the session object, zeroize, sign the response, store it.

The replay insert happens before execution, so delivery is at-most-once. If the signer crashes after step 5 and before storing a result, the client submits a new request with a new ID.

**Blind signing.** A `digest` or `message` request is blind: the signer cannot tell what it covers, so the response sets `blind_sign: true`, and the config switch `allow_digest_signing` is off by default in the production profile and on in the dev profile. A `tx` request is not blind, because the signer decodes the transaction and computes the signing input from the same bytes the policy engine signed.

**Raw transactions.** Five chain codecs cover both schemes, and the EVM codec serves many networks. Each codec decodes the transaction, returns a summary, and builds the signing input. Details are confirmed against published reference vectors in milestone 3.

| Chain | Scheme and path | Accepted input | Signing input | Signature returned |
| --- | --- | --- | --- | --- |
| Bitcoin | BIP32 secp256k1, `m/44'`, `m/49'`, `m/84'` or `m/86'` by input type | PSBT with single-key inputs: P2PKH, P2SH-P2WPKH, P2WPKH or P2TR key-path | Legacy sighash (P2PKH), BIP143 (both SegWit types), BIP341 (Taproot) | One per input: DER ECDSA plus sighash byte, or 64-byte BIP340 Schnorr for Taproot |
| Ethereum and EVM networks (Polygon, BNB Chain, Arbitrum, Optimism, Avalanche C-Chain and others) | BIP32 secp256k1, `m/44'/60'/...` | EIP-1559 (type 2) and legacy EIP-155 transactions | Keccak-256 of the unsigned encoding | `r`, `s` (low-S) and recovery ID |
| Solana | SLIP10 ed25519, `m/44'/501'/...` | Legacy message made of System Program transfers | The serialized message, signed directly | 64-byte Ed25519 signature |
| Tron | BIP32 secp256k1, `m/44'/195'/...` | `raw_data` with a TRX transfer or a TRC-20 `transfer` call | SHA-256 of the `raw_data` bytes | `r`, `s` and recovery ID (65 bytes) |
| XRP Ledger | BIP32 secp256k1, `m/44'/144'/...` | Binary-encoded Payment transaction | SHA-512 half of the `STX` prefix and the signing fields | DER ECDSA, low-S |

**One summary shape.** `parsed` has the same structure on every chain: `transfers` (from, to, amount, asset), `fee`, a sequence field (nonce, sequence number or recent blockhash), and `details` for chain-specific fields. One policy engine can therefore read every chain's summary. Any other transaction type or instruction is rejected as `unsupported_transaction`.

**Bitcoin needs several keys per request.** A transaction spends outputs that sit under different addresses, so the body carries `input_paths`, one derivation path per input to sign, instead of a single `path`. The signer identifies each input as P2PKH, P2SH-P2WPKH, P2WPKH or Taproot key-path from its previous output script, rejects any other script, checks that it belongs to the key derived at the input's path, signs, and returns one signature per input. Taproot signatures are BIP340 Schnorr, which PKCS#11 cannot do, so they are always signed in software. For every input except Taproot, the PSBT must carry the full previous transaction, which the signer hashes and matches to the input, so the amounts and the fee can be trusted. A Taproot sighash commits to the amounts of all inputs, so every input then needs its previous output, signed or not. The fee is computed from the PSBT and shown in `parsed`.

**Not in v1.** Cardano (a different Ed25519 derivation scheme, not SLIP10), Polkadot (Sr25519), and Bitcoin multisig or Taproot script-path spends, which need several keys or custom scripts. Stellar and Cosmos SDK chains are the first candidates to add, since both fit the existing schemes.

## 6. API specification

The API is JSON over HTTP, versioned under `/v1`. Every operation is a request that waits for the signer. Clients poll for the result, so no connection is held open and the API stays stateless.

**Authentication.** `Authorization: Bearer <key>`. Keys are 256-bit random values, stored only as SHA-256 hashes, with one role each: `client` or `signer`. This is a prototype convenience. Real authority comes from the policy engine's signature in section 5, and mTLS replaces keys later.

| Method | Path | Role | Purpose |
| --- | --- | --- | --- |
| GET | `/healthz` | none | Liveness |
| GET | `/v1/signer` | any | Signer ID, public key, capabilities, `protection_level` |
| POST | `/v1/requests` | client | Submit a signed envelope. Returns the request ID and status. |
| GET | `/v1/requests/{id}` | client | Status and, when finished, the signed result |
| GET | `/v1/wallets` | client | List wallets: ID, label, scheme, curve, created time |
| GET | `/v1/wallets/{id}` | client | One wallet's metadata |
| POST | `/internal/claim` | signer | Outbound long poll for the next ready envelope |
| POST | `/internal/results` | signer | Submit the signed result |

The `/internal` routes listen on a second port that is reachable only from the backend network.

**Request states.** `ready` → `claimed` → `completed`, with `failed` and `expired` as terminal states. A request is `ready` as soon as the API accepts its envelope. The API checks only shape and size. The signer verifies everything else.

**Submit request.** `POST /v1/requests`, with an optional `Idempotency-Key` header. The payload is the envelope from section 5. The body travels as base64url of its canonical bytes, so no component can re-encode it:

```json
{
  "body": "<base64url of the canonical JSON body>",
  "authorization": { "kid": "pe-dev-1", "alg": "ed25519", "sig": "<base64url>" }
}
```

With an ES256 key, `authorization` is `{ "kid": "pe-dev-2", "alg": "ES256", "jws": "<header..signature>" }`.

The decoded body for a signing request:

```json
{
  "v": 1, "type": "sign", "request_id": "<uuid>", "nonce": "<16 bytes hex>",
  "audience": "signer-local-1", "expires_at": "2026-10-16T12:10:00Z",
  "decision_id": "dec_8f3a", "wallet_id": "w_01HZ...",
  "scheme": "bip32", "curve": "secp256k1",
  "path": [2147483692, 2147483648, 2147483648, 0, 5],
  "payload_encoding": "digest",
  "payload": "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08"
}
```

A transaction request adds `chain` and sends the raw transaction instead of a digest:

```json
{
  "v": 1, "type": "sign", "request_id": "<uuid>", "nonce": "<16 bytes hex>",
  "audience": "signer-local-1", "expires_at": "2026-10-16T12:10:00Z",
  "decision_id": "dec_8f3b", "wallet_id": "w_01HZ...",
  "scheme": "bip32", "curve": "secp256k1",
  "path": [2147483692, 2147483708, 2147483648, 0, 0],
  "chain": "eip155:1",
  "payload_encoding": "tx",
  "payload": "<raw EIP-1559 transaction, hex>"
}
```

Response `202`: `request_id`, `status`, `expires_at`. For `create_wallet`, the client chooses the new `wallet_id` inside the signed body, and may add an unsigned `label` next to the envelope. The API does not check signatures or key IDs, because it is not a trust anchor.

**Result.** When `status` is `completed`, `GET /v1/requests/{id}` returns the signer's signed response: the result (`public_key` or `signature`, plus `signer_address` for transactions), `parsed` for transactions, `protection_level`, `backend`, `signing_in_hsm`, `blind_sign`, and the signer's signature.

**Errors.** RFC 9457 problem details with a stable `code`: `invalid_request`, `unauthorized`, `unknown_wallet`, `request_expired`, `replayed`, `signer_rejected` (with the signer's reason code, such as `bad_signature`, `unknown_kid`, `audience_mismatch`, `unsupported_transaction`), `signer_unavailable`. A request that no signer claims within its lifetime ends as `expired`.

## 7. Postgres data model

One Postgres 16 instance holds everything, split into two schemas with two database roles. The API role cannot read or write the signer schema, so a compromised API cannot touch the replay store.

| Schema | Table | Key columns |
| --- | --- | --- |
| `app` | `api_keys` | `id`, `name`, `role`, `key_hash`, `revoked_at` |
| `app` | `wallets` | `wallet_id`, `label`, `scheme`, `curve`, `seed_version`, `kek_label`, `wrapped_seed`, `created_at` |
| `app` | `requests` | `request_id`, `type`, `wallet_id`, `body_canonical`, `authorization`, `body_hash`, `status`, `expires_at`, `claimed_until`, `result`, `error_code` |
| `app` | `audit_log` | `seq`, `ts`, `actor`, `event`, `request_id`, `decision_id`, `prev_hash`, `hash` (hash-chained, no updates or deletes granted) |
| `signer` | `replay` | `request_id` (primary key), `nonce` (unique), `seen_at` |
| `signer` | `results` | `request_id`, `response`, `response_sig`, `created_at` |
| `signer` | `signer_audit` | Same shape as `audit_log`, written only by the signer |

`body_canonical` stores the exact bytes that were approved, so the hash can always be re-verified. A wallet's `wrapped_seed` is safe in the API's schema because of the AEAD binding in section 4.

**Postgres as the work queue.** There is no broker. The signer calls `/internal/claim`, and the API runs this inside a short polling loop (one second sleeps, 25 seconds maximum):

```sql
UPDATE app.requests SET status = 'claimed', claimed_until = now() + interval '60 seconds'
WHERE request_id = (
  SELECT request_id FROM app.requests
  WHERE status = 'ready' AND expires_at > now()
  ORDER BY created_at
  FOR UPDATE SKIP LOCKED LIMIT 1)
RETURNING request_id, body_canonical;
```

If a lease lapses without a result, the request returns to `ready`. A second signer attempt is then safe: the signer's replay table rejects an ID it already recorded, and returns the stored result if one exists. A request recorded without a stored result ends as `failed`, and the client submits a new one.

**Migrations.** Plain SQL files applied at API start (golang-migrate), run as an admin role that the services do not use at runtime.

## 8. Backend interface and the SoftHSM generic backend

The signer talks to one `Backend` interface. The generic backend implements it with standard PKCS#11 and software derivation. Native backends later implement the same interface and simply never return the seed to the signer. The interface deliberately exposes operations, not key material, so the swap does not touch the API or the envelope logic.

```rust
pub trait Backend: Send + Sync {
    fn capabilities(&self) -> Result<Capabilities, BackendError>;
    /// Creates a seed inside the backend and returns it wrapped.
    fn create_wallet(&self, spec: &Spec, aad: &[u8]) -> Result<Vec<u8>, BackendError>;
    fn public_key(&self, w: &WalletRef, path: &[u32]) -> Result<Vec<u8>, BackendError>;
    /// Signs a digest, a message, or a transaction's signing input.
    fn sign(&self, w: &WalletRef, path: &[u32], input: SigningInput) -> Result<Signature, BackendError>;
}

pub enum SigningInput<'a> {
    Digest32(&'a [u8; 32]),        // ECDSA
    Message(&'a [u8]),             // Ed25519
    TaprootDigest32(&'a [u8; 32]), // BIP340 Schnorr, BIP86 key-path tweak, software only
}

pub struct WalletRef<'a> {
    pub wrapped: &'a [u8],
    pub aad: &'a [u8],   // built by the signer from the verified body
    pub scheme: Scheme,  // Bip32 | Slip10
    pub curve: Curve,    // Secp256k1 | Ed25519
}

pub struct Capabilities {
    pub backend: String,                   // "softhsm-generic"
    pub protection_level: ProtectionLevel, // GenericDev
    pub schemes: Vec<SchemeCap>,           // scheme, curve, hardened_only, signing: Hsm | Software
    pub max_depth: u8,
    pub wrap_mechanism: String,
    pub derives_in_hsm: bool,              // false for the generic tier
}
```

**Internal split of the generic backend.**

- `pkcs11session`: a wrapper over the `cryptoki` crate. Login, random, AES-GCM with the KEK, loading a child key as a session object, `C_Sign`, destroy. One session per request.
- `derive`: pure Rust. BIP32 secp256k1 and SLIP10 ed25519 from a seed and a path, with no PKCS#11 knowledge.
- `chains`: the five chain codecs. Decode, summarize, build the signing input. No keys and no PKCS#11.
- `generic`: composes them. Unwrap, derive, load the child key into the HSM, sign, destroy, wipe. If the HSM cannot sign on the curve, it signs in software instead. Secrets live in `Zeroizing` wrappers so every path out wipes them.

**Startup probe (fail closed).** The signer refuses to start, and says why, unless all of these hold:

1. The PKCS#11 library loads and the token is present.
2. `C_GetMechanismList` includes `CKM_AES_GCM`, and a self-test wrap and unwrap round-trips.
3. The KEK is found by label and is `CKA_EXTRACTABLE=false`, `CKA_SENSITIVE=true`, with encrypt and decrypt only.
4. The BIP32 and SLIP10 built-in vectors pass at boot.
5. For each scheme, a self-test loads a throwaway key as a session object, signs, verifies the signature, and destroys the object. A failure marks that scheme as software signing, and the capabilities say so.

**SoftHSM build.** HSM-side signing on ed25519 needs a SoftHSM built with EdDSA, which was added in 2.5.0. I could not confirm that secp256k1 is accepted in `CKA_EC_PARAMS`. Debian packages version 2.6.1. If the packaged build lacks a curve, the signer image builds SoftHSM from a pinned source release. The probe, not an assumption, decides.

The probe result feeds `Capabilities`, which the API publishes at `GET /v1/signer`.

**Configuration.** PKCS#11 module path, slot, user PIN (a Docker secret, never an environment variable), KEK label. A different vendor with only standard mechanisms should work by changing these four values, which is the test of the generic tier's portability.

**Later, native backends.** Each implements `CreateWallet`, `PublicKey` and `Sign` with the vendor derive mechanism, sets `DerivesInHSM` to true and `ProtectionLevel` to `native`. IBM steps through the path with a chain code. Thales sends the whole path in one call.

## 9. Local deployment with Docker Compose

Three services and one setup job run on a laptop with `make bootstrap && make up`. Nothing outside the laptop is needed.

| Service | Image base | Ports | Holds |
| --- | --- | --- | --- |
| `postgres` | postgres:16 | none published | All data, in volume `pgdata` |
| `api` | Go, distroless | `127.0.0.1:8080` published, `8081` internal | No secrets except DB credentials |
| `signer` | Rust, Debian slim with `softhsm2` | none | SoftHSM token (volume `hsm-tokens`), signer identity key, trust config (read-only) |
| `bootstrap` (job) | same image as signer | none | Initializes the token, creates the KEK, generates the signer identity key, then exits |
| `pe-sim` (host tool) | not a container | none | Dev stand-in for the client's policy engine: holds a dev signing key and signs request bodies |

**Networks.** `front` connects the host to the API. `backend` is `internal: true` and connects `api`, `signer` and `postgres`. The signer has no route to the internet, so even a compromised signer cannot send a seed out directly.

**Secrets.** Files under `./secrets` (gitignored), mounted as Docker secrets: SoftHSM user PIN, the two database passwords, the bootstrap API keys. `make bootstrap` generates them.

**Container hardening.** Non-root user, `read_only: true` with a tmpfs for `/tmp`, `cap_drop: [ALL]`, `no-new-privileges`, core dumps off (`ulimit core 0`), memory limits. These are cheap in Compose and make the later production story easier.

**Policy engine stand-in.** `pe-sim keygen --alg ed25519|es256` writes a dev key pair on the host, outside Compose. The public key goes into `signer.yaml` with a key ID and its algorithm, mounted read-only into the signer. `pe-sim sign` takes a request body, canonicalizes it, and returns the authorization in the matching format. In production the client's real policy engine takes this role.

**Repository layout.**

```text
api/                     Go: HTTP API, queue, audit chain
signer/                  Rust: envelope check, derive, chains, backends
  src/envelope  src/derive  src/chains  src/backend/generic  src/pkcs11session
tools/pe-sim             dev policy engine stand-in (Ed25519, ES256)
vectors/                 shared vectors: JCS, BIP32, SLIP10, envelopes, transactions
migrations/  deploy/compose.yaml  dev/
```

**Make targets.** `bootstrap`, `up`, `down`, `test` (unit tests and vectors in both languages), `e2e` (runs against the live stack), `demo` (creates a wallet with a `pe-sim` authorization, derives a key, signs, and verifies the result and the signer's signature).

## 10. Test plan and conformance suite

Tests are written against the `Backend` interface, so the same suite later certifies each vendor adapter. A vendor is listed as compatible only after this suite passes on its hardware or simulator.

| Layer | What is tested | Pass criteria |
| --- | --- | --- |
| Derivation | BIP32 test vectors 1 to 3 and SLIP10 ed25519 vectors 1 and 2, as published in the specs | Exact match on every key |
| Derivation, cross-check | Random paths compared against an independent library (Python `bip_utils`) in CI | No mismatch over 1,000 paths per scheme |
| Wrapping | Tampered blob, wrong AAD, blob from another wallet, missing KEK | Every case fails with no partial output |
| Signing | Signatures made in the HSM and in the software fallback verify with the derived public key. ECDSA signatures are low-S. | Verification succeeds. Repeat signatures need not be identical. |
| HSM hygiene | After each request, including forced failures, `C_FindObjects` on the token lists no session objects | None left |
| Transactions | Published reference transactions for each of the five chains: signing input, summary, signature, and for Ethereum and Tron the recovered address. Bitcoin: the BIP143 and BIP341 published vectors, Bitcoin Core's sighash test data for legacy inputs, and a PSBT mixing all four input types on different paths. Unsupported types and instructions. | All match. Unsupported input is rejected. |
| Canonicalization | Bodies canonicalized and signed by an independent implementation (Python) are verified by the Rust signer | Byte-exact agreement over the shared vectors |
| Authorization formats | Ed25519 and ES256 JWS accepted. Rejected: header `alg` mismatch, `none`, wrong key ID, key outside its validity window. | Each rejected with the right reason code |
| Envelope | Malformed, unknown field, non-canonical bytes, wrong audience, expired, signature over a different body, chain mismatch, digest request while the digest switch is off | Each rejected with the right reason code |
| Forging API | A hostile test API that forges a request, replays an authorized one, edits the path after authorization, swaps the wallet blob, or substitutes a signature from an unpinned key | Signer rejects all, produces no signature |
| Queue | Two signers claiming at once, signer killed mid-request, lease expiry | One claim per request, no double signing, clean final state |
| Probe | Library missing, no AES-GCM, extractable KEK. A SoftHSM build without a curve. | Signer refuses to start for the first three. For a missing curve it starts, marks that scheme as software signing, and says so. |
| End to end | `make demo`: `pe-sim` authorization, derive public key, sign one transfer on each of the five chains, verify the signer's signature on each response | Exit code 0 |

Two notes on limits. Zeroization is checked best-effort (a test scans the signer's memory after a request for the seed bytes), and it is not a proof, because Go's garbage collector can copy values. Timing and side-channel resistance are out of scope for the prototype.

## 11. Milestones, decisions and open questions

Seven milestones, each with a gate that must pass before the next starts. Order matters more than dates, so none are given.

1. **Derivation core.** `derive` module in Rust with BIP32 secp256k1 and SLIP10 ed25519. Gate: all published vectors pass and the cross-check agrees.
2. **HSM wrapping and signing.** `pkcs11session` over the `cryptoki` crate, bootstrap job, AES-GCM wrap and unwrap with AAD, session-object signing, startup probe. Gate: every wrapping and hygiene test passes against SoftHSM in Docker, and the probe reports which curves sign in the HSM.
3. **Chain codecs, in this order.** Ethereum and EVM, Solana, Tron, XRP Ledger, then Bitcoin in full (four input types, PSBT, several paths per request, Taproot Schnorr), which is the most involved. Each codec: decode, summary in the common shape, signing input, signature formatting. Gate per codec: published reference vectors match.
4. **Signer and envelope.** Verification checklist, pinned policy engine keys for both formats, replay table, signed responses, dev and production profiles. Gate: the forging-API harness is fully rejected, and bodies canonicalized by an independent implementation verify.
5. **API and queue (Go).** Submit, status, claim and result routes, Postgres schema, audit chain. Gate: `make demo` passes end to end.
6. **Policy engine stand-in and hardening.** `pe-sim` with both algorithms, container hardening. Gate: a fresh clone reaches a working demo from the README alone.
7. **Conformance packaging.** Run the suite through the `Backend` interface with a selectable backend. Gate: the suite is ready to point at a vendor simulator, starting with Utimaco's.

**Decisions taken (change any of these).**

| Decision | Choice |
| --- | --- |
| Languages | API in Go, signer in Rust (`cryptoki` for PKCS#11) |
| Authorization model | One policy-engine signature per request. No approvals or quorum in this product. |
| Authorization formats | Ed25519 over the body hash, or ES256 as a detached-payload JWS. The algorithm is pinned per key ID. |
| Who builds the request body | The client, signed by its policy engine. The API passes the bytes through untouched. |
| Canonical encoding | JSON Canonicalization, RFC 8785 |
| Where the generic tier signs | In the HSM through PKCS#11, with the child key as a session object. Software fallback per scheme, flagged in every response. |
| Transactions | Five chains are decoded in the signer: Bitcoin (all four single-key input types, Taproot Schnorr signed in software), Ethereum and EVM networks, Solana, Tron and XRP Ledger. Digest signing is behind allow\_digest\_signing: on in the dev profile, off in the production profile. |
| Seed generation and import | Generated in the signer with the HSM's random generator. No import in v1. |
| Wrapping mechanism | AES-GCM, required. SoftHSM supports it since 2.4.0. |

**Open questions.**

None open. The five chains and the Bitcoin scope (all four single-key input types, no multisig or script-path spends) are confirmed. Which curves SoftHSM can sign on is answered by the probe in milestone 2, not by a decision.
