//! Forging-API Adversarial Test Harness (Milestone 4 Gate).
//!
//! Simulates a hostile or compromised API attempting to:
//! (a) Forge an unsigned or self-signed request.
//! (b) Replay an authorized request with a new or same `request_id` / `nonce`.
//! (c) Mutate `path` or `payload` after policy engine signing.
//! (d) Swap `wrapped_seed` between two wallets.
//! (e) Substitute a signature from an unpinned key or wrong `alg`.
//! (f) Submit a digest signing request when `allow_digest_signing` is false.
//!
//! Milestone 4 Gate Verification:
//! - 100% of forging-API attacks are rejected with exact reason codes.
//! - ZERO signatures produced for all rejected attacks.
//! - Valid `create_wallet`, `derive_public`, and `sign` requests produce verifiable signed responses.

use std::sync::Arc;

use chrono::{Duration, Utc};
use ed25519_dalek::{Signer as DalekSigner, SigningKey as Ed25519SigningKey};
use hmac::{Hmac, Mac};
use p256::ecdsa::SigningKey as P256SigningKey;
use sha2::{Digest, Sha256};
use zeroize::Zeroize;

use signer::backend::generic::crypto::{
    postprocess_ed25519_signature, sign_secp256k1_ecdsa_software, sign_taproot_schnorr_software,
};
use signer::backend::{
    Backend, BackendError, Capabilities, Curve, ProtectionLevel, Scheme,
    Signature, SigningInput as BackendSigningInput, SigningLocation, Spec, WalletRef,
    AES_GCM_IV_LEN, AES_GCM_TAG_LEN, DEFAULT_KEK_LABEL, WALLET_SEED_LEN, WRAPPED_SEED_LEN,
};
use signer::derive::{derive_bip32, derive_slip10, DerivationPath};
use signer::envelope::auth::{
    sign_ed25519_authorization, sign_es256_authorization, PinnedKey, PolicyAlg, Profile,
    SignerConfig,
};
use signer::envelope::jcs::{
    encode_base64url, to_canonical_json_bytes, PayloadEncoding, RequestBody, RequestType,
};
use signer::envelope::processor::{
    verify_signer_response, ClaimedWallet, ClaimedWork, EnvelopeProcessor, InMemorySignerStore,
    ReplayStore, SignerIdentity, SignerSubmission,
};

const SIGNER_ID: &str = "signer-local-1";
const PINNED_ED25519_KID: &str = "pe-dev-1";
const PINNED_ES256_KID: &str = "pe-dev-2";
const HARNESS_KEK: &[u8; 32] = b"polyglot-test-harness-kek-32byte";

type HmacSha256 = Hmac<Sha256>;

/// Test cryptographic backend simulating HSM AES-GCM wrapping and session signing.
#[derive(Clone)]
struct HarnessBackend {
    caps: Capabilities,
}

impl HarnessBackend {
    fn new() -> Self {
        Self {
            caps: Capabilities::new_generic(
                "softhsm-generic",
                ProtectionLevel::GenericDev,
                SigningLocation::Hsm,
                SigningLocation::Hsm,
            ),
        }
    }

    /// Simulates AES-256-GCM seed unwrapping with strict AAD authentication.
    fn unwrap_seed_checked(&self, wrapped: &[u8], aad: &[u8]) -> Result<[u8; WALLET_SEED_LEN], BackendError> {
        if wrapped.len() != WRAPPED_SEED_LEN {
            return Err(BackendError::UnwrapFailed(format!(
                "invalid wrapped seed length {}, expected {WRAPPED_SEED_LEN}",
                wrapped.len()
            )));
        }

        let iv = &wrapped[..AES_GCM_IV_LEN];
        let ciphertext = &wrapped[AES_GCM_IV_LEN..AES_GCM_IV_LEN + WALLET_SEED_LEN];
        let tag = &wrapped[AES_GCM_IV_LEN + WALLET_SEED_LEN..];

        // Compute expected tag: HMAC-SHA256(KEK, iv || aad || ciphertext)[..16]
        let mut mac = HmacSha256::new_from_slice(HARNESS_KEK)
            .map_err(|e| BackendError::Crypto(e.to_string()))?;
        mac.update(iv);
        mac.update(aad);
        mac.update(ciphertext);
        let mac_result = mac.finalize().into_bytes();
        let expected_tag = &mac_result[..AES_GCM_TAG_LEN];

        if tag != expected_tag {
            return Err(BackendError::UnwrapFailed(
                "AES-GCM authentication tag mismatch (wrong AAD or corrupted/swapped ciphertext)"
                    .to_string(),
            ));
        }

        // Decrypt ciphertext via XOR stream derived from KEK and IV
        let mut seed = [0u8; WALLET_SEED_LEN];
        let mut mask = Sha256::new();
        mask.update(HARNESS_KEK);
        mask.update(iv);
        let mask1 = mask.finalize();

        let mut mask = Sha256::new();
        mask.update(HARNESS_KEK);
        mask.update(iv);
        mask.update(b"second-block");
        let mask2 = mask.finalize();

        for i in 0..32 {
            seed[i] = ciphertext[i] ^ mask1[i];
            seed[32 + i] = ciphertext[32 + i] ^ mask2[i];
        }

        Ok(seed)
    }
}

impl Backend for HarnessBackend {
    fn capabilities(&self) -> Result<Capabilities, BackendError> {
        Ok(self.caps.clone())
    }

    fn create_wallet(&self, _spec: &Spec, aad: &[u8]) -> Result<Vec<u8>, BackendError> {
        // Generate 64 random bytes for root seed
        let mut rng = p256::elliptic_curve::rand_core::OsRng;
        use p256::elliptic_curve::rand_core::RngCore;
        let mut seed = [0u8; WALLET_SEED_LEN];
        rng.fill_bytes(&mut seed);

        let mut iv = [0u8; AES_GCM_IV_LEN];
        rng.fill_bytes(&mut iv);

        // Encrypt seed via XOR stream
        let mut ciphertext = [0u8; WALLET_SEED_LEN];
        let mut mask = Sha256::new();
        mask.update(HARNESS_KEK);
        mask.update(&iv);
        let mask1 = mask.finalize();

        let mut mask = Sha256::new();
        mask.update(HARNESS_KEK);
        mask.update(&iv);
        mask.update(b"second-block");
        let mask2 = mask.finalize();

        for i in 0..32 {
            ciphertext[i] = seed[i] ^ mask1[i];
            ciphertext[32 + i] = seed[32 + i] ^ mask2[i];
        }
        seed.zeroize();

        // Compute tag with AAD: HMAC-SHA256(KEK, iv || aad || ciphertext)[..16]
        let mut mac = HmacSha256::new_from_slice(HARNESS_KEK)
            .map_err(|e| BackendError::Crypto(e.to_string()))?;
        mac.update(&iv);
        mac.update(aad);
        mac.update(&ciphertext);
        let mac_result = mac.finalize().into_bytes();
        let tag = &mac_result[..AES_GCM_TAG_LEN];

        let mut wrapped = Vec::with_capacity(WRAPPED_SEED_LEN);
        wrapped.extend_from_slice(&iv);
        wrapped.extend_from_slice(&ciphertext);
        wrapped.extend_from_slice(tag);

        Ok(wrapped)
    }

    fn public_key(&self, w: &WalletRef, path: &[u32]) -> Result<Vec<u8>, BackendError> {
        let mut seed = self.unwrap_seed_checked(w.wrapped, w.aad)?;
        let deriv_path = DerivationPath::from_slice(path).map_err(BackendError::Path)?;
        let pubkey = match (w.scheme, w.curve) {
            (Scheme::Bip32, Curve::Secp256k1) => {
                let derived = derive_bip32(&seed, &deriv_path)?;
                derived.public_key().to_vec()
            }
            (Scheme::Slip10, Curve::Ed25519) => {
                let derived = derive_slip10(&seed, &deriv_path)?;
                derived.public_key().to_vec()
            }
            _ => {
                seed.zeroize();
                return Err(BackendError::Crypto(
                    "unsupported scheme/curve combination in test harness".to_string(),
                ));
            }
        };
        seed.zeroize();
        Ok(pubkey)
    }

    fn sign(
        &self,
        w: &WalletRef,
        path: &[u32],
        input: BackendSigningInput,
    ) -> Result<Signature, BackendError> {
        let mut seed = self.unwrap_seed_checked(w.wrapped, w.aad)?;
        let deriv_path = DerivationPath::from_slice(path).map_err(BackendError::Path)?;

        let sig = match (w.scheme, w.curve, input) {
            (Scheme::Bip32, Curve::Secp256k1, BackendSigningInput::TaprootDigest32(d)) => {
                let derived = derive_bip32(&seed, &deriv_path)?;
                sign_taproot_schnorr_software(derived.private_key(), d)?
            }
            (Scheme::Bip32, Curve::Secp256k1, BackendSigningInput::Digest32(d)) => {
                let derived = derive_bip32(&seed, &deriv_path)?;
                sign_secp256k1_ecdsa_software(derived.private_key(), d)?
            }
            (Scheme::Slip10, Curve::Ed25519, BackendSigningInput::Message(msg)) => {
                let derived = derive_slip10(&seed, &deriv_path)?;
                let signing_key = Ed25519SigningKey::from_bytes(derived.private_key());
                let raw_sig = signing_key.sign(msg).to_bytes();
                postprocess_ed25519_signature(&raw_sig, msg, derived.public_key(), true)?
            }
            _ => {
                seed.zeroize();
                return Err(BackendError::InvalidSigningInput {
                    scheme: w.scheme,
                    curve: w.curve,
                    reason: "unsupported scheme/curve/input combination in test harness".to_string(),
                });
            }
        };

        seed.zeroize();
        Ok(sig)
    }
}


/// Test harness containing configured signer, policy engine keys, and in-memory store.
struct TestHarness {
    processor_dev: EnvelopeProcessor,
    processor_prod: EnvelopeProcessor,
    pe_ed25519_key: Ed25519SigningKey,
    pe_es256_key: P256SigningKey,
    signer_identity: SignerIdentity,
    store_dev: Arc<InMemorySignerStore>,
    store_prod: Arc<InMemorySignerStore>,
}

fn setup_test_harness() -> TestHarness {
    // 1. Generate policy engine keys
    let mut rng = p256::elliptic_curve::rand_core::OsRng;
    let pe_ed25519_key = Ed25519SigningKey::generate(&mut rng);
    let pe_ed25519_pub = pe_ed25519_key.verifying_key().to_bytes();

    let pe_es256_key = P256SigningKey::random(&mut rng);
    let pe_es256_pub = pe_es256_key.verifying_key().to_encoded_point(false);

    // Expired and future keypairs for testing validity windows
    let pe_expired_key = Ed25519SigningKey::generate(&mut rng);
    let pe_future_key = Ed25519SigningKey::generate(&mut rng);

    let pinned_keys = vec![
        PinnedKey {
            kid: PINNED_ED25519_KID.to_string(),
            alg: PolicyAlg::Ed25519,
            public_key: hex::encode(pe_ed25519_pub),
            not_before: None,
            not_after: None,
        },
        PinnedKey {
            kid: PINNED_ES256_KID.to_string(),
            alg: PolicyAlg::Es256,
            public_key: hex::encode(pe_es256_pub.as_bytes()),
            not_before: None,
            not_after: None,
        },
        PinnedKey {
            kid: "pe-expired-1".to_string(),
            alg: PolicyAlg::Ed25519,
            public_key: hex::encode(pe_expired_key.verifying_key().to_bytes()),
            not_before: Some("2020-01-01T00:00:00Z".to_string()),
            not_after: Some("2021-01-01T00:00:00Z".to_string()), // Past
        },
        PinnedKey {
            kid: "pe-future-1".to_string(),
            alg: PolicyAlg::Ed25519,
            public_key: hex::encode(pe_future_key.verifying_key().to_bytes()),
            not_before: Some("2099-01-01T00:00:00Z".to_string()), // Future
            not_after: Some("2100-01-01T00:00:00Z".to_string()),
        },
    ];

    let mut dev_cfg = SignerConfig::new(SIGNER_ID, Profile::Dev);
    dev_cfg.policy_engine_keys = pinned_keys.clone();
    dev_cfg.allow_digest_signing = Some(true);

    let mut prod_cfg = SignerConfig::new(SIGNER_ID, Profile::Prod);
    prod_cfg.policy_engine_keys = pinned_keys;
    prod_cfg.allow_digest_signing = Some(false);

    let backend = Arc::new(HarnessBackend::new());
    let signer_identity = SignerIdentity::generate();

    let store_dev = Arc::new(InMemorySignerStore::new());
    let store_prod = Arc::new(InMemorySignerStore::new());

    let processor_dev = EnvelopeProcessor::new(
        dev_cfg,
        backend.clone(),
        store_dev.clone(),
        signer_identity.clone(),
    );
    let processor_prod = EnvelopeProcessor::new(
        prod_cfg,
        backend,
        store_prod.clone(),
        signer_identity.clone(),
    );

    TestHarness {
        processor_dev,
        processor_prod,
        pe_ed25519_key,
        pe_es256_key,
        signer_identity,
        store_dev,
        store_prod,
    }
}

/// Helper to build and sign [`ClaimedWork`] using Ed25519 policy engine key.
fn build_claimed_work_ed25519(
    harness: &TestHarness,
    body: &RequestBody,
    wallet: Option<ClaimedWallet>,
) -> ClaimedWork {
    let canonical_bytes = to_canonical_json_bytes(body).expect("canonicalize body");
    let body_b64url = encode_base64url(&canonical_bytes);
    let raw_auth =
        sign_ed25519_authorization(&harness.pe_ed25519_key, PINNED_ED25519_KID, &canonical_bytes);

    ClaimedWork {
        request_id: body.request_id.clone(),
        body_canonical: body_b64url,
        authorization: serde_json::to_value(&raw_auth).expect("serialize auth"),
        label: Some("test-label".to_string()),
        wallet,
    }
}

/// Helper to build and sign [`ClaimedWork`] using ES256 policy engine key.
fn build_claimed_work_es256(
    harness: &TestHarness,
    body: &RequestBody,
    wallet: Option<ClaimedWallet>,
) -> ClaimedWork {
    let canonical_bytes = to_canonical_json_bytes(body).expect("canonicalize body");
    let body_b64url = encode_base64url(&canonical_bytes);
    let raw_auth =
        sign_es256_authorization(&harness.pe_es256_key, PINNED_ES256_KID, &canonical_bytes);

    ClaimedWork {
        request_id: body.request_id.clone(),
        body_canonical: body_b64url,
        authorization: serde_json::to_value(&raw_auth).expect("serialize auth"),
        label: Some("test-label".to_string()),
        wallet,
    }
}

/// Helper to build sample valid RequestBody.
fn sample_request_body(
    request_type: RequestType,
    request_id: &str,
    nonce: &str,
    wallet_id: &str,
) -> RequestBody {
    let now = Utc::now();
    let expires_at = (now + Duration::minutes(5)).to_rfc3339_opts(chrono::SecondsFormat::Secs, true);

    RequestBody {
        v: 1,
        request_type,
        request_id: request_id.to_string(),
        nonce: nonce.to_string(),
        audience: SIGNER_ID.to_string(),
        expires_at,
        decision_id: format!("dec-{request_id}"),
        wallet_id: wallet_id.to_string(),
        scheme: Scheme::Bip32,
        curve: Curve::Secp256k1,
        path: Some(vec![2147483692, 2147483708, 2147483648, 0, 0]), // m/44'/60'/0'/0/0
        input_paths: None,
        payload_encoding: None,
        payload: None,
        chain: None,
        seed_version: Some(1),
        kek_label: Some(DEFAULT_KEK_LABEL.to_string()),
    }
}

/// Asserts that a submission represents a rejection and produced ZERO signatures.
fn assert_rejected_with_zero_signatures(sub: &SignerSubmission, expected_reason: &str) {
    assert_eq!(
        sub.status, "failed",
        "expected failed status, got {}",
        sub.status
    );
    assert!(
        sub.response.is_none(),
        "CRITICAL SECURITY VIOLATION: response was produced on rejected request!"
    );
    assert!(
        sub.response_sig.is_none(),
        "CRITICAL SECURITY VIOLATION: signer signature was produced on rejected request!"
    );
    assert_eq!(
        sub.reason_code.as_deref(),
        Some(expected_reason),
        "reason code mismatch: expected '{expected_reason}', got '{:?}'",
        sub.reason_code
    );
}

// =============================================================================
// 1. VALID BASELINE OPERATIONS (Milestone 4 Gate Requirement)
// =============================================================================

#[test]
fn test_valid_create_wallet_derive_public_and_sign_produce_verifiable_signed_responses() {
    let harness = setup_test_harness();
    let now = Utc::now();

    // 1. Valid create_wallet (BIP32 / secp256k1)
    let create_body = sample_request_body(
        RequestType::CreateWallet,
        "11111111-1111-1111-1111-111111111111",
        "0123456789abcdef0123456789abcdef",
        "w-test-wallet-1",
    );
    let claimed_create = build_claimed_work_ed25519(&harness, &create_body, None);

    let create_sub = harness
        .processor_dev
        .process_claimed_work(&claimed_create, Some(now))
        .expect("valid create_wallet must succeed");

    assert_eq!(create_sub.status, "completed");
    assert!(create_sub.response.is_some());
    assert!(create_sub.response_sig.is_some());
    assert!(create_sub.wallet.is_some());

    let created_wallet = create_sub.wallet.unwrap();
    assert_eq!(created_wallet.wallet_id, "w-test-wallet-1");
    assert!(!created_wallet.wrapped_seed.is_empty());

    let resp = create_sub.response.unwrap();
    let resp_sig = create_sub.response_sig.unwrap();

    // Verify signer's Ed25519 identity signature over canonical response
    verify_signer_response(&harness.signer_identity.public_key(), &resp, &resp_sig)
        .expect("signer signature must verify");

    // 2. Valid derive_public using the created wallet
    let mut derive_body = sample_request_body(
        RequestType::DerivePublic,
        "22222222-2222-2222-2222-222222222222",
        "11223344556677881122334455667788",
        "w-test-wallet-1",
    );
    derive_body.path = Some(vec![2147483692, 2147483708, 2147483648, 0, 0]);

    let claimed_wallet = ClaimedWallet {
        wallet_id: created_wallet.wallet_id.clone(),
        label: created_wallet.label.clone(),
        scheme: created_wallet.scheme,
        curve: created_wallet.curve,
        seed_version: created_wallet.seed_version,
        kek_label: created_wallet.kek_label.clone(),
        wrapped_seed: created_wallet.wrapped_seed.clone(),
    };

    let claimed_derive =
        build_claimed_work_ed25519(&harness, &derive_body, Some(claimed_wallet.clone()));
    let derive_sub = harness
        .processor_dev
        .process_claimed_work(&claimed_derive, Some(now))
        .expect("valid derive_public must succeed");

    assert_eq!(derive_sub.status, "completed");
    let derive_resp = derive_sub.response.unwrap();
    let derive_sig = derive_sub.response_sig.unwrap();

    verify_signer_response(
        &harness.signer_identity.public_key(),
        &derive_resp,
        &derive_sig,
    )
    .expect("derive_public response signature must verify");
    assert!(derive_resp.result.get("public_key").is_some());

    // 3. Valid blind digest signing in dev profile (allow_digest_signing == true)
    let mut digest_body = sample_request_body(
        RequestType::Sign,
        "33333333-3333-3333-3333-333333333333",
        "22334455667788992233445566778899",
        "w-test-wallet-1",
    );
    digest_body.payload_encoding = Some(PayloadEncoding::Digest);
    digest_body.payload =
        Some("9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08".to_string());

    let claimed_digest =
        build_claimed_work_ed25519(&harness, &digest_body, Some(claimed_wallet.clone()));
    let digest_sub = harness
        .processor_dev
        .process_claimed_work(&claimed_digest, Some(now))
        .expect("valid digest signing must succeed in dev profile");

    assert_eq!(digest_sub.status, "completed");
    let digest_resp = digest_sub.response.unwrap();
    let digest_sig = digest_sub.response_sig.unwrap();

    assert!(digest_resp.blind_sign);
    verify_signer_response(
        &harness.signer_identity.public_key(),
        &digest_resp,
        &digest_sig,
    )
    .expect("digest response signature must verify");

    // 4. Verify audit entries were logged into the store
    assert_eq!(
        harness.store_dev.verify_audit_chain().expect("audit chain"),
        3
    );
}

#[test]
fn test_valid_es256_authorization_in_prod_profile() {
    let harness = setup_test_harness();
    let now = Utc::now();

    let create_body = sample_request_body(
        RequestType::CreateWallet,
        "44444444-4444-4444-4444-444444444444",
        "aabbccddeeff00112233445566778899",
        "w-prod-wallet-1",
    );
    let claimed_create = build_claimed_work_es256(&harness, &create_body, None);

    let create_sub = harness
        .processor_prod
        .process_claimed_work(&claimed_create, Some(now))
        .expect("valid ES256 create_wallet must succeed in prod");

    assert_eq!(create_sub.status, "completed");
    assert!(create_sub.response.is_some());
    assert!(create_sub.response_sig.is_some());
    let resp = create_sub.response.unwrap();
    let resp_sig = create_sub.response_sig.unwrap();

    verify_signer_response(&harness.signer_identity.public_key(), &resp, &resp_sig)
        .expect("signer signature must verify");

    assert_eq!(
        harness.store_prod.verify_audit_chain().expect("audit chain"),
        1
    );
}

// =============================================================================
// 2. ATTACK (a): FORGE UNSIGNED OR SELF-SIGNED REQUEST
// =============================================================================

#[test]
fn test_attack_a_reject_unsigned_or_self_signed_request() {
    let harness = setup_test_harness();
    let now = Utc::now();

    let body = sample_request_body(
        RequestType::CreateWallet,
        "aaaaaaaa-1111-1111-1111-111111111111",
        "00112233445566778899aabbccddeeff",
        "w-forge-1",
    );
    let canonical_bytes = to_canonical_json_bytes(&body).expect("canonicalize");
    let body_b64url = encode_base64url(&canonical_bytes);

    // Case 1: Completely missing signature / malformed authorization
    let bad_auth_claimed = ClaimedWork {
        request_id: body.request_id.clone(),
        body_canonical: body_b64url.clone(),
        authorization: serde_json::json!({
            "kid": PINNED_ED25519_KID,
            "alg": "ed25519"
            // Missing "sig"
        }),
        label: None,
        wallet: None,
    };
    let sub1 = harness
        .processor_dev
        .process_and_submit(&bad_auth_claimed, Some(now));
    assert_rejected_with_zero_signatures(&sub1, "bad_signature");

    // Case 2: Self-signed request with attacker's unauthorized Ed25519 key (kid not pinned)
    let mut rng = p256::elliptic_curve::rand_core::OsRng;
    let attacker_ed_key = Ed25519SigningKey::generate(&mut rng);
    let attacker_auth =
        sign_ed25519_authorization(&attacker_ed_key, "attacker-key-id", &canonical_bytes);

    let self_signed_claimed = ClaimedWork {
        request_id: body.request_id.clone(),
        body_canonical: body_b64url.clone(),
        authorization: serde_json::to_value(&attacker_auth).unwrap(),
        label: None,
        wallet: None,
    };
    let sub2 = harness
        .processor_dev
        .process_and_submit(&self_signed_claimed, Some(now));
    assert_rejected_with_zero_signatures(&sub2, "unknown_kid");

    // Case 3: Attacker claims kid="pe-dev-1" but signs with their own private key
    let forged_key_auth =
        sign_ed25519_authorization(&attacker_ed_key, PINNED_ED25519_KID, &canonical_bytes);
    let forged_claimed = ClaimedWork {
        request_id: body.request_id.clone(),
        body_canonical: body_b64url,
        authorization: serde_json::to_value(&forged_key_auth).unwrap(),
        label: None,
        wallet: None,
    };
    let sub3 = harness
        .processor_dev
        .process_and_submit(&forged_claimed, Some(now));
    assert_rejected_with_zero_signatures(&sub3, "bad_signature");
}

// =============================================================================
// 3. ATTACK (b): REPLAY AN AUTHORIZED REQUEST
// =============================================================================

#[test]
fn test_attack_b_replay_authorized_request() {
    let harness = setup_test_harness();
    let now = Utc::now();

    let body = sample_request_body(
        RequestType::CreateWallet,
        "bbbbbbbb-1111-1111-1111-111111111111",
        "aabbccddeeff00112233445566778899",
        "w-replay-1",
    );
    let claimed = build_claimed_work_ed25519(&harness, &body, None);

    // Initial valid submission
    let first_sub = harness
        .processor_dev
        .process_claimed_work(&claimed, Some(now))
        .expect("initial submission succeeds");
    assert_eq!(first_sub.status, "completed");
    let original_sig = first_sub.response_sig.clone().unwrap();

    // Attack b.1: Replay completed request with exact same request_id and nonce
    // Must return the cached signed result without executing again or creating new signatures
    let replay_cached_sub = harness
        .processor_dev
        .process_claimed_work(&claimed, Some(now))
        .expect("replay of completed request returns cached result");
    assert_eq!(replay_cached_sub.status, "completed");
    assert_eq!(replay_cached_sub.response_sig.unwrap(), original_sig);

    // Attack b.2: Replay with duplicate request_id that was recorded in replay table WITHOUT stored result
    // (e.g. signer crashed between step 5 and step 9)
    let crashed_req_id = "bbbbbbbb-2222-2222-2222-222222222222";
    let crashed_nonce = "crashednonce1234crashednonce1234";
    harness
        .store_dev
        .check_or_record_replay(crashed_req_id, crashed_nonce)
        .expect("record in replay table");

    let crashed_body = sample_request_body(
        RequestType::CreateWallet,
        crashed_req_id,
        crashed_nonce,
        "w-crashed-1",
    );
    let crashed_claimed = build_claimed_work_ed25519(&harness, &crashed_body, None);

    let sub_crashed = harness
        .processor_dev
        .process_and_submit(&crashed_claimed, Some(now));
    assert_rejected_with_zero_signatures(&sub_crashed, "replayed");

    // Attack b.3: New request_id but reusing a previously seen nonce
    let reused_nonce_body = sample_request_body(
        RequestType::CreateWallet,
        "bbbbbbbb-3333-3333-3333-333333333333",
        &body.nonce, // Reused nonce from first completed request
        "w-replay-nonce",
    );
    let reused_nonce_claimed =
        build_claimed_work_ed25519(&harness, &reused_nonce_body, None);
    let sub_nonce_replay = harness
        .processor_dev
        .process_and_submit(&reused_nonce_claimed, Some(now));
    assert_rejected_with_zero_signatures(&sub_nonce_replay, "replayed");
}

// =============================================================================
// 4. ATTACK (c): MUTATE PATH OR PAYLOAD AFTER POLICY ENGINE SIGNING
// =============================================================================

#[test]
fn test_attack_c_mutate_path_or_payload_after_policy_signing() {
    let harness = setup_test_harness();
    let now = Utc::now();

    // Create a wallet first
    let create_body = sample_request_body(
        RequestType::CreateWallet,
        "cccccccc-0000-0000-0000-000000000000",
        "00001111222233334444555566667777",
        "w-mutate-test",
    );
    let claimed_create = build_claimed_work_ed25519(&harness, &create_body, None);
    let created = harness
        .processor_dev
        .process_claimed_work(&claimed_create, Some(now))
        .unwrap();
    let wallet_data = created.wallet.unwrap();
    let claimed_wallet = ClaimedWallet {
        wallet_id: wallet_data.wallet_id,
        label: wallet_data.label,
        scheme: wallet_data.scheme,
        curve: wallet_data.curve,
        seed_version: wallet_data.seed_version,
        kek_label: wallet_data.kek_label,
        wrapped_seed: wallet_data.wrapped_seed,
    };

    // Client builds and policy engine signs request with path = m/44'/60'/0'/0/0
    let mut original_body = sample_request_body(
        RequestType::DerivePublic,
        "cccccccc-1111-1111-1111-111111111111",
        "11112222333344445555666677778888",
        "w-mutate-test",
    );
    original_body.path = Some(vec![2147483692, 2147483708, 2147483648, 0, 0]);

    let canonical_original = to_canonical_json_bytes(&original_body).unwrap();
    let original_auth = sign_ed25519_authorization(
        &harness.pe_ed25519_key,
        PINNED_ED25519_KID,
        &canonical_original,
    );

    // Attack c.1: Hostile API mutates path in the body (e.g. index 0 -> 5)
    let mut tampered_body = original_body.clone();
    tampered_body.path = Some(vec![2147483692, 2147483708, 2147483648, 0, 5]);
    let tampered_bytes = to_canonical_json_bytes(&tampered_body).unwrap();
    let tampered_b64 = encode_base64url(&tampered_bytes);

    let attack_path_claimed = ClaimedWork {
        request_id: tampered_body.request_id.clone(),
        body_canonical: tampered_b64,
        authorization: serde_json::to_value(&original_auth).unwrap(), // original authorization
        label: None,
        wallet: Some(claimed_wallet.clone()),
    };

    let sub_path = harness
        .processor_dev
        .process_and_submit(&attack_path_claimed, Some(now));
    assert_rejected_with_zero_signatures(&sub_path, "bad_signature");

    // Attack c.2: Hostile API mutates payload in a transaction request
    let mut tx_body = sample_request_body(
        RequestType::Sign,
        "cccccccc-2222-2222-2222-222222222222",
        "22223333444455556666777788889999",
        "w-mutate-test",
    );
    tx_body.payload_encoding = Some(PayloadEncoding::Tx);
    tx_body.chain = Some("eip155:1".to_string());
    tx_body.payload = Some("0x02f00105...".to_string());

    let canonical_tx = to_canonical_json_bytes(&tx_body).unwrap();
    let tx_auth =
        sign_ed25519_authorization(&harness.pe_ed25519_key, PINNED_ED25519_KID, &canonical_tx);

    let mut tampered_tx_body = tx_body.clone();
    tampered_tx_body.payload = Some("0x02f00106...".to_string()); // Mutated payload
    let tampered_tx_bytes = to_canonical_json_bytes(&tampered_tx_body).unwrap();
    let tampered_tx_b64 = encode_base64url(&tampered_tx_bytes);

    let attack_payload_claimed = ClaimedWork {
        request_id: tampered_tx_body.request_id.clone(),
        body_canonical: tampered_tx_b64,
        authorization: serde_json::to_value(&tx_auth).unwrap(),
        label: None,
        wallet: Some(claimed_wallet),
    };

    let sub_payload = harness
        .processor_dev
        .process_and_submit(&attack_payload_claimed, Some(now));
    assert_rejected_with_zero_signatures(&sub_payload, "bad_signature");

    // Attack c.3: Non-canonical JSON formatting injected by API
    let non_canonical_json = format!(
        "{{\"v\": 1,  \"type\": \"create_wallet\", \"request_id\": \"{}\", \"nonce\": \"{}\", \"audience\": \"{}\", \"expires_at\": \"{}\", \"decision_id\": \"dec-1\", \"wallet_id\": \"w-nc\", \"scheme\": \"bip32\", \"curve\": \"secp256k1\"}}",
        "cccccccc-3333-3333-3333-333333333333",
        "33334444555566667777888899990000",
        SIGNER_ID,
        (now + Duration::minutes(5)).to_rfc3339()
    );
    let nc_b64 = encode_base64url(non_canonical_json.as_bytes());
    let nc_claimed = ClaimedWork {
        request_id: "cccccccc-3333-3333-3333-333333333333".to_string(),
        body_canonical: nc_b64,
        authorization: serde_json::to_value(&original_auth).unwrap(),
        label: None,
        wallet: None,
    };
    let sub_nc = harness
        .processor_dev
        .process_and_submit(&nc_claimed, Some(now));
    assert_rejected_with_zero_signatures(&sub_nc, "non_canonical_body");
}

// =============================================================================
// 5. ATTACK (d): SWAP WRAPPED SEED BETWEEN TWO WALLETS
// =============================================================================

#[test]
fn test_attack_d_swap_wrapped_seed_between_two_wallets() {
    let harness = setup_test_harness();
    let now = Utc::now();

    // 1. Create Wallet Alpha
    let body_alpha = sample_request_body(
        RequestType::CreateWallet,
        "dddddddd-1111-1111-1111-111111111111",
        "aaaa1111bbbb2222cccc3333dddd4444",
        "w-wallet-alpha",
    );
    let claimed_alpha = build_claimed_work_ed25519(&harness, &body_alpha, None);
    let sub_alpha = harness
        .processor_dev
        .process_claimed_work(&claimed_alpha, Some(now))
        .unwrap();
    let _wallet_alpha = sub_alpha.wallet.unwrap();

    // 2. Create Wallet Beta
    let body_beta = sample_request_body(
        RequestType::CreateWallet,
        "dddddddd-2222-2222-2222-222222222222",
        "bbbb2222cccc3333dddd4444eeee5555",
        "w-wallet-beta",
    );
    let claimed_beta = build_claimed_work_ed25519(&harness, &body_beta, None);
    let sub_beta = harness
        .processor_dev
        .process_claimed_work(&claimed_beta, Some(now))
        .unwrap();
    let wallet_beta = sub_beta.wallet.unwrap();

    // 3. Client authorizes a derive_public request bound to Wallet Alpha ("w-wallet-alpha")
    let mut derive_alpha_body = sample_request_body(
        RequestType::DerivePublic,
        "dddddddd-3333-3333-3333-333333333333",
        "cccc3333dddd4444eeee5555ffff6666",
        "w-wallet-alpha",
    );
    derive_alpha_body.path = Some(vec![2147483692, 2147483708, 2147483648, 0, 0]);

    // Hostile API swaps wrapped_seed: passes Wallet Beta's wrapped_seed for Wallet Alpha's request
    let swapped_wallet = ClaimedWallet {
        wallet_id: "w-wallet-alpha".to_string(), // Spoofed ID in DB
        label: "spoofed-label".to_string(),
        scheme: wallet_beta.scheme,
        curve: wallet_beta.curve,
        seed_version: wallet_beta.seed_version,
        kek_label: wallet_beta.kek_label,
        wrapped_seed: wallet_beta.wrapped_seed.clone(), // SEED FROM WALLET BETA
    };

    let attack_swap_claimed =
        build_claimed_work_ed25519(&harness, &derive_alpha_body, Some(swapped_wallet));

    // Signer builds AAD strictly from the signed body ("w-wallet-alpha|...").
    // Attempting to unwrap Wallet Beta's ciphertext under Wallet Alpha's AAD MUST fail AES-GCM tag verification!
    let sub_swap = harness
        .processor_dev
        .process_and_submit(&attack_swap_claimed, Some(now));
    assert_rejected_with_zero_signatures(&sub_swap, "aead_mismatch");
}

// =============================================================================
// 6. ATTACK (e): SUBSTITUTE SIGNATURE FROM UNPINNED KEY OR WRONG ALG
// =============================================================================

#[test]
fn test_attack_e_substitute_unpinned_key_wrong_alg_or_expired_key() {
    let harness = setup_test_harness();
    let now = Utc::now();

    let body = sample_request_body(
        RequestType::CreateWallet,
        "eeeeeeee-1111-1111-1111-111111111111",
        "12341234123412341234123412341234",
        "w-subst-1",
    );
    let canonical_bytes = to_canonical_json_bytes(&body).unwrap();
    let body_b64 = encode_base64url(&canonical_bytes);

    // Case 1: Pinned key "pe-dev-1" is ed25519, but API provides alg: "ES256"
    let mismatched_alg_auth = serde_json::json!({
        "kid": PINNED_ED25519_KID,
        "alg": "ES256",
        "jws": "header..sig"
    });
    let claimed1 = ClaimedWork {
        request_id: body.request_id.clone(),
        body_canonical: body_b64.clone(),
        authorization: mismatched_alg_auth,
        label: None,
        wallet: None,
    };
    let sub1 = harness.processor_dev.process_and_submit(&claimed1, Some(now));
    assert_rejected_with_zero_signatures(&sub1, "alg_mismatch");

    // Case 2: Pinned key "pe-dev-2" is ES256, but API provides alg: "ed25519"
    let mismatched_alg_auth2 = serde_json::json!({
        "kid": PINNED_ES256_KID,
        "alg": "ed25519",
        "sig": "some-base64url-sig"
    });
    let claimed2 = ClaimedWork {
        request_id: body.request_id.clone(),
        body_canonical: body_b64.clone(),
        authorization: mismatched_alg_auth2,
        label: None,
        wallet: None,
    };
    let sub2 = harness.processor_dev.process_and_submit(&claimed2, Some(now));
    assert_rejected_with_zero_signatures(&sub2, "alg_mismatch");

    // Case 3: JWS protected header with alg: "none"
    let none_jws = format!(
        "{}..{}",
        encode_base64url(b"{\"alg\":\"none\"}"),
        encode_base64url(&[0u8; 64])
    );
    let none_auth = serde_json::json!({
        "kid": PINNED_ES256_KID,
        "alg": "ES256",
        "jws": none_jws
    });
    let claimed3 = ClaimedWork {
        request_id: body.request_id.clone(),
        body_canonical: body_b64.clone(),
        authorization: none_auth,
        label: None,
        wallet: None,
    };
    let sub3 = harness.processor_dev.process_and_submit(&claimed3, Some(now));
    assert_rejected_with_zero_signatures(&sub3, "alg_mismatch");

    // Case 4: Key used outside its validity window (expired key "pe-expired-1")
    let expired_auth = serde_json::json!({
        "kid": "pe-expired-1",
        "alg": "ed25519",
        "sig": encode_base64url(&[0u8; 64])
    });
    let claimed4 = ClaimedWork {
        request_id: body.request_id.clone(),
        body_canonical: body_b64.clone(),
        authorization: expired_auth,
        label: None,
        wallet: None,
    };
    let sub4 = harness.processor_dev.process_and_submit(&claimed4, Some(now));
    assert_rejected_with_zero_signatures(&sub4, "key_expired");

    // Case 5: Key used before not_before (future key "pe-future-1")
    let future_auth = serde_json::json!({
        "kid": "pe-future-1",
        "alg": "ed25519",
        "sig": encode_base64url(&[0u8; 64])
    });
    let claimed5 = ClaimedWork {
        request_id: body.request_id.clone(),
        body_canonical: body_b64,
        authorization: future_auth,
        label: None,
        wallet: None,
    };
    let sub5 = harness.processor_dev.process_and_submit(&claimed5, Some(now));
    assert_rejected_with_zero_signatures(&sub5, "key_expired");
}

// =============================================================================
// 7. ATTACK (f): SUBMIT DIGEST SIGNING WHEN ALLOW_DIGEST_SIGNING IS FALSE
// =============================================================================

#[test]
fn test_attack_f_reject_digest_signing_when_allow_digest_signing_is_false() {
    let harness = setup_test_harness();
    let now = Utc::now();

    // Create wallet in prod processor
    let create_body = sample_request_body(
        RequestType::CreateWallet,
        "fffffffe-0000-0000-0000-000000000000",
        "00000000111111112222222233333333",
        "w-prod-wallet",
    );
    let claimed_create = build_claimed_work_ed25519(&harness, &create_body, None);
    let created = harness
        .processor_prod
        .process_claimed_work(&claimed_create, Some(now))
        .unwrap();
    let wallet_data = created.wallet.unwrap();
    let claimed_wallet = ClaimedWallet {
        wallet_id: wallet_data.wallet_id,
        label: wallet_data.label,
        scheme: wallet_data.scheme,
        curve: wallet_data.curve,
        seed_version: wallet_data.seed_version,
        kek_label: wallet_data.kek_label,
        wrapped_seed: wallet_data.wrapped_seed,
    };

    // Case 1: Submit payload_encoding == "digest" in prod profile
    let mut digest_body = sample_request_body(
        RequestType::Sign,
        "ffffffff-1111-1111-1111-111111111111",
        "11111111222222223333333344444444",
        "w-prod-wallet",
    );
    digest_body.payload_encoding = Some(PayloadEncoding::Digest);
    digest_body.payload =
        Some("9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08".to_string());

    let claimed_digest =
        build_claimed_work_ed25519(&harness, &digest_body, Some(claimed_wallet.clone()));
    let sub_digest = harness
        .processor_prod
        .process_and_submit(&claimed_digest, Some(now));
    assert_rejected_with_zero_signatures(&sub_digest, "digest_signing_disabled");

    // Case 2: Submit payload_encoding == "message" in prod profile
    let mut msg_body = sample_request_body(
        RequestType::Sign,
        "ffffffff-2222-2222-2222-222222222222",
        "22222222333333334444444455555555",
        "w-prod-wallet",
    );
    msg_body.payload_encoding = Some(PayloadEncoding::Message);
    msg_body.payload = Some("hello-prod-world".to_string());

    let claimed_msg =
        build_claimed_work_ed25519(&harness, &msg_body, Some(claimed_wallet));
    let sub_msg = harness
        .processor_prod
        .process_and_submit(&claimed_msg, Some(now));
    assert_rejected_with_zero_signatures(&sub_msg, "digest_signing_disabled");
}

// =============================================================================
// 8. ADDITIONAL CHECKLIST STEPS (1, 2, 3, 6, 7) REJECTIONS
// =============================================================================

#[test]
fn test_checklist_audience_expiry_lifetime_and_version_rejections() {
    let harness = setup_test_harness();
    let now = Utc::now();

    // Step 1: Unknown version (v == 2)
    let mut v2_body = sample_request_body(
        RequestType::CreateWallet,
        "12345678-0000-0000-0000-000000000001",
        "99998888777766665555444433332222",
        "w-v2",
    );
    v2_body.v = 2;
    let claimed_v2 = build_claimed_work_ed25519(&harness, &v2_body, None);
    let sub_v2 = harness
        .processor_dev
        .process_and_submit(&claimed_v2, Some(now));
    assert_rejected_with_zero_signatures(&sub_v2, "unknown_version");

    // Step 2: Audience mismatch
    let mut aud_body = sample_request_body(
        RequestType::CreateWallet,
        "12345678-0000-0000-0000-000000000002",
        "88887777666655554444333322221111",
        "w-aud",
    );
    aud_body.audience = "signer-evil".to_string();
    let claimed_aud = build_claimed_work_ed25519(&harness, &aud_body, None);
    let sub_aud = harness
        .processor_dev
        .process_and_submit(&claimed_aud, Some(now));
    assert_rejected_with_zero_signatures(&sub_aud, "audience_mismatch");

    // Step 3: Expired request (expires_at in the past beyond clock skew)
    let mut exp_body = sample_request_body(
        RequestType::CreateWallet,
        "12345678-0000-0000-0000-000000000003",
        "77776666555544443333222211110000",
        "w-exp",
    );
    exp_body.expires_at = (now - Duration::seconds(60)).to_rfc3339();
    let claimed_exp = build_claimed_work_ed25519(&harness, &exp_body, None);
    let sub_exp = harness
        .processor_dev
        .process_and_submit(&claimed_exp, Some(now));
    assert_rejected_with_zero_signatures(&sub_exp, "request_expired");

    // Step 3: Lifetime exceeds maximum allowed (e.g. 15 minutes in the future when max is 10 min)
    let mut life_body = sample_request_body(
        RequestType::CreateWallet,
        "12345678-0000-0000-0000-000000000004",
        "66665555444433332222111100009999",
        "w-life",
    );
    life_body.expires_at = (now + Duration::minutes(15)).to_rfc3339();
    let claimed_life = build_claimed_work_ed25519(&harness, &life_body, None);
    let sub_life = harness
        .processor_dev
        .process_and_submit(&claimed_life, Some(now));
    assert_rejected_with_zero_signatures(&sub_life, "invalid_lifetime");

    // Step 6: Non-hardened index in SLIP10 derivation path
    let mut slip_body = sample_request_body(
        RequestType::CreateWallet,
        "12345678-0000-0000-0000-000000000005",
        "55554444333322221111000099998888",
        "w-slip-non-hardened",
    );
    slip_body.scheme = Scheme::Slip10;
    slip_body.curve = Curve::Ed25519;
    slip_body.path = Some(vec![2147483692, 0]); // Index 0 is NOT hardened
    let claimed_slip = build_claimed_work_ed25519(&harness, &slip_body, None);
    let sub_slip = harness
        .processor_dev
        .process_and_submit(&claimed_slip, Some(now));
    assert_rejected_with_zero_signatures(&sub_slip, "invalid_path");
}
