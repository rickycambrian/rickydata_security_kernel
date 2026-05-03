use base64::{engine::general_purpose::STANDARD as BASE64, Engine as _};
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::io::Read;

const VERSION: &str = env!("CARGO_PKG_VERSION");
const POLICY_VERSION: &str = "secret-release-v1";

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct TrustDecisionRequest {
    mode: String,
    enforce_degraded: bool,
    snapshot: TrustSnapshot,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
struct TrustSnapshot {
    state: String,
    #[serde(default)]
    reason_code: Option<String>,
    #[serde(default)]
    detail: Option<String>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct TrustDecision {
    version: &'static str,
    allowed: bool,
    would_block_if_fail_closed: bool,
    state: String,
    reason_code: String,
    detail: Option<String>,
    policy_version: &'static str,
}

fn read_stdin_json() -> Result<Value, String> {
    let mut raw = String::new();
    std::io::stdin()
        .read_to_string(&mut raw)
        .map_err(|err| err.to_string())?;
    serde_json::from_str(&raw).map_err(|err| err.to_string())
}

fn normalize_snapshot(snapshot: TrustSnapshot) -> TrustSnapshot {
    match snapshot.state.as_str() {
        "trusted" | "degraded" | "unavailable" => TrustSnapshot {
            reason_code: snapshot.reason_code.or_else(|| {
                Some(if snapshot.state == "trusted" {
                    "trusted".to_string()
                } else {
                    "degraded".to_string()
                })
            }),
            ..snapshot
        },
        other => TrustSnapshot {
            state: "unavailable".to_string(),
            reason_code: Some("trust_provider_invalid_state".to_string()),
            detail: Some(format!("invalid state: {other}")),
        },
    }
}

fn decide(req: TrustDecisionRequest) -> TrustDecision {
    let snapshot = normalize_snapshot(req.snapshot);
    let reason = snapshot.reason_code.clone().unwrap_or_else(|| {
        if snapshot.state == "trusted" {
            "trusted".to_string()
        } else {
            "degraded".to_string()
        }
    });
    let would_block = snapshot.state != "trusted";
    let allowed = match snapshot.state.as_str() {
        "trusted" => true,
        "unavailable" => req.mode != "enforced",
        "degraded" => !(req.mode == "enforced" && req.enforce_degraded),
        _ => false,
    };
    TrustDecision {
        version: VERSION,
        allowed,
        would_block_if_fail_closed: would_block,
        state: snapshot.state,
        reason_code: reason,
        detail: snapshot.detail,
        policy_version: POLICY_VERSION,
    }
}

fn canonicalize(value: &Value) -> Value {
    match value {
        Value::Object(map) => {
            let mut out = serde_json::Map::new();
            let mut keys: Vec<_> = map.keys().collect();
            keys.sort();
            for key in keys {
                out.insert(key.clone(), canonicalize(&map[key]));
            }
            Value::Object(out)
        }
        Value::Array(items) => Value::Array(items.iter().map(canonicalize).collect()),
        _ => value.clone(),
    }
}

fn hash_canonical(value: &Value) -> Result<String, String> {
    let canonical = canonicalize(value);
    let bytes = serde_json::to_vec(&canonical).map_err(|err| err.to_string())?;
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    Ok(hex::encode(hasher.finalize()))
}

fn hash_legacy_json(value: &Value) -> Result<String, String> {
    let bytes = serde_json::to_vec(value).map_err(|err| err.to_string())?;
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    Ok(hex::encode(hasher.finalize()))
}

fn get_str<'a>(value: &'a Value, pointer: &str) -> Option<&'a str> {
    value.pointer(pointer).and_then(Value::as_str)
}

fn build_legacy_signed_message(proof: &Value) -> Result<String, String> {
    let mut entries: Vec<(&str, Value)> = vec![
        ("codeHash", Value::String(get_str(proof, "/gateway/codeHash").unwrap_or("").to_string())),
        ("gitCommit", Value::String(get_str(proof, "/gateway/gitCommit").unwrap_or("").to_string())),
        ("serverId", Value::String(get_str(proof, "/server/id").unwrap_or("").to_string())),
        ("package", Value::String(get_str(proof, "/server/package").unwrap_or("").to_string())),
        ("registryType", Value::String(get_str(proof, "/server/registryType").unwrap_or("").to_string())),
        ("toolName", Value::String(get_str(proof, "/execution/toolName").unwrap_or("").to_string())),
        ("requestHash", Value::String(get_str(proof, "/execution/requestHash").unwrap_or("").to_string())),
        ("responseHash", Value::String(get_str(proof, "/execution/responseHash").unwrap_or("").to_string())),
        ("timestamp", Value::String(get_str(proof, "/execution/timestamp").unwrap_or("").to_string())),
        ("nonce", Value::String(get_str(proof, "/execution/nonce").unwrap_or("").to_string())),
    ];
    if let Some(registry_digest) = get_str(proof, "/server/packageAttestation/integrity/registryDigest") {
        entries.push(("registryDigest", Value::String(registry_digest.to_string())));
    }

    let mut rendered = String::from("{");
    for (idx, (key, value)) in entries.iter().enumerate() {
        if idx > 0 {
            rendered.push(',');
        }
        rendered.push_str(&serde_json::to_string(key).map_err(|err| err.to_string())?);
        rendered.push(':');
        rendered.push_str(&serde_json::to_string(value).map_err(|err| err.to_string())?);
    }
    rendered.push('}');
    Ok(rendered)
}

fn extract_ed25519_key_from_spki(spki: &[u8]) -> Result<[u8; 32], String> {
    const ED25519_SPKI_PREFIX: &[u8] = &[
        0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00,
    ];
    let key = if spki.len() == 32 {
        spki
    } else if spki.starts_with(ED25519_SPKI_PREFIX) && spki.len() == ED25519_SPKI_PREFIX.len() + 32 {
        &spki[ED25519_SPKI_PREFIX.len()..]
    } else {
        return Err("unsupported Ed25519 public key encoding".to_string());
    };
    key.try_into().map_err(|_| "invalid Ed25519 public key length".to_string())
}

fn verify_ed25519_signature(proof: &Value, reconstructed_message: &str) -> Result<Value, String> {
    let signature_v2 = proof.get("signatureV2").unwrap_or(&Value::Null);
    let sig_b64 = get_str(signature_v2, "/value");
    let spki_b64 = get_str(signature_v2, "/publicKey/spkiB64");
    let signed_message_b64 = get_str(signature_v2, "/signedMessage");

    let Some(sig_b64) = sig_b64 else {
        return Ok(json!({
            "present": false,
            "signedMessageMatches": false,
            "signatureValid": false,
            "verified": false,
            "error": "signatureV2 missing"
        }));
    };
    let Some(spki_b64) = spki_b64 else {
        return Ok(json!({
            "present": true,
            "signedMessageMatches": false,
            "signatureValid": false,
            "verified": false,
            "error": "signatureV2 publicKey.spkiB64 missing"
        }));
    };
    let Some(signed_message_b64) = signed_message_b64 else {
        return Ok(json!({
            "present": true,
            "signedMessageMatches": false,
            "signatureValid": false,
            "verified": false,
            "error": "signatureV2 signedMessage missing"
        }));
    };

    let signed_message = BASE64.decode(signed_message_b64).map_err(|err| err.to_string())?;
    let signed_message_matches = signed_message == reconstructed_message.as_bytes();
    let signature_bytes = BASE64.decode(sig_b64).map_err(|err| err.to_string())?;
    let spki = BASE64.decode(spki_b64).map_err(|err| err.to_string())?;
    let key_bytes = extract_ed25519_key_from_spki(&spki)?;
    let verifying_key = VerifyingKey::from_bytes(&key_bytes).map_err(|err| err.to_string())?;
    let signature = Signature::from_slice(&signature_bytes).map_err(|err| err.to_string())?;
    let signature_valid = verifying_key.verify(&signed_message, &signature).is_ok();

    Ok(json!({
        "present": true,
        "signedMessageMatches": signed_message_matches,
        "signatureValid": signature_valid,
        "verified": signed_message_matches && signature_valid,
    }))
}

fn verify_proof_shape(value: Value) -> Result<Value, String> {
    let request_args = value
        .pointer("/requestArgs")
        .or_else(|| value.pointer("/request_args"))
        .cloned()
        .unwrap_or(Value::Null);
    let response_content = value
        .pointer("/responseContent")
        .or_else(|| value.pointer("/response_content"))
        .cloned()
        .unwrap_or(Value::Null);
    let proof = value.get("proof").cloned().unwrap_or(value);
    let expected_request_hash = proof.pointer("/execution/requestHash").and_then(Value::as_str);
    let expected_response_hash = proof.pointer("/execution/responseHash").and_then(Value::as_str);
    let request_hash = hash_legacy_json(&request_args)?;
    let response_hash = hash_legacy_json(&response_content)?;
    let canonical_request_hash = hash_canonical(&request_args)?;
    let canonical_response_hash = hash_canonical(&response_content)?;
    let reconstructed_message = build_legacy_signed_message(&proof)?;
    let reconstructed_message_hash = {
        let mut hasher = Sha256::new();
        hasher.update(reconstructed_message.as_bytes());
        hex::encode(hasher.finalize())
    };
    let ed25519 = verify_ed25519_signature(&proof, &reconstructed_message)?;
    let signature_verified = ed25519
        .get("verified")
        .and_then(Value::as_bool)
        .unwrap_or(false);
    Ok(json!({
        "version": VERSION,
        "requestHash": request_hash,
        "responseHash": response_hash,
        "canonicalRequestHash": canonical_request_hash,
        "canonicalResponseHash": canonical_response_hash,
        "requestHashMatches": expected_request_hash.map(|h| h == request_hash).unwrap_or(false),
        "responseHashMatches": expected_response_hash.map(|h| h == response_hash).unwrap_or(false),
        "canonicalRequestHashMatches": expected_request_hash.map(|h| h == canonical_request_hash).unwrap_or(false),
        "canonicalResponseHashMatches": expected_response_hash.map(|h| h == canonical_response_hash).unwrap_or(false),
        "legacySignedMessageSha256": reconstructed_message_hash,
        "hasSignature": proof.pointer("/signature/value").is_some() || proof.pointer("/signatureV2/value").is_some(),
        "ed25519": ed25519,
        "signatureVerified": signature_verified,
    }))
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let result = match args.get(1).map(|s| s.as_str()) {
        Some("decide-secret-release") => {
            let value = read_stdin_json().and_then(|v| {
                serde_json::from_value::<TrustDecisionRequest>(v).map_err(|err| err.to_string())
            });
            value.map(|req| serde_json::to_value(decide(req)).unwrap())
        }
        Some("verify-proof") => read_stdin_json().and_then(verify_proof_shape),
        Some("version") | Some("--version") | Some("-V") => Ok(json!({ "version": VERSION })),
        _ => Ok(json!({
            "error": "usage",
            "commands": ["decide-secret-release", "verify-proof", "version"]
        })),
    };

    match result {
        Ok(value) => println!("{}", serde_json::to_string(&value).unwrap()),
        Err(err) => {
            eprintln!("trust-plane error: {err}");
            std::process::exit(1);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn trusted_snapshots_are_allowed() {
        let decision = decide(TrustDecisionRequest {
            mode: "enforced".to_string(),
            enforce_degraded: true,
            snapshot: TrustSnapshot {
                state: "trusted".to_string(),
                reason_code: Some("attestation_available".to_string()),
                detail: None,
            },
        });
        assert!(decision.allowed);
        assert!(!decision.would_block_if_fail_closed);
        assert_eq!(decision.reason_code, "attestation_available");
    }

    #[test]
    fn unavailable_snapshots_block_only_in_enforced_mode() {
        let decision = decide(TrustDecisionRequest {
            mode: "enforced".to_string(),
            enforce_degraded: false,
            snapshot: TrustSnapshot {
                state: "unavailable".to_string(),
                reason_code: Some("trust_provider_not_configured".to_string()),
                detail: None,
            },
        });
        assert!(!decision.allowed);
        assert!(decision.would_block_if_fail_closed);

        let permissive = decide(TrustDecisionRequest {
            mode: "permissive".to_string(),
            enforce_degraded: false,
            snapshot: TrustSnapshot {
                state: "unavailable".to_string(),
                reason_code: Some("trust_provider_not_configured".to_string()),
                detail: None,
            },
        });
        assert!(permissive.allowed);
    }

    #[test]
    fn degraded_snapshots_follow_fail_closed_degraded_flag() {
        let decision = decide(TrustDecisionRequest {
            mode: "enforced".to_string(),
            enforce_degraded: true,
            snapshot: TrustSnapshot {
                state: "degraded".to_string(),
                reason_code: Some("tee_mode_disabled".to_string()),
                detail: None,
            },
        });
        assert!(!decision.allowed);

        let soft = decide(TrustDecisionRequest {
            mode: "enforced".to_string(),
            enforce_degraded: false,
            snapshot: TrustSnapshot {
                state: "degraded".to_string(),
                reason_code: Some("tee_mode_disabled".to_string()),
                detail: None,
            },
        });
        assert!(soft.allowed);
    }

    #[test]
    fn canonical_hash_is_stable_across_key_order() {
        let a = serde_json::json!({"b": 2, "a": {"d": 4, "c": 3}});
        let b = serde_json::json!({"a": {"c": 3, "d": 4}, "b": 2});
        assert_eq!(hash_canonical(&a).unwrap(), hash_canonical(&b).unwrap());
    }

    #[test]
    fn legacy_hash_preserves_gateway_v1_json_order() {
        let a = serde_json::json!({"b": 2, "a": 1});
        let b = serde_json::json!({"a": 1, "b": 2});
        assert_ne!(hash_legacy_json(&a).unwrap(), hash_legacy_json(&b).unwrap());
        assert_eq!(hash_canonical(&a).unwrap(), hash_canonical(&b).unwrap());
    }

    #[test]
    fn proof_verifier_uses_legacy_hash_for_v1_proof_parity() {
        let request_args = serde_json::json!({"b": 2, "a": 1});
        let response_content = serde_json::json!({"structuredContent": {"chains": ["base", "ethereum"]}, "content": [{"type": "text", "text": "ok"}]});
        let request_hash = hash_legacy_json(&request_args).unwrap();
        let response_hash = hash_legacy_json(&response_content).unwrap();
        let proof = serde_json::json!({
            "gateway": {
                "codeHash": "code",
                "gitCommit": "commit"
            },
            "server": {
                "id": "server",
                "package": "@rickydata/test",
                "registryType": "npm"
            },
            "execution": {
                "toolName": "ping",
                "requestHash": request_hash,
                "responseHash": response_hash,
                "timestamp": "2026-05-02T00:00:00.000Z",
                "nonce": "nonce"
            }
        });

        let verified = verify_proof_shape(serde_json::json!({
            "proof": proof,
            "requestArgs": request_args,
            "responseContent": response_content
        })).unwrap();

        assert_eq!(verified["requestHashMatches"], true);
        assert_eq!(verified["responseHashMatches"], true);
        assert_ne!(verified["responseHash"], verified["canonicalResponseHash"]);
    }

    #[test]
    fn verifies_existing_execution_proof_ed25519_shape() {
        use base64::{engine::general_purpose::STANDARD as BASE64, Engine as _};
        use ed25519_dalek::{Signer, SigningKey};

        const ED25519_SPKI_PREFIX: &[u8] = &[
            0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00,
        ];
        let signing_key = SigningKey::from_bytes(&[7_u8; 32]);
        let verifying_key = signing_key.verifying_key();
        let mut spki = ED25519_SPKI_PREFIX.to_vec();
        spki.extend_from_slice(verifying_key.as_bytes());

        let mut proof = serde_json::json!({
            "gateway": {
                "codeHash": "code",
                "gitCommit": "commit"
            },
            "server": {
                "id": "server",
                "package": "@rickydata/test",
                "registryType": "npm"
            },
            "execution": {
                "toolName": "ping",
                "requestHash": "req",
                "responseHash": "res",
                "timestamp": "2026-05-02T00:00:00.000Z",
                "nonce": "nonce"
            },
            "signature": {
                "value": "UNSIGNED"
            }
        });
        let message = build_legacy_signed_message(&proof).unwrap();
        let signature = signing_key.sign(message.as_bytes());
        proof["signatureV2"] = serde_json::json!({
            "algorithm": "Ed25519",
            "value": BASE64.encode(signature.to_bytes()),
            "publicKey": {
                "keyId": "sha256:test",
                "spkiB64": BASE64.encode(spki)
            },
            "signedMessage": BASE64.encode(message.as_bytes()),
            "signed": true
        });

        let verified = verify_ed25519_signature(&proof, &message).unwrap();
        assert_eq!(verified["verified"], true);
    }
}
