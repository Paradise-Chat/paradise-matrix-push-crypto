use serde::{Deserialize, Serialize};
use serde_json::{json, Map, Value};
use vodozemac::megolm::{
    ExportedSessionKey, InboundGroupSession, InboundGroupSessionPickle, MegolmMessage,
    SessionConfig as MegolmConfig, SessionKey,
};
use vodozemac::olm::{
    Account, AccountPickle, Message, OlmMessage, PreKeyMessage, Session, SessionPickle,
};
use vodozemac::{Curve25519PublicKey, Ed25519SecretKey};
use wasm_bindgen::prelude::*;

#[derive(Serialize)]
struct OlmDecryptionResult {
    plaintext: String,
    session_pickle: String,
}

#[derive(Serialize)]
struct MegolmDecryptionResult {
    plaintext: String,
    message_index: u32,
    session_pickle: String,
}

#[derive(Serialize, Deserialize)]
struct ShadowAccountCreationResult {
    account_pickle: String,
    curve25519_key: String,
    ed25519_key: String,
    upload_payload: Value,
    signature_upload_payload: Value,
}

#[derive(Serialize, Deserialize)]
struct ReplenishOtkResult {
    account_pickle: String,
    one_time_keys: Value,
}

fn sign_unpublished_otks(
    account: &Account,
    user_id: &str,
    device_id: &str,
) -> Result<Map<String, Value>, String> {
    let mut otks = Map::new();
    let signer_key_id = format!("ed25519:{device_id}");

    for (key_id, key) in account.one_time_keys() {
        let key_str = key.to_base64();
        let unsigned_otk = json!({ "key": key_str });
        let canonical = serde_json::to_string(&unsigned_otk).map_err(|e| e.to_string())?;
        let sig = account.sign(canonical.as_bytes()).to_base64();

        otks.insert(
            format!("signed_curve25519:{}", key_id.to_base64()),
            json!({
                "key": key_str,
                "signatures": {
                    user_id: {
                        &signer_key_id: sig
                    }
                }
            }),
        );
    }

    Ok(otks)
}

#[wasm_bindgen]
pub fn create_shadow_account(
    user_id: &str,
    device_id: &str,
    otk_count: usize,
    ssk_seed_base64: Option<String>,
) -> Result<String, JsValue> {
    let mut account = Account::new();
    account.generate_one_time_keys(otk_count);

    let id_keys = account.identity_keys();
    let curve25519_key = id_keys.curve25519.to_base64();
    let ed25519_key = id_keys.ed25519.to_base64();

    let otks = sign_unpublished_otks(&account, user_id, device_id)
        .map_err(|e| JsValue::from_str(&format!("Failed to sign OTKs: {e}")))?;

    let mut device_keys = json!({
        "algorithms": [
            "m.olm.v1.curve25519-aes-sha2",
            "m.megolm.v1.aes-sha2"
        ],
        "device_id": device_id,
        "keys": {
            format!("curve25519:{device_id}"): &curve25519_key,
            format!("ed25519:{device_id}"): &ed25519_key
        },
        "user_id": user_id
    });

    let unsigned_canonical = serde_json::to_string(&device_keys)
        .map_err(|e| JsValue::from_str(&format!("Failed to serialize device_keys: {e}")))?;

    let dev_sig = account.sign(unsigned_canonical.as_bytes()).to_base64();

    let mut user_sigs = Map::new();
    user_sigs.insert(format!("ed25519:{device_id}"), Value::String(dev_sig));

    if let Some(seed_str) = ssk_seed_base64 {
        if !seed_str.is_empty() {
            let ssk = Ed25519SecretKey::from_base64(&seed_str)
                .map_err(|e| JsValue::from_str(&format!("Invalid SSK seed: {e}")))?;
            let ssk_pub = ssk.public_key().to_base64();
            let ssk_sig = ssk.sign(unsigned_canonical.as_bytes()).to_base64();
            user_sigs.insert(format!("ed25519:{ssk_pub}"), Value::String(ssk_sig));
        }
    }

    device_keys["signatures"] = json!({
        user_id: user_sigs
    });

    account.mark_keys_as_published();

    let account_pickle = serde_json::to_string(&account.pickle())
        .map_err(|e| JsValue::from_str(&format!("Failed to pickle shadow account: {e}")))?;

    let result = ShadowAccountCreationResult {
        account_pickle,
        curve25519_key,
        ed25519_key,
        upload_payload: json!({
            "device_keys": device_keys,
            "one_time_keys": otks
        }),
        signature_upload_payload: json!({
            user_id: {
                device_id: device_keys
            }
        }),
    };

    serde_json::to_string(&result).map_err(|e| JsValue::from_str(&e.to_string()))
}



#[wasm_bindgen]
pub fn sign_shadow_device_with_ssk(
    account_pickle_json: &str,
    user_id: &str,
    device_id: &str,
    ssk_seed_base64: &str,
) -> Result<String, JsValue> {
    let pickle: AccountPickle = serde_json::from_str(account_pickle_json)
        .map_err(|e| JsValue::from_str(&format!("Invalid account pickle: {e}")))?;
    let account = Account::from_pickle(pickle);

    let id_keys = account.identity_keys();
    let curve25519_key = id_keys.curve25519.to_base64();
    let ed25519_key = id_keys.ed25519.to_base64();

    let mut device_keys = json!({
        "algorithms": [
            "m.olm.v1.curve25519-aes-sha2",
            "m.megolm.v1.aes-sha2"
        ],
        "device_id": device_id,
        "keys": {
            format!("curve25519:{device_id}"): curve25519_key,
            format!("ed25519:{device_id}"): ed25519_key
        },
        "user_id": user_id
    });

    let unsigned_canonical = serde_json::to_string(&device_keys)
        .map_err(|e| JsValue::from_str(&format!("Failed to serialize device_keys: {e}")))?;

    let dev_sig = account.sign(unsigned_canonical.as_bytes()).to_base64();

    let ssk = Ed25519SecretKey::from_base64(ssk_seed_base64)
        .map_err(|e| JsValue::from_str(&format!("Invalid SSK seed: {e}")))?;
    let ssk_pub = ssk.public_key().to_base64();
    let ssk_sig = ssk.sign(unsigned_canonical.as_bytes()).to_base64();

    let mut user_sigs = Map::new();
    user_sigs.insert(format!("ed25519:{device_id}"), Value::String(dev_sig));
    user_sigs.insert(format!("ed25519:{ssk_pub}"), Value::String(ssk_sig));

    device_keys["signatures"] = json!({
        user_id: user_sigs
    });

    serde_json::to_string(&json!({
        user_id: {
            device_id: device_keys
        }
    }))
    .map_err(|e| JsValue::from_str(&e.to_string()))
}


#[wasm_bindgen]
pub fn replenish_one_time_keys(
    account_pickle_json: &str,
    user_id: &str,
    device_id: &str,
    count: usize,
) -> Result<String, JsValue> {
    let pickle: AccountPickle = serde_json::from_str(account_pickle_json)
        .map_err(|e| JsValue::from_str(&format!("Invalid account pickle: {e}")))?;
    let mut account = Account::from_pickle(pickle);

    account.generate_one_time_keys(count);

    let otks = sign_unpublished_otks(&account, user_id, device_id)
        .map_err(|e| JsValue::from_str(&format!("Failed to sign replenished OTKs: {e}")))?;

    account.mark_keys_as_published();

    let account_pickle = serde_json::to_string(&account.pickle())
        .map_err(|e| JsValue::from_str(&format!("Failed to serialize account: {e}")))?;

    serde_json::to_string(&ReplenishOtkResult {
        account_pickle,
        one_time_keys: Value::Object(otks),
    })
    .map_err(|e| JsValue::from_str(&e.to_string()))
}

#[wasm_bindgen]
pub fn decrypt_olm_with_session(
    session_pickle_json: &str,
    message_type: usize,
    ciphertext_base64: &str,
) -> Result<String, JsValue> {
    let pickle: SessionPickle = serde_json::from_str(session_pickle_json)
        .map_err(|e| JsValue::from_str(&format!("Invalid session pickle: {e}")))?;
    let mut session = Session::from_pickle(pickle);

    let olm_message = match message_type {
        0 => OlmMessage::PreKey(
            PreKeyMessage::from_base64(ciphertext_base64)
                .map_err(|e| JsValue::from_str(&format!("Invalid PreKey Olm message: {e}")))?,
        ),
        1 => OlmMessage::Normal(
            Message::from_base64(ciphertext_base64)
                .map_err(|e| JsValue::from_str(&format!("Invalid Normal Olm message: {e}")))?,
        ),
        _ => {
            return Err(JsValue::from_str(&format!(
                "Invalid Olm message type: {message_type}"
            )))
        }
    };

    let plaintext_bytes = session
        .decrypt(&olm_message)
        .map_err(|e| JsValue::from_str(&format!("Olm decrypt failed: {e}")))?;

    let plaintext = String::from_utf8(plaintext_bytes)
        .map_err(|e| JsValue::from_str(&format!("Invalid UTF-8 in Olm plaintext: {e}")))?;

    let new_pickle = serde_json::to_string(&session.pickle())
        .map_err(|e| JsValue::from_str(&format!("Failed to serialize session: {e}")))?;

    serde_json::to_string(&OlmDecryptionResult {
        plaintext,
        session_pickle: new_pickle,
    })
    .map_err(|e| JsValue::from_str(&e.to_string()))
}

#[wasm_bindgen]
pub fn decrypt_olm_prekey_with_account(
    account_pickle_json: &str,
    sender_curve25519_key: &str,
    ciphertext_base64: &str,
) -> Result<String, JsValue> {
    let pickle: AccountPickle = serde_json::from_str(account_pickle_json)
        .map_err(|e| JsValue::from_str(&format!("Invalid account pickle: {e}")))?;
    let mut account = Account::from_pickle(pickle);

    let sender_key = Curve25519PublicKey::from_base64(sender_curve25519_key)
        .map_err(|e| JsValue::from_str(&format!("Invalid sender key: {e}")))?;

    let prekey_msg = PreKeyMessage::from_base64(ciphertext_base64)
        .map_err(|e| JsValue::from_str(&format!("Invalid PreKey message: {e}")))?;

    let result = account
        .create_inbound_session(sender_key, &prekey_msg)
        .map_err(|e| JsValue::from_str(&format!("Inbound session creation failed: {e}")))?;

    let plaintext = String::from_utf8(result.plaintext)
        .map_err(|e| JsValue::from_str(&format!("Invalid UTF-8 in PreKey plaintext: {e}")))?;

    let session_pickle = serde_json::to_string(&result.session.pickle())
        .map_err(|e| JsValue::from_str(&format!("Failed to serialize session: {e}")))?;

    let account_pickle = serde_json::to_string(&account.pickle())
        .map_err(|e| JsValue::from_str(&format!("Failed to serialize account: {e}")))?;

    serde_json::to_string(&json!({
        "plaintext": plaintext,
        "session_pickle": session_pickle,
        "account_pickle": account_pickle,
    }))
    .map_err(|e| JsValue::from_str(&e.to_string()))
}

#[wasm_bindgen]
pub fn create_inbound_group_session(session_key_base64: &str) -> Result<String, JsValue> {
    let session_key = SessionKey::from_base64(session_key_base64)
        .map_err(|e| JsValue::from_str(&format!("Invalid Megolm session key: {e}")))?;

    let session = InboundGroupSession::new(&session_key, MegolmConfig::version_1());

    serde_json::to_string(&session.pickle())
        .map_err(|e| JsValue::from_str(&format!("Failed to serialize Megolm session: {e}")))
}

#[wasm_bindgen]
pub fn import_exported_group_session(exported_key_base64: &str) -> Result<String, JsValue> {
    let exported_key = ExportedSessionKey::from_base64(exported_key_base64)
        .map_err(|e| JsValue::from_str(&format!("Invalid exported Megolm key: {e}")))?;

    let session = InboundGroupSession::import(&exported_key, MegolmConfig::version_1());

    serde_json::to_string(&session.pickle())
        .map_err(|e| JsValue::from_str(&format!("Failed to serialize imported Megolm session: {e}")))
}

#[wasm_bindgen]
pub fn decrypt_megolm(
    session_pickle_json: &str,
    ciphertext_base64: &str,
) -> Result<String, JsValue> {
    let pickle: InboundGroupSessionPickle = serde_json::from_str(session_pickle_json)
        .map_err(|e| JsValue::from_str(&format!("Invalid Megolm pickle: {e}")))?;
    let mut session = InboundGroupSession::from_pickle(pickle);

    let message = MegolmMessage::from_base64(ciphertext_base64)
        .map_err(|e| JsValue::from_str(&format!("Invalid Megolm ciphertext: {e}")))?;

    let decrypted = session
        .decrypt(&message)
        .map_err(|e| JsValue::from_str(&format!("Megolm decrypt failed: {e}")))?;

    let plaintext = String::from_utf8(decrypted.plaintext)
        .map_err(|e| JsValue::from_str(&format!("Invalid UTF-8 in Megolm plaintext: {e}")))?;

    let updated_pickle = serde_json::to_string(&session.pickle())
        .map_err(|e| JsValue::from_str(&format!("Failed to serialize updated Megolm pickle: {e}")))?;

    serde_json::to_string(&MegolmDecryptionResult {
        plaintext,
        message_index: decrypted.message_index,
        session_pickle: updated_pickle,
    })
    .map_err(|e| JsValue::from_str(&e.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::process::Command;
    use vodozemac::megolm::{GroupSession, InboundGroupSession, SessionConfig as MegolmConfig};
    use vodozemac::olm::{Account, OlmMessage, SessionConfig as OlmConfig};
    use vodozemac::{Curve25519PublicKey, Ed25519PublicKey, Ed25519SecretKey, Ed25519Signature};

    #[test]
    fn test_wasm2js_bundle_end_to_end() {
        let user_id = "@bob:example.org";
        let device_id = "SHADOWDEV1";
        let ssk = Ed25519SecretKey::new();
        let ssk_seed_b64 = ssk.to_base64();
        let ssk_pub_key = ssk.public_key();
        let ssk_key_id = format!("ed25519:{}", ssk_pub_key.to_base64());

        let js_provision_harness = r#"
            const cryptoNode = require("crypto");
            delete globalThis.WebAssembly;
            delete globalThis.TextEncoder;
            delete globalThis.TextDecoder;
            delete globalThis.crypto;
            globalThis.__nativeGetRandomBytes = (count) => {
                return Uint8Array.from(cryptoNode.randomBytes(count));
            };
            require("./dist/paradise_push_crypto_bundle.js");
            const api = globalThis.ParadisePushCrypto;
            const [userId, deviceId, sskSeedB64] = process.argv.slice(1);
            console.log(api.create_shadow_account(userId, deviceId, 5, sskSeedB64));
        "#;

        let prov_output = Command::new("node")
            .arg("-e")
            .arg(js_provision_harness)
            .arg(user_id)
            .arg(device_id)
            .arg(&ssk_seed_b64)
            .output()
            .expect("Failed to execute node for provisioning");

        if !prov_output.status.success() {
            panic!(
                "JS provisioning failed:\nSTDOUT: {}\nSTDERR: {}",
                String::from_utf8_lossy(&prov_output.stdout),
                String::from_utf8_lossy(&prov_output.stderr)
            );
        }

        let created: ShadowAccountCreationResult =
            serde_json::from_slice(&prov_output.stdout).expect("Invalid provisioning JSON");

        let mut unsigned_dev_keys = created.upload_payload["device_keys"].clone();
        let sigs = unsigned_dev_keys
            .as_object_mut()
            .unwrap()
            .remove("signatures")
            .unwrap();
        let canonical_dev_keys = serde_json::to_string(&unsigned_dev_keys).unwrap();

        let dev_ed_pub = Ed25519PublicKey::from_base64(&created.ed25519_key).unwrap();
        let dev_sig_str = sigs[user_id][format!("ed25519:{device_id}")].as_str().unwrap();
        let dev_sig = Ed25519Signature::from_base64(dev_sig_str).unwrap();
        dev_ed_pub
            .verify(canonical_dev_keys.as_bytes(), &dev_sig)
            .expect("Shadow device self-signature verification failed");

        let ssk_sig_str = sigs[user_id][&ssk_key_id].as_str().unwrap();
        let ssk_sig = Ed25519Signature::from_base64(ssk_sig_str).unwrap();
        ssk_pub_key
            .verify(canonical_dev_keys.as_bytes(), &ssk_sig)
            .expect("SSK cross-signature verification failed");

        let otks_obj = created.upload_payload["one_time_keys"].as_object().unwrap();
        assert_eq!(otks_obj.len(), 5);
        let first_otk_entry = otks_obj.values().next().unwrap();
        let bob_otk_b64 = first_otk_entry["key"].as_str().unwrap();
        let bob_otk = Curve25519PublicKey::from_base64(bob_otk_b64).unwrap();
        let bob_curve_pub = Curve25519PublicKey::from_base64(&created.curve25519_key).unwrap();

        let alice = Account::new();
        let alice_curve_key = alice.identity_keys().curve25519.to_base64();

        let mut alice_session = alice.create_outbound_session(
            OlmConfig::version_1(),
            bob_curve_pub,
            bob_otk,
        );

        let OlmMessage::PreKey(prekey_msg) = alice_session.encrypt(b"First message via PreKey") else {
            panic!("Expected PreKey Olm message");
        };
        let prekey_b64 = prekey_msg.to_base64();

        let bob_pickle: AccountPickle = serde_json::from_str(&created.account_pickle).unwrap();
        let mut bob_native = Account::from_pickle(bob_pickle)
            .create_inbound_session(alice.identity_keys().curve25519, &prekey_msg)
            .unwrap()
            .session;
        let bob_ack = bob_native.encrypt(b"ack");
        let alice_session_pickle = serde_json::to_string(&alice_session.pickle()).unwrap();

        let OlmMessage::Normal(normal_msg) = bob_ack else {
            panic!("Expected Normal Olm message from Bob's reply");
        };
        let normal_type = 1usize;
        let normal_b64 = normal_msg.to_base64();

        let mut megolm_out = GroupSession::new(MegolmConfig::version_1());
        let session_key_b64 = megolm_out.session_key().to_base64();
        let mut inbound_for_export =
            InboundGroupSession::new(&megolm_out.session_key(), MegolmConfig::version_1());
        let exported_key_b64 = inbound_for_export.export_at(0).unwrap().to_base64();
        let megolm_plaintext = r#"{"type":"m.room.message","content":{"body":"Push works!"}}"#;
        let megolm_cipher_b64 = megolm_out.encrypt(megolm_plaintext.as_bytes()).to_base64();

        let js_harness = r#"
            const cryptoNode = require("crypto");

            delete globalThis.WebAssembly;
            delete globalThis.TextEncoder;
            delete globalThis.TextDecoder;
            delete globalThis.crypto;

            globalThis.__nativeGetRandomBytes = (count) => {
                return Uint8Array.from(cryptoNode.randomBytes(count));
            };

            require("./dist/paradise_push_crypto_bundle.js");
            const api = globalThis.ParadisePushCrypto;

            const [
                bobAccountPickle,
                aliceCurveKey,
                prekeyB64,
                aliceSessionPickle,
                normalType,
                normalB64,
                sessionKeyB64,
                exportedKeyB64,
                megolmCipherB64,
                userId,
                deviceId
            ] = process.argv.slice(1);

            const prekeyRes = JSON.parse(
                api.decrypt_olm_prekey_with_account(bobAccountPickle, aliceCurveKey, prekeyB64)
            );

            const replenishRes = JSON.parse(
                api.replenish_one_time_keys(prekeyRes.account_pickle, userId, deviceId, 3)
            );

            const normalRes = JSON.parse(
                api.decrypt_olm_with_session(aliceSessionPickle, Number(normalType), normalB64)
            );

            const megolmPickle = api.create_inbound_group_session(sessionKeyB64);
            const megolmRes = JSON.parse(
                api.decrypt_megolm(megolmPickle, megolmCipherB64)
            );

            const importedPickle = api.import_exported_group_session(exportedKeyB64);
            const importedMegolmRes = JSON.parse(
                api.decrypt_megolm(importedPickle, megolmCipherB64)
            );

            console.log(JSON.stringify({
                prekeyPlaintext: prekeyRes.plaintext,
                replenishedCount: Object.keys(replenishRes.one_time_keys).length,
                normalPlaintext: normalRes.plaintext,
                megolmPlaintext: megolmRes.plaintext,
                importedMegolmPlaintext: importedMegolmRes.plaintext,
                megolmIndex: megolmRes.message_index
            }));
        "#;

        let output = Command::new("node")
            .arg("-e")
            .arg(js_harness)
            .arg(&created.account_pickle)
            .arg(&alice_curve_key)
            .arg(&prekey_b64)
            .arg(&alice_session_pickle)
            .arg(normal_type.to_string())
            .arg(&normal_b64)
            .arg(&session_key_b64)
            .arg(&exported_key_b64)
            .arg(&megolm_cipher_b64)
            .arg(user_id)
            .arg(device_id)
            .output()
            .expect("Failed to execute node");

        if !output.status.success() {
            panic!(
                "JS bundle execution failed:\nSTDOUT: {}\nSTDERR: {}",
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr)
            );
        }

        let result: serde_json::Value =
            serde_json::from_slice(&output.stdout).expect("Invalid JSON from JS harness");

        assert_eq!(result["prekeyPlaintext"], "First message via PreKey");
        assert_eq!(result["replenishedCount"], 3);
        assert_eq!(result["normalPlaintext"], "ack");
        assert_eq!(result["megolmPlaintext"], megolm_plaintext);
        assert_eq!(result["importedMegolmPlaintext"], megolm_plaintext);
        assert_eq!(result["megolmIndex"], 0);
    }
}


