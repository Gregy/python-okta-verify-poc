use std::fs::{self, OpenOptions};
use std::io::Write;
use std::os::unix::fs::OpenOptionsExt;
use std::path::Path;
use std::collections::HashSet;
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

use base64::Engine;
use fcm_receiver_rs::client::{AndroidApp, FcmClient};
use fcm_receiver_rs::Result;
use serde::{Deserialize, Serialize};

// Public client configuration recovered from the analyzed Okta Verify APK.
// These are Firebase client identifiers, not Okta server credentials.
const API_KEY: &str = "AIzaSyDwy_6SVFbhzuHSzH5ld-Q-cnHJMHbGOac";
const APP_ID: &str = "1:302730332600:android:fef22a316c6a55e7";
const PROJECT_ID: &str = "okta-verify-2";
const SENDER_ID: &str = "302730332600";
const PACKAGE: &str = "com.okta.android.auth";
// SHA-1 of the signing certificate in the analyzed APK. Its distribution
// provenance was not independently verified; replace with an official pull
// before treating this as a stable integration profile.
const PACKAGE_CERT: &str = "d2dd7d391505aabbb7e35432019d4b84a39059a8";
const CREDENTIALS: &str = "live-captures/okta-fcm-device.json";
const TOKEN_OUT: &str = "/dev/shm/okta-poc-okta-fcm-token";
const CHALLENGE_OUT: &str = "/dev/shm/okta-poc-fcm-challenge.jws";

#[derive(Debug, Serialize, Deserialize)]
struct DeviceCredentials {
    fcm_token: String,
    android_id: u64,
    security_token: u64,
    private_key_base64: String,
    auth_secret_base64: String,
}

fn write_secret(path: &str, value: &str) -> Result<()> {
    let mut file = OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .open(path)?;
    file.write_all(value.as_bytes())?;
    file.sync_all()?;
    Ok(())
}

fn is_expired(challenge: &str) -> bool {
    // This is only a replay-queue filter. Python still performs full JWS
    // validation before any decision or signature.
    let Some(payload) = challenge.split('.').nth(1) else {
        return false;
    };
    let Ok(decoded) = base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(payload) else {
        return false;
    };
    let Ok(value) = serde_json::from_slice::<serde_json::Value>(&decoded) else {
        return false;
    };
    let Some(exp) = value.get("exp").and_then(|item| item.as_u64()) else {
        return false;
    };
    let Ok(now) = SystemTime::now().duration_since(UNIX_EPOCH) else {
        return false;
    };
    now.as_secs() > exp.saturating_add(60)
}

fn save_credentials(path: &str, creds: &DeviceCredentials) -> Result<()> {
    if let Some(parent) = Path::new(path).parent() {
        fs::create_dir_all(parent)?;
    }
    let json = serde_json::to_string_pretty(creds)?;
    write_secret(path, &json)
}

fn load_seen(path: &str) -> HashSet<String> {
    fs::read_to_string(path)
        .ok()
        .and_then(|value| serde_json::from_str(&value).ok())
        .unwrap_or_default()
}

fn save_seen(path: &str, seen: &HashSet<String>) -> Result<()> {
    write_secret(path, &serde_json::to_string_pretty(seen)?)
}

fn main() -> Result<()> {
    let credentials_path = std::env::var("OKTA_POC_FCM_DEVICE")
        .unwrap_or_else(|_| CREDENTIALS.to_string());
    let token_path = std::env::var("OKTA_POC_FCM_TOKEN_OUT")
        .unwrap_or_else(|_| TOKEN_OUT.to_string());
    let challenge_path = std::env::var("OKTA_POC_FCM_CHALLENGE_OUT")
        .unwrap_or_else(|_| CHALLENGE_OUT.to_string());
    let seen_path = std::env::var("OKTA_POC_FCM_SEEN")
        .unwrap_or_else(|_| "live-captures/okta-fcm-seen.json".to_string());
    let seen_transactions = Arc::new(Mutex::new(load_seen(&seen_path)));

    let mut client = FcmClient::new(
        API_KEY.to_string(),
        APP_ID.to_string(),
        PROJECT_ID.to_string(),
    )?;
    client.android_app = Some(AndroidApp {
        gcm_sender_id: SENDER_ID.to_string(),
        android_package: PACKAGE.to_string(),
        android_package_cert: PACKAGE_CERT.to_string(),
    });

    if Path::new(&credentials_path).exists() {
        let bytes = fs::read(&credentials_path)?;
        let creds: DeviceCredentials = serde_json::from_slice(&bytes)?;
        if creds.android_id == 0
            || creds.security_token == 0
            || creds.private_key_base64.is_empty()
            || creds.auth_secret_base64.is_empty()
            || creds.fcm_token.is_empty()
        {
            return Err(fcm_receiver_rs::Error::InvalidData(
                "incomplete FCM device credentials",
            ));
        }
        client.fcm_token = Some(creds.fcm_token);
        client.android_id = creds.android_id;
        client.security_token = creds.security_token;
        client.load_keys(&creds.private_key_base64, &creds.auth_secret_base64)?;
        println!("Loaded existing Okta-project FCM registration; secrets not printed");
    } else {
        let (private_key_b64, auth_secret_b64) = client.create_new_keys()?;
        client.load_keys(&private_key_b64, &auth_secret_b64)?;
        let (fcm_token, _gcm_token, android_id, security_token) = client.register()?;
        let creds = DeviceCredentials {
            fcm_token: fcm_token.clone(),
            android_id,
            security_token,
            private_key_base64: private_key_b64,
            auth_secret_base64: auth_secret_b64,
        };
        save_credentials(&credentials_path, &creds)?;
        println!("Okta-project FCM registration succeeded; device credentials stored mode 0600");
    }

    let token = client
        .fcm_token
        .as_ref()
        .ok_or_else(|| fcm_receiver_rs::Error::InvalidData("FCM token missing"))?;
    write_secret(&token_path, token)?;
    println!("FCM token written to {token_path} (mode 0600; not printed)");

    let output_path = challenge_path.clone();
    let seen_path = seen_path.clone();
    let seen_transactions = seen_transactions.clone();
    client.on_raw_message = Some(Arc::new(move |message| {
        if message.from.as_deref() != Some(SENDER_ID) {
            println!("Ignoring FCM data message from an unexpected sender");
            return;
        }
        let mut keys: Vec<&str> = message.app_data.iter().map(|item| item.key.as_str()).collect();
        keys.sort_unstable();
        keys.dedup();
        println!("FCM data message from expected Okta sender; keys: {}", keys.join(","));
        let challenge = message
            .app_data
            .iter()
            .find(|item| item.key == "challenge" || item.key == "okta.challenge")
            .map(|item| item.value.as_str());
        let Some(challenge) = challenge else {
            println!("Message has no challenge field; not an IDX challenge");
            return;
        };
        let transaction = message
            .app_data
            .iter()
            .find(|item| item.key == "transactionId")
            .map(|item| item.value.as_str());
        if transaction.is_some_and(|id| seen_transactions.lock().unwrap().contains(id)) {
            println!("Ignoring previously handled FCM transaction and waiting for the next message");
            return;
        }
        if challenge.is_empty() || challenge.len() > 65536 {
            eprintln!("Rejected empty or oversized challenge");
            return;
        }
        if is_expired(challenge) {
            // Do not disconnect: the next queued message may be fresh.
            println!("Ignoring expired FCM challenge and waiting for the next message");
            return;
        }
        match write_secret(&output_path, challenge) {
            Ok(()) => {
                if let Some(transaction) = transaction {
                    let mut seen = seen_transactions.lock().unwrap();
                    seen.insert(transaction.to_string());
                    if let Err(error) = save_seen(&seen_path, &seen) {
                        eprintln!("Could not persist handled transaction ID: {error}");
                    }
                }
                println!(
                    "OKTA_CHALLENGE_RECEIVED bytes={} saved={}",
                    challenge.len(), output_path
                );
                let _ = std::io::stdout().flush();
                std::process::exit(0);
            }
            Err(error) => eprintln!("Could not save challenge securely: {error}"),
        }
    }));
    client.on_data_message = Some(Arc::new(|payload| {
        // Android direct-token messages normally arrive as raw app_data. Do
        // not log an encrypted payload because it may contain a live JWS.
        println!("Received encrypted FCM payload ({} bytes); raw challenge handler did not apply", payload.len());
    }));

    println!("Starting FCM listener; trigger one sign-in for the enrolled test user");
    client.start_listening()?;
    Ok(())
}
