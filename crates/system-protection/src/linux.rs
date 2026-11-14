use std::{collections::HashMap, fs, sync::OnceLock};

use factr_core::vault::{self, KEY_LEN, ProtectedVaultKey};
use secret_service::{EncryptionType, blocking::SecretService};
use uuid::Uuid;
use zbus::{
    blocking::{Connection, Proxy},
    zvariant::Value,
};
use zeroize::Zeroizing;

const PROVIDER: &str = "linux-secret-service";
const VERSION: u32 = 1;
const SECRET_SERVICE: &str = "org.freedesktop.secrets";
const ALLOW_USER_INTERACTION: u32 = 1;
const ACTION: &str = "com.factr.unlock";
const POLICY_PATH: &str = "/usr/share/polkit-1/actions/com.factr.policy";
const POLKIT_SERVICE: &str = "org.freedesktop.PolicyKit1";
const POLKIT_AUTHORITY_PATH: &str = "/org/freedesktop/PolicyKit1/Authority";
const POLKIT_AUTHORITY_INTERFACE: &str = "org.freedesktop.PolicyKit1.Authority";
const POLKIT_CHECK_AUTHORIZATION: &str = "CheckAuthorization";
const POLKIT_SUBJECT_KIND: &str = "system-bus-name";
const POLKIT_SUBJECT_NAME: &str = "name";
const POLKIT_NO_CANCELLATION_ID: &str = "";

/// Identifies the current machine and session user without exposing secrets.
fn device_id() -> Result<&'static str, String> {
    static DEVICE: OnceLock<Result<String, String>> = OnceLock::new();
    DEVICE
        .get_or_init(|| {
            let machine = fs::read_to_string("/etc/machine-id").map_err(|e| e.to_string())?;
            if machine.trim().is_empty() {
                return Err("Missing machine ID".to_string());
            }
            let connection = Connection::session().map_err(|e| e.to_string())?;
            let bus =
                zbus::blocking::fdo::DBusProxy::new(&connection).map_err(|e| e.to_string())?;
            let name = connection.unique_name().ok_or("Missing session bus name")?;
            let user = bus
                .get_connection_unix_user(name.clone().into())
                .map_err(|e| e.to_string())?;
            Ok(format!("{}:{user}", machine.trim()))
        })
        .as_ref()
        .map(String::as_str)
        .map_err(Clone::clone)
}

/// Checks the session keyring and installed authentication policy without prompting.
pub fn available() -> bool {
    static AVAILABLE: OnceLock<bool> = OnceLock::new();
    *AVAILABLE.get_or_init(|| {
        if !std::path::Path::new(POLICY_PATH).is_file() || device_id().is_err() {
            return false;
        }
        let Ok(connection) = Connection::session() else {
            return false;
        };
        let Ok(bus) = zbus::blocking::fdo::DBusProxy::new(&connection) else {
            return false;
        };
        bus.list_names()
            .is_ok_and(|names| names.iter().any(|name| name.as_str() == SECRET_SERVICE))
            || bus
                .list_activatable_names()
                .is_ok_and(|names| names.iter().any(|name| name.as_str() == SECRET_SERVICE))
    })
}

/// Matches a Linux protection record to its machine and user.
pub fn is_local(protected_key: &ProtectedVaultKey) -> bool {
    protected_key.provider == PROVIDER
        && protected_key.version == VERSION
        && device_id().is_ok_and(|device| protected_key.metadata["device"].as_str() == Some(device))
}

/// Requests fresh authorization from the desktop's Polkit agent.
fn authenticate() -> Result<(), String> {
    let connection = Connection::system().map_err(|e| e.to_string())?;
    let proxy = Proxy::new(
        &connection,
        POLKIT_SERVICE,
        POLKIT_AUTHORITY_PATH,
        POLKIT_AUTHORITY_INTERFACE,
    )
    .map_err(|e| e.to_string())?;
    let name = connection.unique_name().ok_or("Missing system bus name")?;
    let subject = (
        POLKIT_SUBJECT_KIND,
        HashMap::from([(POLKIT_SUBJECT_NAME, Value::from(name.as_str()))]),
    );
    let details = HashMap::<&str, &str>::new();
    let (authorized, _, _): (bool, bool, HashMap<String, String>) = proxy
        .call(
            POLKIT_CHECK_AUTHORIZATION,
            &(
                subject,
                ACTION,
                details,
                ALLOW_USER_INTERACTION,
                POLKIT_NO_CANCELLATION_ID,
            ),
        )
        .map_err(|e| format!("System authentication failed: {e}"))?;
    if !authorized {
        return Err("System authentication was denied or cancelled".to_string());
    }
    Ok(())
}

/// Creates stable lookup attributes for a vault's keyring entry.
fn attributes<'a>(vault: &'a str, entry: &'a str) -> HashMap<&'a str, &'a str> {
    HashMap::from([
        ("application", "factr-auth"),
        ("vault", vault),
        ("entry", entry),
    ])
}

/// Encrypts a vault key with a random wrapping key held by Secret Service.
pub fn protect(id: Uuid, key: &[u8; KEY_LEN], _reason: &str) -> Result<ProtectedVaultKey, String> {
    authenticate()?;
    let wrapping_key = vault::random_key();
    let protected_key_id = Uuid::new_v4();
    let context = vault::encryption_context(id, protected_key_id, PROVIDER, VERSION);
    let protected_key = ProtectedVaultKey {
        id: protected_key_id,
        provider: PROVIDER.to_string(),
        version: VERSION,
        metadata: serde_json::json!({"device": device_id()?}),
        wrapped_key_b64: vault::encrypt_bound(key, &wrapping_key, &context)?,
    };
    let service = SecretService::connect(EncryptionType::Dh).map_err(|e| e.to_string())?;
    let collection = match service.get_default_collection() {
        Ok(collection) => collection,
        Err(secret_service::Error::NoResult) => service
            .create_collection("Factr", "default")
            .map_err(|e| e.to_string())?,
        Err(error) => return Err(error.to_string()),
    };
    collection.unlock().map_err(|e| e.to_string())?;
    collection
        .create_item(
            "Factr vault protection",
            attributes(&id.to_string(), &protected_key.id.to_string()),
            &*wrapping_key,
            false,
            "application/octet-stream",
        )
        .map_err(|e| e.to_string())?;
    Ok(protected_key)
}

/// Authenticates the user and unwraps a vault key using Secret Service.
pub fn unlock(
    id: Uuid,
    protected_key: &ProtectedVaultKey,
    _reason: &str,
) -> Result<Zeroizing<[u8; KEY_LEN]>, String> {
    if !is_local(protected_key) {
        return Err("Unsupported or non-local system protected key".to_string());
    }
    authenticate()?;
    let service = SecretService::connect(EncryptionType::Dh).map_err(|e| e.to_string())?;
    let result = service
        .search_items(attributes(&id.to_string(), &protected_key.id.to_string()))
        .map_err(|e| e.to_string())?;
    let item = result
        .unlocked
        .first()
        .or_else(|| result.locked.first())
        .ok_or("System key is missing; use the recovery key")?;
    item.unlock().map_err(|e| e.to_string())?;
    let secret = Zeroizing::new(item.get_secret().map_err(|e| e.to_string())?);
    let wrapping_key = Zeroizing::new(
        <[u8; KEY_LEN]>::try_from(secret.as_slice()).map_err(|_| "Invalid system key length")?,
    );
    let bytes = vault::decrypt_bound(
        &protected_key.wrapped_key_b64,
        &wrapping_key,
        &vault::encryption_context(
            id,
            protected_key.id,
            &protected_key.provider,
            protected_key.version,
        ),
    )
    .map_err(|e| e.to_string())?;
    Ok(Zeroizing::new(
        <[u8; KEY_LEN]>::try_from(bytes.as_slice()).map_err(|_| "Invalid vault key length")?,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    /// Rejects unsupported records before requesting authentication.
    fn rejects_other_providers() {
        let id = Uuid::new_v4();
        let (protected_key, _) = factr_core::recovery::create(id, &vault::random_key()).unwrap();
        assert!(!is_local(&protected_key));
        assert!(unlock(id, &protected_key, "Test").is_err());
    }

    #[test]
    #[ignore = "Requires Secret Service, the Factr Polkit policy, and interactive authentication"]
    /// Checks persistent protection and rejects a mismatched vault context.
    fn system_protection_round_trip() {
        let id = Uuid::new_v4();
        let key = vault::random_key();
        let protected_key = protect(id, &key, "Test").unwrap();
        assert_eq!(*unlock(id, &protected_key, "Test").unwrap(), *key);
        assert!(unlock(Uuid::new_v4(), &protected_key, "Test").is_err());
        let service = SecretService::connect(EncryptionType::Dh).unwrap();
        let items = service
            .search_items(attributes(&id.to_string(), &protected_key.id.to_string()))
            .unwrap();
        for item in items.unlocked.into_iter().chain(items.locked) {
            item.delete().unwrap();
        }
    }
}
