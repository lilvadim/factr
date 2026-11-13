use std::{
    collections::HashMap,
    sync::{Mutex, OnceLock},
};

use base64::prelude::*;
use factr_core::vault::{self, ProtectedVaultKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use uuid::Uuid;
use windows::{
    Security::{
        Credentials::{KeyCredentialCreationOption, KeyCredentialManager, KeyCredentialStatus},
        Cryptography::CryptographicBuffer,
    },
    Win32::{
        Security::Credentials::{
            CRED_PERSIST_LOCAL_MACHINE, CRED_TYPE_GENERIC, CREDENTIALW, CredFree, CredReadW,
            CredWriteW,
        },
        System::WinRT::{RO_INIT_MULTITHREADED, RoInitialize, RoUninitialize},
    },
    core::{Array, HSTRING, PWSTR, h},
};
use zeroize::{Zeroize, Zeroizing};

const PROVIDER: &str = "windows.hello";
const HELLO_CREDENTIAL: &HSTRING = h!("FactrVaultProtectionV1");

#[derive(Serialize, Deserialize)]
struct ProtectedKey {
    vault_id: Uuid,
    challenge: String,
    wrapped_key_b64: String,
}

struct Runtime;

impl Runtime {
    /// Initializes WinRT on a protection worker thread.
    fn new() -> Result<Self, String> {
        unsafe { RoInitialize(RO_INIT_MULTITHREADED) }.map_err(|e| e.to_string())?;
        Ok(Self)
    }
}

impl Drop for Runtime {
    /// Releases this thread's WinRT initialization.
    fn drop(&mut self) {
        unsafe { RoUninitialize() };
    }
}

/// Checks Windows Hello availability without displaying authentication UI.
pub fn available() -> bool {
    std::thread::spawn(|| {
        let Ok(_runtime) = Runtime::new() else {
            return false;
        };
        KeyCredentialManager::IsSupportedAsync()
            .and_then(|operation| operation.join())
            .unwrap_or(false)
    })
    .join()
    .unwrap_or(false)
}

/// Returns the cached presence of local Credential Manager entries.
fn local_keys() -> &'static Mutex<HashMap<Uuid, bool>> {
    static KEYS: OnceLock<Mutex<HashMap<Uuid, bool>>> = OnceLock::new();
    KEYS.get_or_init(Mutex::default)
}

/// Matches a protection record to an entry available to the current Windows user.
pub fn is_local(protected_key: &ProtectedVaultKey) -> bool {
    if protected_key.provider != PROVIDER || protected_key.version != 1 {
        return false;
    }
    let Ok(mut keys) = local_keys().lock() else {
        return false;
    };
    *keys.entry(protected_key.id).or_insert_with(|| {
        read_key(protected_key.id)
            .is_ok_and(|entry| entry.wrapped_key_b64 == protected_key.wrapped_key_b64)
    })
}

/// Names an individual vault protection entry in Credential Manager.
fn credential_name(id: Uuid) -> HSTRING {
    HSTRING::from(format!("Factr/VaultProtection/{id}"))
}

/// Copies a saved envelope before releasing the native credential allocation.
fn read_key(id: Uuid) -> Result<ProtectedKey, String> {
    let target = credential_name(id);
    let mut pointer = std::ptr::null_mut();
    unsafe { CredReadW(&target, CRED_TYPE_GENERIC, None, &mut pointer) }
        .map_err(|e| format!("System key is unavailable; use the recovery key: {e}"))?;
    let result = unsafe {
        let credential = &*pointer;
        if credential.CredentialBlob.is_null() || credential.CredentialBlobSize == 0 {
            Err("Empty system key entry".to_string())
        } else {
            let bytes = std::slice::from_raw_parts(
                credential.CredentialBlob,
                credential.CredentialBlobSize as usize,
            );
            serde_json::from_slice(bytes).map_err(|e| e.to_string())
        }
    };
    unsafe { CredFree(pointer.cast()) };
    result
}

/// Saves only the public challenge and encrypted vault key on this machine.
fn write_key(id: Uuid, protected: &ProtectedKey) -> Result<(), String> {
    let target = credential_name(id);
    let mut bytes = serde_json::to_vec(protected).map_err(|e| e.to_string())?;
    let credential = CREDENTIALW {
        Type: CRED_TYPE_GENERIC,
        TargetName: PWSTR(target.as_ptr().cast_mut()),
        CredentialBlobSize: bytes
            .len()
            .try_into()
            .map_err(|_| "System key entry is too large")?,
        CredentialBlob: bytes.as_mut_ptr(),
        Persist: CRED_PERSIST_LOCAL_MACHINE,
        ..Default::default()
    };
    unsafe { CredWriteW(&credential, 0) }.map_err(|e| e.to_string())
}

/// Derives a wrapping key from a Windows Hello authorized signature.
fn wrapping_key(challenge: &[u8], create: bool) -> Result<Zeroizing<[u8; 32]>, String> {
    let _runtime = Runtime::new()?;
    let result = if create {
        KeyCredentialManager::RequestCreateAsync(
            HELLO_CREDENTIAL,
            KeyCredentialCreationOption::FailIfExists,
        )
    } else {
        KeyCredentialManager::OpenAsync(HELLO_CREDENTIAL)
    }
    .and_then(|operation| operation.join())
    .map_err(|e| e.to_string())?;
    let result = if create
        && result.Status().map_err(|e| e.to_string())?
            == KeyCredentialStatus::CredentialAlreadyExists
    {
        KeyCredentialManager::OpenAsync(HELLO_CREDENTIAL)
            .and_then(|operation| operation.join())
            .map_err(|e| e.to_string())?
    } else {
        result
    };
    let status = result.Status().map_err(|e| e.to_string())?;
    if status != KeyCredentialStatus::Success {
        return Err(format!(
            "Windows Hello key is unavailable or authentication was cancelled ({status:?}); use the recovery key"
        ));
    }
    let credential = result.Credential().map_err(|e| e.to_string())?;
    let buffer = CryptographicBuffer::CreateFromByteArray(challenge).map_err(|e| e.to_string())?;
    let signed = credential
        .RequestSignAsync(&buffer)
        .and_then(|operation| operation.join())
        .map_err(|e| e.to_string())?;
    let status = signed.Status().map_err(|e| e.to_string())?;
    if status != KeyCredentialStatus::Success {
        return Err(format!(
            "Windows Hello authentication failed or was cancelled ({status:?})"
        ));
    }
    let mut signature = Array::new();
    CryptographicBuffer::CopyToByteArray(
        &signed.Result().map_err(|e| e.to_string())?,
        &mut signature,
    )
    .map_err(|e| e.to_string())?;
    let key = Sha256::new()
        .chain_update(b"Factr Windows Hello wrapping key V1")
        .chain_update(signature.as_slice())
        .finalize();
    signature.iter_mut().for_each(Zeroize::zeroize);
    Ok(Zeroizing::new(key.into()))
}

/// Creates a Hello-protected vault key and persists its encrypted envelope.
pub fn protect(id: Uuid, key: &[u8; 32], _reason: &str) -> Result<ProtectedVaultKey, String> {
    let mut protected_key = ProtectedVaultKey {
        id: Uuid::new_v4(),
        provider: PROVIDER.to_string(),
        version: 1,
        metadata: serde_json::Value::Null,
        wrapped_key_b64: String::new(),
    };
    let challenge = vault::random_key();
    let wrapping_key = wrapping_key(&*challenge, true)?;
    protected_key.wrapped_key_b64 =
        vault::encrypt_bound(key, &wrapping_key, &protected_key.context(id))?;
    write_key(
        protected_key.id,
        &ProtectedKey {
            vault_id: id,
            challenge: BASE64_STANDARD.encode(challenge.as_slice()),
            wrapped_key_b64: protected_key.wrapped_key_b64.clone(),
        },
    )?;
    local_keys()
        .lock()
        .map_err(|e| e.to_string())?
        .insert(protected_key.id, true);
    Ok(protected_key)
}

/// Recovers a vault key using its saved challenge and a fresh Hello signature.
pub fn unlock(
    id: Uuid,
    protected_key: &ProtectedVaultKey,
    _reason: &str,
) -> Result<Zeroizing<[u8; 32]>, String> {
    if protected_key.provider != PROVIDER || protected_key.version != 1 {
        return Err("Unsupported system protected key".to_string());
    }
    let entry = read_key(protected_key.id)?;
    if entry.vault_id != id || entry.wrapped_key_b64 != protected_key.wrapped_key_b64 {
        return Err("System key does not match this vault".to_string());
    }
    let challenge = BASE64_STANDARD
        .decode(&entry.challenge)
        .map_err(|e| e.to_string())?;
    if challenge.len() != 32 {
        return Err("Invalid Windows Hello challenge".to_string());
    }
    let wrapping_key = wrapping_key(&challenge, false)?;
    let bytes = vault::decrypt_bound(
        &entry.wrapped_key_b64,
        &wrapping_key,
        &protected_key.context(id),
    )
    .map_err(|e| e.to_string())?;
    Ok(Zeroizing::new(
        <[u8; 32]>::try_from(bytes.as_slice()).map_err(|_| "Invalid vault key length")?,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    /// Rejects unrelated providers before accessing Windows services.
    fn rejects_other_providers() {
        let id = Uuid::new_v4();
        let (protected, _) = factr_core::recovery::create(id, &vault::random_key()).unwrap();
        assert!(!is_local(&protected));
        assert!(unlock(id, &protected, "Test").is_err());
    }

    #[test]
    #[ignore = "Requires configured Windows Hello and interactive authentication"]
    /// Checks persisted recovery across separate WinRT initializations.
    fn native_protection_round_trip() {
        let id = Uuid::new_v4();
        let key = vault::random_key();
        let protected = protect(id, &key, "Test").unwrap();
        let result = unlock(id, &protected, "Test");
        assert!(unlock(Uuid::new_v4(), &protected, "Test").is_err());
        unsafe {
            windows::Win32::Security::Credentials::CredDeleteW(
                &credential_name(protected.id),
                CRED_TYPE_GENERIC,
                None,
            )
        }
        .unwrap();
        assert_eq!(*result.unwrap(), *key);
    }
}
