use crate::SystemProtectionError;
use std::{
    collections::HashMap,
    sync::{Mutex, OnceLock},
};

use base64::prelude::*;
use factr_core::vault::{self, KEY_LEN, ProtectedVaultKey};
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
const VERSION: u32 = 1;
const WRAPPING_KEY_INFO: &[u8] = b"Factr Windows Hello wrapping key V1";
const SIGN_IN_SETTINGS: &HSTRING = h!("ms-settings:signinoptions");
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
    fn new() -> Result<Self, SystemProtectionError> {
        unsafe { RoInitialize(RO_INIT_MULTITHREADED) }.map_err(SystemProtectionError::platform)?;
        Ok(Self)
    }
}

impl Drop for Runtime {
    /// Releases this thread's WinRT initialization.
    fn drop(&mut self) {
        unsafe { RoUninitialize() };
    }
}

/// Checks Windows Hello availability on the current worker thread.
pub fn check_availability() -> Result<bool, SystemProtectionError> {
    let _runtime = Runtime::new()?;
    KeyCredentialManager::IsSupportedAsync()
        .and_then(|operation| operation.join())
        .map_err(SystemProtectionError::platform)
}

/// Opens the Windows sign-in settings page.
pub fn open_settings() -> Result<(), SystemProtectionError> {
    let _runtime = Runtime::new()?;
    let uri = windows::Foundation::Uri::CreateUri(SIGN_IN_SETTINGS)
        .map_err(SystemProtectionError::platform)?;
    let opened = windows::System::Launcher::LaunchUriAsync(&uri)
        .and_then(|operation| operation.join())
        .map_err(SystemProtectionError::platform)?;
    if !opened {
        return Err(SystemProtectionError::SettingsUnavailable);
    }
    Ok(())
}

/// Returns the cached presence of local Credential Manager entries.
fn local_keys() -> &'static Mutex<HashMap<Uuid, bool>> {
    static KEYS: OnceLock<Mutex<HashMap<Uuid, bool>>> = OnceLock::new();
    KEYS.get_or_init(Mutex::default)
}

/// Matches a protection record to an entry available to the current Windows user.
pub fn is_local(protected_key: &ProtectedVaultKey) -> bool {
    if protected_key.provider != PROVIDER || protected_key.version != VERSION {
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
fn read_key(id: Uuid) -> Result<ProtectedKey, SystemProtectionError> {
    let target = credential_name(id);
    let mut pointer = std::ptr::null_mut();
    unsafe { CredReadW(&target, CRED_TYPE_GENERIC, None, &mut pointer) }.map_err(|error| {
        if error.code()
            == windows::core::HRESULT::from_win32(windows::Win32::Foundation::ERROR_NOT_FOUND.0)
        {
            SystemProtectionError::KeyMissing
        } else {
            SystemProtectionError::platform(error)
        }
    })?;
    let result = unsafe {
        let credential = &*pointer;
        if credential.CredentialBlob.is_null() || credential.CredentialBlobSize == 0 {
            Err(SystemProtectionError::InvalidKey)
        } else {
            let bytes = std::slice::from_raw_parts(
                credential.CredentialBlob,
                credential.CredentialBlobSize as usize,
            );
            serde_json::from_slice(bytes).map_err(SystemProtectionError::platform)
        }
    };
    unsafe { CredFree(pointer.cast()) };
    result
}

/// Saves only the public challenge and encrypted vault key on this machine.
fn write_key(id: Uuid, protected: &ProtectedKey) -> Result<(), SystemProtectionError> {
    let target = credential_name(id);
    let mut bytes = serde_json::to_vec(protected).map_err(SystemProtectionError::platform)?;
    let credential = CREDENTIALW {
        Type: CRED_TYPE_GENERIC,
        TargetName: PWSTR(target.as_ptr().cast_mut()),
        CredentialBlobSize: bytes
            .len()
            .try_into()
            .map_err(|_| SystemProtectionError::InvalidKey)?,
        CredentialBlob: bytes.as_mut_ptr(),
        Persist: CRED_PERSIST_LOCAL_MACHINE,
        ..Default::default()
    };
    unsafe { CredWriteW(&credential, 0) }.map_err(SystemProtectionError::platform)
}

/// Classifies Windows Hello outcomes without parsing native error text.
fn credential_error(status: KeyCredentialStatus) -> SystemProtectionError {
    match status {
        KeyCredentialStatus::UserCanceled => SystemProtectionError::AuthenticationCancelled,
        KeyCredentialStatus::NotFound => SystemProtectionError::KeyMissing,
        _ => SystemProtectionError::AuthenticationDenied,
    }
}

/// Derives a wrapping key from a Windows Hello authorized signature.
fn wrapping_key(
    challenge: &[u8],
    create: bool,
) -> Result<Zeroizing<[u8; KEY_LEN]>, SystemProtectionError> {
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
    .map_err(SystemProtectionError::platform)?;
    let result = if create
        && result.Status().map_err(SystemProtectionError::platform)?
            == KeyCredentialStatus::CredentialAlreadyExists
    {
        KeyCredentialManager::OpenAsync(HELLO_CREDENTIAL)
            .and_then(|operation| operation.join())
            .map_err(SystemProtectionError::platform)?
    } else {
        result
    };
    let status = result.Status().map_err(SystemProtectionError::platform)?;
    if status != KeyCredentialStatus::Success {
        return Err(credential_error(status));
    }
    let credential = result
        .Credential()
        .map_err(SystemProtectionError::platform)?;
    let buffer = CryptographicBuffer::CreateFromByteArray(challenge)
        .map_err(SystemProtectionError::platform)?;
    let signed = credential
        .RequestSignAsync(&buffer)
        .and_then(|operation| operation.join())
        .map_err(SystemProtectionError::platform)?;
    let status = signed.Status().map_err(SystemProtectionError::platform)?;
    if status != KeyCredentialStatus::Success {
        return Err(credential_error(status));
    }
    let mut signature = Array::new();
    CryptographicBuffer::CopyToByteArray(
        &signed.Result().map_err(SystemProtectionError::platform)?,
        &mut signature,
    )
    .map_err(SystemProtectionError::platform)?;
    let key = Sha256::new()
        .chain_update(WRAPPING_KEY_INFO)
        .chain_update(signature.as_slice())
        .finalize();
    signature.iter_mut().for_each(Zeroize::zeroize);
    Ok(Zeroizing::new(key.into()))
}

/// Creates a Hello-protected vault key and persists its encrypted envelope.
pub fn protect(
    id: Uuid,
    key: &[u8; KEY_LEN],
    _reason: &str,
) -> Result<ProtectedVaultKey, SystemProtectionError> {
    let challenge = vault::random_key();
    let wrapping_key = wrapping_key(&*challenge, true)?;
    let protected_key_id = Uuid::new_v4();
    let context = vault::encryption_context(id, protected_key_id, PROVIDER, VERSION);
    let protected_key = ProtectedVaultKey {
        id: protected_key_id,
        provider: PROVIDER.to_string(),
        version: VERSION,
        metadata: serde_json::Value::Null,
        wrapped_key_b64: vault::encrypt_bound(key, &wrapping_key, &context)?,
    };
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
        .map_err(|_| SystemProtectionError::StateUnavailable)?
        .insert(protected_key.id, true);
    Ok(protected_key)
}

/// Recovers a vault key using its saved challenge and a fresh Hello signature.
pub fn unlock(
    id: Uuid,
    protected_key: &ProtectedVaultKey,
    _reason: &str,
) -> Result<Zeroizing<[u8; KEY_LEN]>, SystemProtectionError> {
    if protected_key.provider != PROVIDER || protected_key.version != VERSION {
        return Err(SystemProtectionError::UnsupportedKey);
    }
    let entry = read_key(protected_key.id)?;
    if entry.vault_id != id || entry.wrapped_key_b64 != protected_key.wrapped_key_b64 {
        return Err(SystemProtectionError::KeyMismatch);
    }
    let challenge = BASE64_STANDARD
        .decode(&entry.challenge)
        .map_err(SystemProtectionError::platform)?;
    if challenge.len() != KEY_LEN {
        return Err(SystemProtectionError::InvalidKey);
    }
    let wrapping_key = wrapping_key(&challenge, false)?;
    let bytes = vault::decrypt_bound(
        &entry.wrapped_key_b64,
        &wrapping_key,
        &vault::encryption_context(
            id,
            protected_key.id,
            &protected_key.provider,
            protected_key.version,
        ),
    )?;
    Ok(Zeroizing::new(
        <[u8; KEY_LEN]>::try_from(bytes.as_slice())
            .map_err(|_| SystemProtectionError::InvalidKey)?,
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
