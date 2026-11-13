use std::{
    ffi::{CStr, c_char},
    sync::OnceLock,
};

use base64::prelude::*;
use serde::{Deserialize, Serialize};
use uuid::Uuid;
use zeroize::Zeroizing;

use factr_core::vault::ProtectedVaultKey;

pub const PROVIDER: &str = "macos.secure-enclave";

unsafe extern "C" {
    /// Executes a native request and returns an owned JSON reply.
    fn factr_system_protection(bytes: *const u8, count: usize) -> *mut c_char;
    /// Wipes and releases a native reply.
    fn factr_system_protection_free(pointer: *mut c_char);
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct Request<'a> {
    operation: &'a str,
    context: String,
    secret: Option<String>,
    protected_key: Option<String>,
    reason: &'a str,
}

impl Drop for Request<'_> {
    // Wipe the encoded secret when the request is released.
    fn drop(&mut self) {
        use zeroize::Zeroize;
        self.secret.zeroize();
    }
}

/// Exchanges a serialized request and response with the native bridge.
fn call(
    operation: &str,
    context: &[u8],
    secret: Option<&[u8]>,
    protected: Option<&str>,
    reason: &str,
) -> Result<Zeroizing<Vec<u8>>, String> {
    #[derive(Deserialize)]
    struct Reply {
        data: Option<String>,
        error: Option<String>,
    }
    let request = Request {
        operation,
        context: BASE64_STANDARD.encode(context),
        secret: secret.map(|bytes| BASE64_STANDARD.encode(bytes)),
        protected_key: protected.map(str::to_owned),
        reason,
    };
    let bytes = Zeroizing::new(serde_json::to_vec(&request).map_err(|e| e.to_string())?);
    // The Swift bridge returns a malloc-owned, NUL-terminated JSON reply.
    // Copy it before asking the bridge to wipe and release its allocation.
    let pointer = unsafe { factr_system_protection(bytes.as_ptr(), bytes.len()) };
    if pointer.is_null() {
        return Err("System protection returned no result".to_string());
    }
    let result = unsafe { Zeroizing::new(CStr::from_ptr(pointer).to_bytes().to_vec()) };
    unsafe {
        factr_system_protection_free(pointer);
    }
    let reply: Reply = serde_json::from_slice(&result).map_err(|e| e.to_string())?;
    if let Some(error) = reply.error {
        return Err(error);
    }
    let data = Zeroizing::new(reply.data.ok_or("System protection returned no data")?);
    BASE64_STANDARD
        .decode(data.as_bytes())
        .map(Zeroizing::new)
        .map_err(|e| e.to_string())
}

/// Returns the cached device identifier after checking protection availability.
pub fn device_id() -> Result<String, String> {
    static DEVICE: OnceLock<Result<String, String>> = OnceLock::new();
    DEVICE
        .get_or_init(|| {
            String::from_utf8(call("available", &[], None, None, "")?.to_vec())
                .map_err(|e| e.to_string())
        })
        .clone()
}

/// Creates a device-bound protected key using Secure Enclave.
pub fn protect(id: Uuid, key: &[u8; 32], reason: &str) -> Result<ProtectedVaultKey, String> {
    let device = device_id()?;
    let mut protected_key = ProtectedVaultKey {
        id: Uuid::new_v4(),
        provider: PROVIDER.to_string(),
        version: 1,
        metadata: serde_json::json!({"device": device}),
        wrapped_key_b64: String::new(),
    };
    let protected = call(
        "protect",
        &protected_key.context(id),
        Some(key),
        None,
        reason,
    )?;
    protected_key.wrapped_key_b64 = BASE64_STANDARD.encode(&*protected);
    Ok(protected_key)
}

/// Validates a protected key and recovers its key through the native bridge.
pub fn unlock(
    id: Uuid,
    protected_key: &ProtectedVaultKey,
    reason: &str,
) -> Result<Zeroizing<[u8; 32]>, String> {
    if protected_key.provider != PROVIDER || protected_key.version != 1 {
        return Err("Unsupported system protected key".to_string());
    }
    let bytes = call(
        "unlock",
        &protected_key.context(id),
        None,
        Some(&protected_key.wrapped_key_b64),
        reason,
    )?;
    let key = <[u8; 32]>::try_from(bytes.as_slice()).map_err(|_| "Invalid system key length")?;
    Ok(Zeroizing::new(key))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    #[ignore = "Requires Secure Enclave and interactive system authentication"]
    /// Checks native key protection and authenticated recovery.
    fn native_protection_round_trip() {
        let id = Uuid::new_v4();
        let key = factr_core::vault::random_key();
        let reason = "Test Factr system protection";
        let protected_key = protect(id, &key, reason).unwrap();
        assert!(crate::is_local(&protected_key));
        assert_eq!(*unlock(id, &protected_key, reason).unwrap(), *key);
    }
}
