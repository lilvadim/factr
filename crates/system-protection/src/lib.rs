use factr_core::vault::ProtectedVaultKey;
use uuid::Uuid;
use zeroize::Zeroizing;

#[cfg(target_os = "macos")]
mod macos;

/// Checks whether system protection is available on this device.
pub fn available() -> bool {
    #[cfg(target_os = "macos")]
    return macos::device_id().is_ok();
    #[cfg(not(target_os = "macos"))]
    false
}

/// Checks whether a protected key belongs to the current device and provider.
pub fn is_local(protected_key: &ProtectedVaultKey) -> bool {
    #[cfg(target_os = "macos")]
    return protected_key.provider == macos::PROVIDER
        && protected_key.version == 1
        && macos::device_id()
            .is_ok_and(|id| protected_key.metadata["device"].as_str() == Some(&id));
    #[cfg(not(target_os = "macos"))]
    {
        let _ = protected_key;
        false
    }
}

/// Protects a vault key with mandatory system authentication.
pub fn protect(id: Uuid, key: &[u8; 32], reason: &str) -> Result<ProtectedVaultKey, String> {
    #[cfg(target_os = "macos")]
    return macos::protect(id, key, reason);
    #[cfg(not(target_os = "macos"))]
    {
        let _ = (id, key, reason);
        Err("System protection is not implemented for this operating system".to_string())
    }
}

/// Recovers a vault key after system authentication.
pub fn unlock(
    id: Uuid,
    protected_key: &ProtectedVaultKey,
    reason: &str,
) -> Result<Zeroizing<[u8; 32]>, String> {
    #[cfg(target_os = "macos")]
    return macos::unlock(id, protected_key, reason);
    #[cfg(not(target_os = "macos"))]
    {
        let _ = (id, protected_key, reason);
        Err("This system protection provider is unavailable".to_string())
    }
}
