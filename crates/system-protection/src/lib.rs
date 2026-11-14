use factr_core::vault::{KEY_LEN, ProtectedVaultKey};
use uuid::Uuid;
use zeroize::Zeroizing;

#[cfg(target_os = "linux")]
mod linux;
#[cfg(target_os = "macos")]
mod macos;
#[cfg(target_os = "windows")]
mod windows;

/// Checks whether system protection is available on this device.
pub fn available() -> bool {
    check_availability().unwrap_or(false)
}

/// Rechecks platform availability and preserves diagnostic errors.
pub fn check_availability() -> Result<bool, String> {
    #[cfg(target_os = "macos")]
    return macos::check_availability();
    #[cfg(target_os = "linux")]
    return linux::check_availability();
    #[cfg(target_os = "windows")]
    return windows::check_availability();
    #[cfg(not(any(target_os = "macos", target_os = "linux", target_os = "windows")))]
    Ok(false)
}

#[cfg(target_os = "windows")]
/// Opens platform settings for system authentication.
pub fn open_settings() -> Result<(), String> {
    windows::open_settings()
}

/// Checks whether a protected key belongs to the current device and provider.
pub fn is_local(protected_key: &ProtectedVaultKey) -> bool {
    #[cfg(target_os = "macos")]
    return protected_key.provider == macos::PROVIDER
        && protected_key.version == macos::VERSION
        && macos::device_id()
            .is_ok_and(|id| protected_key.metadata["device"].as_str() == Some(&id));
    #[cfg(target_os = "linux")]
    return linux::is_local(protected_key);
    #[cfg(target_os = "windows")]
    return windows::is_local(protected_key);
    #[cfg(not(any(target_os = "macos", target_os = "linux", target_os = "windows")))]
    {
        let _ = protected_key;
        false
    }
}

/// Protects a vault key using the platform's storage and authentication services.
pub fn protect(id: Uuid, key: &[u8; KEY_LEN], reason: &str) -> Result<ProtectedVaultKey, String> {
    #[cfg(target_os = "macos")]
    return macos::protect(id, key, reason);
    #[cfg(target_os = "linux")]
    return linux::protect(id, key, reason);
    #[cfg(target_os = "windows")]
    return windows::protect(id, key, reason);
    #[cfg(not(any(target_os = "macos", target_os = "linux", target_os = "windows")))]
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
) -> Result<Zeroizing<[u8; KEY_LEN]>, String> {
    #[cfg(target_os = "macos")]
    return macos::unlock(id, protected_key, reason);
    #[cfg(target_os = "linux")]
    return linux::unlock(id, protected_key, reason);
    #[cfg(target_os = "windows")]
    return windows::unlock(id, protected_key, reason);
    #[cfg(not(any(target_os = "macos", target_os = "linux", target_os = "windows")))]
    {
        let _ = (id, protected_key, reason);
        Err("This system protection provider is unavailable".to_string())
    }
}
