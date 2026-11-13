use std::fmt::Write;

use uuid::Uuid;
use zeroize::Zeroizing;

use crate::vault::{self, ProtectedVaultKey};

const PROVIDER: &str = "recovery";

/// Generates a recovery key and uses it to protect a vault key.
pub fn create(
    id: Uuid,
    vault_key: &[u8; 32],
) -> Result<(ProtectedVaultKey, Zeroizing<String>), String> {
    let key = vault::random_key();
    let mut text = Zeroizing::new(String::from("FR2"));
    for chunk in key.chunks(4) {
        text.push('-');
        for byte in chunk {
            write!(&mut *text, "{byte:02X}").unwrap();
        }
    }
    let mut protected_key = ProtectedVaultKey {
        id: Uuid::new_v4(),
        provider: PROVIDER.to_string(),
        version: 1,
        metadata: serde_json::Value::Null,
        wrapped_key_b64: String::new(),
    };
    protected_key.wrapped_key_b64 =
        vault::encrypt_bound(vault_key, &key, &protected_key.context(id))?;
    Ok((protected_key, text))
}

/// Recovers a vault key using a validated recovery key.
pub fn unlock(
    id: Uuid,
    protected_keys: &[ProtectedVaultKey],
    text: &str,
) -> Result<Zeroizing<[u8; 32]>, String> {
    let text = Zeroizing::new(text.trim().to_ascii_uppercase());
    let text = text
        .strip_prefix("FR2-")
        .ok_or("Invalid recovery key format")?;
    let digits = Zeroizing::new(
        text.chars()
            .filter(|c| *c != '-' && !c.is_whitespace())
            .collect::<String>(),
    );
    if digits.len() != 64 || !digits.bytes().all(|c| c.is_ascii_hexdigit()) {
        return Err("Invalid recovery key format".to_string());
    }
    let mut key = Zeroizing::new([0u8; 32]);
    for (index, byte) in key.iter_mut().enumerate() {
        *byte =
            u8::from_str_radix(&digits[index * 2..index * 2 + 2], 16).map_err(|e| e.to_string())?;
    }
    for protected_key in protected_keys
        .iter()
        .filter(|s| s.provider == PROVIDER && s.version == 1)
    {
        if let Ok(bytes) = vault::decrypt_bound(
            &protected_key.wrapped_key_b64,
            &key,
            &protected_key.context(id),
        ) {
            let key =
                <[u8; 32]>::try_from(bytes.as_slice()).map_err(|_| "Invalid vault key length")?;
            return Ok(Zeroizing::new(key));
        }
    }
    Err("Incorrect recovery key or damaged protected key".to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    /// Checks recovery and rejects mismatched vaults or protected keys.
    fn recovery_is_bound_to_vault_and_protected_key() {
        let id = Uuid::new_v4();
        let key = vault::random_key();
        let (protected_key, text) = create(id, &key).unwrap();
        assert_eq!(
            *unlock(id, std::slice::from_ref(&protected_key), &text).unwrap(),
            *key
        );
        assert!(unlock(Uuid::new_v4(), std::slice::from_ref(&protected_key), &text).is_err());
        let mut moved = protected_key.clone();
        moved.id = Uuid::new_v4();
        assert!(unlock(id, &[moved], &text).is_err());
        assert!(unlock(id, &[protected_key], "1234").is_err());
    }
}
