use std::fmt::Write;
use uuid::Uuid;
use zeroize::Zeroizing;

use crate::vault::{self, KEY_LEN, ProtectedVaultKey};

const PROVIDER: &str = "recovery";
const REC_KEY_PREFIX: &str = "FR2";
const GROUP_BYTES: usize = 4;
const HEX_DIGITS_PER_BYTE: usize = 2;
const HEX_RADIX: u32 = 16;
const REC_KEY_VERSION: u32 = 1;

/// Generates a recovery key and uses it to protect a vault key.
pub fn create(
    id: Uuid,
    vault_key: &[u8; KEY_LEN],
) -> Result<(ProtectedVaultKey, Zeroizing<String>), String> {
    let key = vault::random_key();
    let text = bytes_to_text_key(&key);
    let protected_key_id = Uuid::new_v4();
    let context = vault::encryption_context(id, protected_key_id, PROVIDER, REC_KEY_VERSION);
    let protected_key = ProtectedVaultKey {
        id: protected_key_id,
        provider: PROVIDER.to_string(),
        version: REC_KEY_VERSION,
        metadata: serde_json::Value::Null,
        wrapped_key_b64: vault::encrypt_bound(vault_key, &key, &context)?,
    };
    Ok((protected_key, text))
}

fn bytes_to_text_key(key: &Zeroizing<[u8; KEY_LEN]>) -> Zeroizing<String> {
    let mut text = Zeroizing::new(String::from(REC_KEY_PREFIX));
    for chunk in key.chunks(GROUP_BYTES) {
        text.push('-');
        for byte in chunk {
            write!(&mut *text, "{byte:02X}").unwrap();
        }
    }
    text
}

/// Recovers a vault key using a validated recovery key.
pub fn unlock(
    id: Uuid,
    protected_keys: &[ProtectedVaultKey],
    text: &str,
) -> Result<Zeroizing<[u8; KEY_LEN]>, String> {
    let text = Zeroizing::new(text.trim().to_ascii_uppercase());
    let text = text
        .strip_prefix(&format!("{REC_KEY_PREFIX}-"))
        .ok_or("Invalid recovery key format")?;
    let digits = Zeroizing::new(
        text.chars()
            .filter(|c| *c != '-' && !c.is_whitespace())
            .collect::<String>(),
    );
    if digits.len() != KEY_LEN * HEX_DIGITS_PER_BYTE
        || !digits.bytes().all(|c| c.is_ascii_hexdigit())
    {
        return Err("Invalid recovery key format".to_string());
    }
    let key = text_to_bytes_key(digits)?;
    for protected_key in protected_keys
        .iter()
        .filter(|s| s.provider == PROVIDER && s.version == REC_KEY_VERSION)
    {
        if let Ok(bytes) = vault::decrypt_bound(
            &protected_key.wrapped_key_b64,
            &key,
            &vault::encryption_context(
                id,
                protected_key.id,
                &protected_key.provider,
                protected_key.version,
            ),
        ) {
            let key = <[u8; KEY_LEN]>::try_from(bytes.as_slice())
                .map_err(|_| "Invalid vault key length")?;
            return Ok(Zeroizing::new(key));
        }
    }
    Err("Incorrect recovery key or damaged protected key".to_string())
}

fn text_to_bytes_key(digits: Zeroizing<String>) -> Result<Zeroizing<[u8; KEY_LEN]>, String> {
    let mut key = Zeroizing::new([0u8; KEY_LEN]);
    for (index, byte) in key.iter_mut().enumerate() {
        *byte = u8::from_str_radix(
            &digits[index * HEX_DIGITS_PER_BYTE..(index + 1) * HEX_DIGITS_PER_BYTE],
            HEX_RADIX,
        )
        .map_err(|e| e.to_string())?;
    }
    Ok(key)
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
