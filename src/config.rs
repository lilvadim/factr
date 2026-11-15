use std::path::PathBuf;

use egui::ThemePreference;
use serde::{Deserialize, Serialize};

pub const APP_NAME: &str = "factr";
const CONFIG_FILE: &str = "config.json";
const STORAGE_FILE: &str = "storage.json";

#[derive(Default, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum AutoLockTimeout {
    #[default]
    Disabled,
    OneMinute,
    FiveMinutes,
    FifteenMinutes,
    ThirtyMinutes,
}

impl AutoLockTimeout {
    pub const ALL: [Self; 5] = [
        Self::Disabled,
        Self::OneMinute,
        Self::FiveMinutes,
        Self::FifteenMinutes,
        Self::ThirtyMinutes,
    ];

    /// Returns the configured inactivity interval.
    pub fn duration(self) -> Option<std::time::Duration> {
        let minutes = match self {
            Self::Disabled => return None,
            Self::OneMinute => 1,
            Self::FiveMinutes => 5,
            Self::FifteenMinutes => 15,
            Self::ThirtyMinutes => 30,
        };
        Some(std::time::Duration::from_mins(minutes))
    }
}

#[derive(Default, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct AccountSort {
    pub enabled: bool,
    pub field: SortField,
    pub descending: bool,
}

#[derive(Default, PartialEq, Eq, Clone, Copy, Serialize, Deserialize)]
pub enum SortField {
    #[default]
    Name,
    Username,
    FirstAdded,
    LastModified,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct Config {
    pub storage_file: PathBuf,
    pub close_after_copy: bool,
    pub always_on_top: bool,
    pub toolbar_labels: bool,
    pub theme: ThemePreference,
    pub sort: AccountSort,
    pub auto_lock: AutoLockTimeout,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            storage_file: storage_default_path(),
            close_after_copy: false,
            always_on_top: false,
            toolbar_labels: true,
            theme: ThemePreference::System,
            sort: AccountSort::default(),
            auto_lock: AutoLockTimeout::default(),
        }
    }
}

pub fn save_to_dot_config(config: &Config) -> Result<(), String> {
    serde_json::to_string(config)
        .map_err(|e| e.to_string())
        .and_then(|json| std::fs::write(config_default_path(), &json).map_err(|e| e.to_string()))
}

pub fn read_from_dot_config() -> Result<Config, String> {
    std::fs::read_to_string(config_default_path())
        .map_err(|e| e.to_string())
        .and_then(|text| serde_json::from_str::<Config>(&text).map_err(|e| e.to_string()))
        .inspect_err(|e| eprintln!("{}", e))
}

pub fn app_config_dir_path() -> PathBuf {
    dot_config_path().join(APP_NAME)
}

fn dot_config_path() -> PathBuf {
    PathBuf::from(env_home_dir()).join(".config")
}

fn config_default_path() -> PathBuf {
    app_config_dir_path().join(CONFIG_FILE)
}

fn storage_default_path() -> PathBuf {
    app_config_dir_path().join(STORAGE_FILE)
}

fn env_home_dir() -> String {
    std::env::var("HOME")
        .or_else(|_| std::env::var("USERPROFILE"))
        .expect("Cannot find home directory")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn auto_lock_defaults_to_disabled_and_preserves_configured_intervals() {
        let old_config: Config = serde_json::from_str("{}").unwrap();
        assert!(old_config.auto_lock == AutoLockTimeout::Disabled);
        for timeout in AutoLockTimeout::ALL {
            let config = Config {
                auto_lock: timeout,
                ..Default::default()
            };
            let json = serde_json::to_string(&config).unwrap();
            let restored: Config = serde_json::from_str(&json).unwrap();
            assert!(restored.auto_lock == timeout);
        }
    }
}
