use std::path::PathBuf;

use serde::{Deserialize, Serialize};

pub const APP_NAME: &str = "factr";
const CONFIG_FILE: &str = "config.json";
const STORAGE_FILE: &str = "storage.json";

#[derive(Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct Config {
    pub storage_file: PathBuf,
    pub close_after_copy: bool,
    pub always_on_top: bool,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            storage_file: storage_default_path(),
            close_after_copy: false,
            always_on_top: false,
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
