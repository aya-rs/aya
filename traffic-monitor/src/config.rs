use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::{fs, path::Path};

#[derive(Debug, Serialize, Deserialize)]
pub struct TrafficMonitorConfig {
    pub permitted_cidrs: Vec<String>,
}

impl TrafficMonitorConfig {
    pub fn load<P: AsRef<Path>>(path: P) -> Result<Self> {
        let content = fs::read_to_string(path.as_ref())
            .with_context(|| format!("Failed to read config file: {:?}", path.as_ref()))?;
        
        serde_json::from_str(&content)
            .with_context(|| "Failed to parse config file as JSON")
    }

    pub fn save<P: AsRef<Path>>(&self, path: P) -> Result<()> {
        let content = serde_json::to_string_pretty(self)
            .context("Failed to serialize config to JSON")?;
        
        fs::write(path.as_ref(), content)
            .with_context(|| format!("Failed to write config file: {:?}", path.as_ref()))?;
        
        Ok(())
    }
}

impl Default for TrafficMonitorConfig {
    fn default() -> Self {
        Self {
            permitted_cidrs: vec![
                "127.0.0.0/8".to_string(),    // Localhost
                "10.0.0.0/8".to_string(),     // Private network
                "172.16.0.0/12".to_string(),  // Private network
                "192.168.0.0/16".to_string(), // Private network
            ],
        }
    }
}

// Re-export for convenience
pub use TrafficMonitorConfig as Config;

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::NamedTempFile;

    #[test]
    fn test_config_serialization() {
        let config = TrafficMonitorConfig {
            permitted_cidrs: vec![
                "192.168.1.0/24".to_string(),
                "10.0.0.0/8".to_string(),
            ],
        };

        let json = serde_json::to_string(&config).unwrap();
        let deserialized: TrafficMonitorConfig = serde_json::from_str(&json).unwrap();
        
        assert_eq!(config.permitted_cidrs, deserialized.permitted_cidrs);
    }

    #[test]
    fn test_config_file_operations() {
        let config = TrafficMonitorConfig::default();
        let temp_file = NamedTempFile::new().unwrap();
        
        // Save config
        config.save(temp_file.path()).unwrap();
        
        // Load config
        let loaded_config = TrafficMonitorConfig::load(temp_file.path()).unwrap();
        
        assert_eq!(config.permitted_cidrs, loaded_config.permitted_cidrs);
    }

    #[test]
    fn test_default_config() {
        let config = TrafficMonitorConfig::default();
        assert!(!config.permitted_cidrs.is_empty());
        assert!(config.permitted_cidrs.contains(&"127.0.0.0/8".to_string()));
    }
}