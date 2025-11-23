use serde::{Deserialize, Serialize};
use anyhow::Result;
use super::booleans::{BooleanManager, BooleanState};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SafeModeConfig {
    pub enable_httpd_readonly: bool,
    pub disable_unused_services: bool,
    pub restrict_user_homes: bool,
    pub enable_audit_all_denials: bool,
    pub safe_boolean_changes: bool,
}

impl Default for SafeModeConfig {
    fn default() -> Self {
        Self {
            enable_httpd_readonly: true,
            disable_unused_services: true,
            restrict_user_homes: true,
            enable_audit_all_denials: true,
            safe_boolean_changes: true,
        }
    }
}

impl SafeModeConfig {
    pub fn apply_safe_defaults(&self, boolean_manager: &mut BooleanManager, simulation: bool) -> Result<Vec<String>> {
        let previous_booleans = boolean_manager.booleans.clone();
        let safe_booleans: Vec<(String, bool)> = vec![
            ("httpd_read_user_content".to_string(), false),
            ("httpd_enable_homedirs".to_string(), false),
            ("allow_ssh_keysign".to_string(), false),
        ];
        boolean_manager.set_booleans_persistent(&safe_booleans, simulation)?;
        Ok(self.generate_rollback_commands(&previous_booleans))
    }

    pub fn apply_restrictive_policy(&self, boolean_manager: &mut BooleanManager, simulation: bool) -> Result<Vec<String>> {
        let previous_booleans = boolean_manager.booleans.clone();
        let restrictive_booleans_raw = vec![
            ("deny_ptrace".to_string(), true),
            ("deny_execmem".to_string(), true),
            ("secure_mode".to_string(), true),
        ];
        let restrictive_booleans: Vec<(String, bool)> = restrictive_booleans_raw
            .into_iter()
            .filter(|(name, _)| boolean_manager.booleans.iter().any(|b| b.name == *name))
            .collect();
        if !restrictive_booleans.is_empty() {
            boolean_manager.set_booleans_persistent(&restrictive_booleans, simulation)?;
        }
        Ok(self.generate_rollback_commands(&previous_booleans))
    }

    pub fn generate_rollback_commands(&self, previous_booleans: &[BooleanState]) -> Vec<String> {
        previous_booleans
        .iter()
        .map(|b| format!("setsebool -P {} {}", b.name, if b.current_value { "on" } else { "off" }))
        .collect()
    }
}

