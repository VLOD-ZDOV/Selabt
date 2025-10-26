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
        let safe_booleans = vec![
            ("httpd_read_user_content", false),
            ("httpd_enable_homedirs", false),
            ("allow_ssh_keysign", false),
        ];

        for (name, value) in safe_booleans {
            boolean_manager.set_boolean(name, value, simulation)?;
        }

        Ok(self.generate_rollback_commands(&previous_booleans))
    }

    pub fn apply_restrictive_policy(&self, boolean_manager: &mut BooleanManager, simulation: bool) -> Result<Vec<String>> {
        let previous_booleans = boolean_manager.booleans.clone();
        let restrictive_booleans = vec![
            ("deny_ptrace", true),
            ("deny_execmem", true),
            ("secure_mode", true),
        ];

        for (name, value) in restrictive_booleans {
            if boolean_manager.booleans.iter().any(|b| b.name == name) {
                boolean_manager.set_boolean(name, value, simulation)?;
            }
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

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityProfile {
    pub name: String,
    pub description: String,
    pub booleans: Vec<(String, bool)>,
    pub risk_level: RiskLevel,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum RiskLevel {
    Low,
    Medium,
    High,
}
