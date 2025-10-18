use serde::{Deserialize, Serialize};
use std::collections::VecDeque;
use super::booleans::BooleanState;
use super::modules::SELinuxModule;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SystemState {
    pub timestamp: String,
    pub selinux_mode: String,
    pub booleans: Vec<BooleanState>,
    pub modules: Vec<SELinuxModule>,
    pub file_contexts: Vec<String>,
    pub ports: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChangeRecord {
    pub id: String,
    pub timestamp: String,
    pub action: String,
    pub description: String,
    pub previous_state: SystemState,
    pub new_state: SystemState,
    pub rollback_commands: Vec<String>,
}

pub struct RollbackManager {
    pub change_history: VecDeque<ChangeRecord>,
    pub max_history: usize,
}

impl RollbackManager {
    pub fn new() -> Self {
        Self {
            change_history: VecDeque::new(),
            max_history: 100,
        }
    }

    pub fn record_change(
        &mut self,
        action: String,
        description: String,
        previous_state: SystemState,
        new_state: SystemState,
        rollback_commands: Vec<String>,
    ) {
        let record = ChangeRecord {
            id: format!("chg_{}", chrono::Utc::now().timestamp_millis()),
            timestamp: chrono::Utc::now().to_rfc3339(),
            action,
            description,
            previous_state,
            new_state,
            rollback_commands,
        };

        self.change_history.push_front(record);
        if self.change_history.len() > self.max_history {
            self.change_history.pop_back();
        }
    }

    pub fn rollback_last(&mut self) -> Result<(), Box<dyn std::error::Error>> {
        if let Some(change) = self.change_history.pop_front() {
            // Реализация выполнения команд отката
            println!("Rolling back: {}", change.description);
            Ok(())
        } else {
            Err("No changes to rollback".into())
        }
    }

    pub fn rollback_to_id(&mut self, id: &str) -> Result<(), Box<dyn std::error::Error>> {
        if let Some(index) = self.change_history.iter().position(|r| r.id == id) {
            for _ in 0..=index {
                self.rollback_last()?;
            }
            Ok(())
        } else {
            Err("Change ID not found".into())
        }
    }
}
