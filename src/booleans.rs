use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BooleanState {
    pub name: String,
    pub description: String,
    pub current_value: bool,
    pub persistent: bool,
    pub default_value: bool,
}

pub struct BooleanManager {
    pub booleans: Vec<BooleanState>,
}

impl BooleanManager {
    pub fn new() -> Self {
        Self { booleans: Vec::new() }
    }

    pub fn load_booleans(&mut self) -> Result<(), Box<dyn std::error::Error>> {
        // Реализация загрузки boolean'ов
        Ok(())
    }

    pub fn load_simulation_data(&mut self) {
        self.booleans = vec![
            BooleanState {
                name: "httpd_enable_homedirs".to_string(),
                description: "Allow httpd to read home directories".to_string(),
                current_value: false,
                persistent: true,
                default_value: false,
            },
            BooleanState {
                name: "allow_ssh_keysign".to_string(),
                description: "Allow ssh keysign operation".to_string(),
                current_value: true,
                persistent: true,
                default_value: false,
            },
        ];
    }

    pub fn set_boolean(&mut self, name: &str, value: bool) -> Result<(), Box<dyn std::error::Error>> {
        // Реализация изменения boolean'а
        if let Some(boolean) = self.booleans.iter_mut().find(|b| b.name == name) {
            boolean.current_value = value;
        }
        Ok(())
    }
}
