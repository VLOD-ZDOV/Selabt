use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SELinuxModule {
    pub name: String,
    pub enabled: bool,
    pub priority: i32,
}

pub struct ModuleManager {
    pub modules: Vec<SELinuxModule>,
}

impl ModuleManager {
    pub fn new() -> Self {
        Self { modules: Vec::new() }
    }

    pub fn load_modules(&mut self) -> Result<(), Box<dyn std::error::Error>> {
        // Реализация загрузки модулей
        Ok(())
    }

    pub fn load_simulation_data(&mut self) {
        self.modules = vec![
            SELinuxModule {
                name: "apache".to_string(),
                enabled: true,
                priority: 400,
            },
            SELinuxModule {
                name: "mysql".to_string(),
                enabled: true,
                priority: 400,
            },
        ];
    }

    pub fn enable_module(&mut self, name: &str) -> Result<(), Box<dyn std::error::Error>> {
        if let Some(module) = self.modules.iter_mut().find(|m| m.name == name) {
            module.enabled = true;
        }
        Ok(())
    }

    pub fn disable_module(&mut self, name: &str) -> Result<(), Box<dyn std::error::Error>> {
        if let Some(module) = self.modules.iter_mut().find(|m| m.name == name) {
            module.enabled = false;
        }
        Ok(())
    }
}
