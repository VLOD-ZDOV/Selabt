use serde::{Deserialize, Serialize};
use std::process::Command;
use anyhow::Result;
use regex::Regex;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SELinuxModule {
    pub name: String,
    pub enabled: bool,
    pub priority: i32,
}

#[derive(Clone)]
pub struct ModuleManager {
    pub modules: Vec<SELinuxModule>,
}

impl ModuleManager {
    pub fn new() -> Self {
        Self { modules: Vec::new() }
    }

    pub fn load_modules(&mut self) -> Result<()> {
        let output = Command::new("semodule")
        .arg("-l")
        .output()?
        .stdout;

        let logs = String::from_utf8_lossy(&output);
        let re = Regex::new(r"^(\S+)\s+(\d+)\s*")?;

        self.modules.clear();
        for line in logs.lines() {
            if let Some(cap) = re.captures(line) {
                let name = cap[1].to_string();
                let priority: i32 = cap.get(2).map_or(400, |m| m.as_str().parse().unwrap_or(400));

                self.modules.push(SELinuxModule {
                    name,
                    enabled: true,
                    priority,
                });
            }
        }
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

    pub fn enable_module(&mut self, name: &str, simulation: bool) -> Result<()> {
        if simulation {
            if let Some(module) = self.modules.iter_mut().find(|m| m.name == name) {
                module.enabled = true;
            }
            return Ok(());
        }

        Command::new("semodule")
        .arg("-e")
        .arg(name)
        .output()?;

        if let Some(module) = self.modules.iter_mut().find(|m| m.name == name) {
            module.enabled = true;
        }
        Ok(())
    }

    pub fn disable_module(&mut self, name: &str, simulation: bool) -> Result<()> {
        if simulation {
            if let Some(module) = self.modules.iter_mut().find(|m| m.name == name) {
                module.enabled = false;
            }
            return Ok(());
        }

        Command::new("semodule")
        .arg("-d")
        .arg(name)
        .output()?;

        if let Some(module) = self.modules.iter_mut().find(|m| m.name == name) {
            module.enabled = false;
        }
        Ok(())
    }

    pub fn install_module(&mut self, path: &str, simulation: bool) -> Result<()> {
        if simulation {
            self.modules.push(SELinuxModule {
                name: path.to_string(),
                              enabled: true,
                              priority: 400,
            });
            return Ok(());
        }

        Command::new("semodule")
        .arg("-i")
        .arg(path)
        .output()?;

        self.load_modules()?;
        Ok(())
    }

    pub fn remove_module(&mut self, name: &str, simulation: bool) -> Result<()> {
        if simulation {
            self.modules.retain(|m| m.name != name);
            return Ok(());
        }

        Command::new("semodule")
        .arg("-r")
        .arg(name)
        .output()?;

        self.load_modules()?;
        Ok(())
    }
}
