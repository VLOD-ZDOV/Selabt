use serde::{Deserialize, Serialize};
use std::process::Command;
use anyhow::Result;
use regex::Regex;

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

    pub fn load_booleans(&mut self) -> Result<()> {
        let output = Command::new("getsebool")
        .arg("-a")
        .output()?
        .stdout;

        let logs = String::from_utf8_lossy(&output);
        let re = Regex::new(r"^(.*?)\s-->\s(on|off)$")?;

        self.booleans.clear();
        for line in logs.lines() {
            if let Some(cap) = re.captures(line) {
                let name = cap[1].to_string();
                let value = cap[2].to_string() == "on";

                let desc_output = Command::new("semanage")
                .args(&["boolean", "-l"])
                .output()?
                .stdout;
                let desc_logs = String::from_utf8_lossy(&desc_output);
                let desc_re = Regex::new(&format!(r"{}\s+\((on|off),\s(on|off)\)\s+(.*)", regex::escape(&name)))?;
                let description = desc_re.captures(&desc_logs).map_or("No description".to_string(), |c| c[3].to_string());

                self.booleans.push(BooleanState {
                    name,
                    description,
                    current_value: value,
                    persistent: true,
                    default_value: value,
                });
            }
        }
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

    pub fn set_boolean(&mut self, name: &str, value: bool, simulation: bool) -> Result<()> {
        if simulation {
            if let Some(boolean) = self.booleans.iter_mut().find(|b| b.name == name) {
                boolean.current_value = value;
            }
            return Ok(());
        }

        let flag = if value { "on" } else { "off" };
        Command::new("setsebool")
        .arg("-P")
        .arg(name)
        .arg(flag)
        .output()?;

        if let Some(boolean) = self.booleans.iter_mut().find(|b| b.name == name) {
            boolean.current_value = value;
        }
        Ok(())
    }
}
