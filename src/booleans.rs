use serde::{Deserialize, Serialize};
use std::collections::HashMap;
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

#[derive(Clone)]
pub struct BooleanManager {
    pub booleans: Vec<BooleanState>,
}

impl BooleanManager {
    pub fn new() -> Self {
        Self { booleans: Vec::new() }
    }

    /// Устанавливает несколько булевых значений ОДНОЙ командой setsebool -P,
    /// чтобы политика пересобиралась один раз (значительно быстрее).
    pub fn set_booleans_persistent(&mut self, changes: &[(String, bool)], simulation: bool) -> Result<()> {
        if simulation {
            for (name, value) in changes {
                if let Some(boolean) = self.booleans.iter_mut().find(|b| &b.name == name) {
                    boolean.current_value = *value;
                }
            }
            return Ok(());
        }
        if changes.is_empty() {
            return Ok(());
        }
        let mut cmd = std::process::Command::new("setsebool");
        cmd.arg("-P");
        for (name, value) in changes {
            cmd.arg(name);
            cmd.arg(if *value { "on" } else { "off" });
        }
        cmd.output()?;
        for (name, value) in changes {
            if let Some(boolean) = self.booleans.iter_mut().find(|b| &b.name == name) {
                boolean.current_value = *value;
            }
        }
        Ok(())
    }

    pub fn load_booleans(&mut self) -> Result<()> {
        // 1) Считываем текущее состояние всех булевых за один вызов
        let output = Command::new("getsebool")
            .arg("-a")
            .output()?
            .stdout;

        let logs = String::from_utf8_lossy(&output);
        let re = Regex::new(r"^(.*?)\s-->\s(on|off)$")?;

        // 2) ОДНОКРАТНО получаем описание всех булевых из semanage
        let desc_output = Command::new("semanage")
            .args(&["boolean", "-l"])
            .output()?
            .stdout;
        let desc_logs = String::from_utf8_lossy(&desc_output);
        // Пример строки: httpd_enable_homedirs (off ,  off)  Allow httpd to read home directories
        let desc_line_re = Regex::new(r"^(\S+)\s+\((on|off)\s*,\s*(on|off)\)\s+(.*)$")?;

        let mut name_to_desc: HashMap<String, (String, bool)> = HashMap::new();
        for line in desc_logs.lines() {
            if let Some(m) = desc_line_re.captures(line) {
                let name = m.get(1).unwrap().as_str().to_string();
                let default_on = m.get(2).unwrap().as_str() == "on";
                let description = m.get(4).unwrap().as_str().to_string();
                name_to_desc.insert(name, (description, default_on));
            }
        }

        self.booleans.clear();
        for line in logs.lines() {
            if let Some(cap) = re.captures(line) {
                let name = cap[1].to_string();
                let value = cap[2].to_string() == "on";
                let (description, default_on) = name_to_desc
                    .get(&name)
                    .cloned()
                    .unwrap_or_else(|| ("No description".to_string(), value));

                self.booleans.push(BooleanState {
                    name,
                    description,
                    current_value: value,
                    persistent: true,
                    default_value: default_on,
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
