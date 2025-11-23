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

    /// Создает модуль из AVC алертов используя audit2allow
    pub fn create_module_from_avc(&mut self, module_name: &str, avc_logs: &str, simulation: bool) -> Result<String> {
        if simulation {
            return Ok(format!("Would create module {} from AVC logs", module_name));
        }

        // Создаем временный файл с логами
        let temp_log = std::env::temp_dir().join(format!("selab_avc_{}.log", module_name));
        std::fs::write(&temp_log, avc_logs)?;

        // Генерируем модуль с помощью audit2allow
        // audit2allow создает .te и .pp файлы в текущей директории
        let work_dir = std::env::temp_dir();
        let pp_file = work_dir.join(format!("{}.pp", module_name));

        // Запускаем audit2allow в рабочей директории
        let output = Command::new("audit2allow")
            .current_dir(&work_dir)
            .arg("-i")
            .arg(&temp_log)
            .arg("-M")
            .arg(module_name)
            .output()?;

        if !output.status.success() {
            let error = String::from_utf8_lossy(&output.stderr);
            return Err(anyhow::anyhow!("audit2allow failed: {}", error));
        }

        // Устанавливаем модуль
        let install_output = Command::new("semodule")
            .arg("-i")
            .arg(&pp_file)
            .output()?;

        if !install_output.status.success() {
            let error = String::from_utf8_lossy(&install_output.stderr);
            return Err(anyhow::anyhow!("semodule install failed: {}", error));
        }

        // Обновляем список модулей
        self.load_modules()?;

        Ok(format!("Module {} created and installed successfully", module_name))
    }

    /// Создает модуль из выбранных AVC алертов
    pub fn create_module_from_alerts(&mut self, module_name: &str, alerts: &[crate::avc::AVCAlert], simulation: bool) -> Result<String> {
        // Формируем лог в формате audit
        let mut log_content = String::new();
        for alert in alerts {
            log_content.push_str(&format!(
                "type=AVC msg=audit({}): avc: denied {{ {} }} for pid=1234 comm=\"{}\" scontext={} tcontext={} tclass={}\n",
                alert.timestamp,
                alert.permission,
                alert.comm,
                alert.source_context,
                alert.target_context,
                alert.target_class
            ));
        }

        self.create_module_from_avc(module_name, &log_content, simulation)
    }
}
