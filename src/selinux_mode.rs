use std::process::Command;
use anyhow::Result;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
pub enum SELinuxMode {
    Enforcing,
    Permissive,
    Disabled,
}

impl SELinuxMode {
    pub fn from_string(s: &str) -> Self {
        match s.to_lowercase().as_str() {
            "enforcing" => Self::Enforcing,
            "permissive" => Self::Permissive,
            "disabled" => Self::Disabled,
            _ => Self::Enforcing,
        }
    }
    
    pub fn to_string(&self) -> &'static str {
        match self {
            Self::Enforcing => "Enforcing",
            Self::Permissive => "Permissive",
            Self::Disabled => "Disabled",
        }
    }
    
    pub fn get_current() -> Result<Self> {
        let output = Command::new("getenforce")
            .output()?
            .stdout;
        let mode_str = String::from_utf8_lossy(&output).trim().to_string();
        Ok(Self::from_string(&mode_str))
    }
    
    pub fn set_mode(&self, simulation: bool) -> Result<()> {
        if simulation {
            return Ok(());
        }
        
        match self {
            Self::Enforcing => {
                let _ = Command::new("setenforce")
                    .arg("1")
                    .output()?;
            }
            Self::Permissive => {
                let _ = Command::new("setenforce")
                    .arg("0")
                    .output()?;
            }
            Self::Disabled => {
                // Для Disabled нужно редактировать /etc/selinux/config
                // Это требует root прав и перезагрузки
                return Err(anyhow::anyhow!("Disabling SELinux requires editing /etc/selinux/config and reboot"));
            }
        }
        Ok(())
    }
    
    pub fn set_persistent(&self, simulation: bool) -> Result<()> {
        if simulation {
            return Ok(());
        }
        
        // Устанавливаем в /etc/selinux/config
        let config_content = match self {
            Self::Enforcing => "SELINUX=enforcing\n",
            Self::Permissive => "SELINUX=permissive\n",
            Self::Disabled => "SELINUX=disabled\n",
        };
        
        // Читаем текущий файл
        let config_path = "/etc/selinux/config";
        if let Ok(content) = std::fs::read_to_string(config_path) {
            // Заменяем строку SELINUX=
            let lines: Vec<&str> = content.lines().collect();
            let mut new_lines = Vec::new();
            let mut found = false;
            
            for line in lines {
                if line.trim().starts_with("SELINUX=") {
                    new_lines.push(config_content.trim());
                    found = true;
                } else {
                    new_lines.push(line);
                }
            }
            
            if !found {
                new_lines.push(config_content.trim());
            }
            
            std::fs::write(config_path, new_lines.join("\n") + "\n")?;
        }
        
        Ok(())
    }
}

#[derive(Clone)]
pub struct SELinuxModeManager {
    pub current_mode: SELinuxMode,
}

impl SELinuxModeManager {
    pub fn new() -> Result<Self> {
        let current_mode = SELinuxMode::get_current()?;
        Ok(Self { current_mode })
    }
    
    pub fn get_current(&self) -> SELinuxMode {
        self.current_mode
    }
    
    pub fn refresh(&mut self) -> Result<()> {
        self.current_mode = SELinuxMode::get_current()?;
        Ok(())
    }
    
    pub fn set_mode(&mut self, mode: SELinuxMode, persistent: bool, simulation: bool) -> Result<()> {
        if persistent {
            mode.set_persistent(simulation)?;
        } else {
            mode.set_mode(simulation)?;
        }
        self.current_mode = mode;
        Ok(())
    }
}

