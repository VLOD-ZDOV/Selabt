use serde::{Deserialize, Serialize};
use std::fs;
use std::path::PathBuf;
use anyhow::Result;
use crate::booleans::BooleanManager;
use crate::modules::ModuleManager;
use crate::file_contexts::FileContextManager;
use crate::ports::PortManager;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConfigProfile {
    pub name: String,
    pub description: String,
    pub timestamp: String,
    pub booleans: Vec<(String, bool)>,
    pub modules: Vec<String>,
    pub file_contexts: Vec<(String, String)>,
    pub ports: Vec<(String, String, String)>, // port, protocol, context
}

pub struct ConfigExporter;

impl ConfigExporter {
    pub fn export_profile(
        name: &str,
        description: &str,
        boolean_manager: &BooleanManager,
        module_manager: &ModuleManager,
        file_context_manager: &FileContextManager,
        port_manager: &PortManager,
    ) -> Result<ConfigProfile> {
        let booleans: Vec<(String, bool)> = boolean_manager.booleans.iter()
            .map(|b| (b.name.clone(), b.current_value))
            .collect();
        
        let modules: Vec<String> = module_manager.modules.iter()
            .filter(|m| m.enabled)
            .map(|m| m.name.clone())
            .collect();
        
        let file_contexts: Vec<(String, String)> = file_context_manager.contexts.iter()
            .map(|c| (c.path.clone(), c.context.clone()))
            .collect();
        
        let ports: Vec<(String, String, String)> = port_manager.ports.iter()
            .map(|p| (p.port.clone(), p.protocol.clone(), p.context.clone()))
            .collect();
        
        Ok(ConfigProfile {
            name: name.to_string(),
            description: description.to_string(),
            timestamp: chrono::Utc::now().to_rfc3339(),
            booleans,
            modules,
            file_contexts,
            ports,
        })
    }
    
    pub fn save_to_file(profile: &ConfigProfile, path: &PathBuf) -> Result<()> {
        let json = serde_json::to_string_pretty(profile)?;
        fs::write(path, json)?;
        Ok(())
    }
    
    pub fn load_from_file(path: &PathBuf) -> Result<ConfigProfile> {
        let data = fs::read_to_string(path)?;
        let profile: ConfigProfile = serde_json::from_str(&data)?;
        Ok(profile)
    }
    
    pub fn apply_profile(
        profile: &ConfigProfile,
        boolean_manager: &mut BooleanManager,
        module_manager: &mut ModuleManager,
        file_context_manager: &mut FileContextManager,
        port_manager: &mut PortManager,
        simulation: bool,
    ) -> Result<Vec<String>> {
        let mut rollback_commands = Vec::new();
        
        // Применяем булевы значения
        let boolean_changes: Vec<(String, bool)> = profile.booleans.clone();
        if !boolean_changes.is_empty() {
            for (name, value) in &boolean_changes {
                rollback_commands.push(format!(
                    "setsebool -P {} {}",
                    name,
                    if *value { "off" } else { "on" }
                ));
            }
            boolean_manager.set_booleans_persistent(&boolean_changes, simulation)?;
        }
        
        // Применяем модули (включаем указанные)
        for module_name in &profile.modules {
            if !module_manager.modules.iter().any(|m| &m.name == module_name && m.enabled) {
                rollback_commands.push(format!("semodule -d {}", module_name));
                module_manager.enable_module(module_name, simulation)?;
            }
        }
        
        // Применяем файловые контексты
        for (path, context) in &profile.file_contexts {
            if !file_context_manager.contexts.iter().any(|c| &c.path == path) {
                rollback_commands.push(format!("semanage fcontext -d {}", path));
                file_context_manager.add_file_context(path, context, simulation)?;
            }
        }
        
        // Применяем порты
        for (port, protocol, context) in &profile.ports {
            if !port_manager.ports.iter().any(|p| &p.port == port && &p.protocol == protocol) {
                rollback_commands.push(format!("semanage port -d -p {} {}", protocol, port));
                port_manager.add_port(port, protocol, context, simulation)?;
            }
        }
        
        Ok(rollback_commands)
    }
}

