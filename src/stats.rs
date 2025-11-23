use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use crate::avc::{AVCManager, AVCSeverity};
use crate::booleans::BooleanManager;
use crate::modules::ModuleManager;
use crate::rollback::RollbackManager;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SystemStats {
    pub total_avc_alerts: usize,
    pub avc_by_severity: HashMap<String, usize>,
    pub avc_by_permission: HashMap<String, usize>,
    pub avc_by_source: HashMap<String, usize>,
    pub total_booleans: usize,
    pub booleans_changed: usize,
    pub total_modules: usize,
    pub modules_enabled: usize,
    pub total_changes: usize,
    pub recent_changes: Vec<ChangeSummary>,
    pub risk_score: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChangeSummary {
    pub timestamp: String,
    pub action: String,
    pub description: String,
}

pub struct StatsManager;

impl StatsManager {
    pub fn calculate_stats(
        avc_manager: &AVCManager,
        boolean_manager: &BooleanManager,
        module_manager: &ModuleManager,
        rollback_manager: &RollbackManager,
    ) -> SystemStats {
        let total_avc = avc_manager.alerts.len();
        
        let mut avc_by_severity = HashMap::new();
        let mut avc_by_permission = HashMap::new();
        let mut avc_by_source = HashMap::new();
        
        for alert in &avc_manager.alerts {
            let severity_str = match alert.severity {
                AVCSeverity::High => "High",
                AVCSeverity::Medium => "Medium",
                AVCSeverity::Low => "Low",
            };
            *avc_by_severity.entry(severity_str.to_string()).or_insert(0) += 1;
            *avc_by_permission.entry(alert.permission.clone()).or_insert(0) += 1;
            
            let source = alert.source_context.split(':').next().unwrap_or("unknown").to_string();
            *avc_by_source.entry(source).or_insert(0) += 1;
        }
        
        let total_booleans = boolean_manager.booleans.len();
        let booleans_changed = boolean_manager.booleans.iter()
            .filter(|b| b.current_value != b.default_value)
            .count();
        
        let total_modules = module_manager.modules.len();
        let modules_enabled = module_manager.modules.iter()
            .filter(|m| m.enabled)
            .count();
        
        let total_changes = rollback_manager.change_history.len();
        let recent_changes: Vec<ChangeSummary> = rollback_manager.change_history
            .iter()
            .take(10)
            .map(|c| ChangeSummary {
                timestamp: c.timestamp.clone(),
                action: c.action.clone(),
                description: c.description.clone(),
            })
            .collect();
        
        // Расчет risk score: учитываем только реальные изменения безопасности
        // Переключения режима SELinux не учитываются как риск
        let high_severity_count = avc_by_severity.get("High").copied().unwrap_or(0);
        let medium_severity_count = avc_by_severity.get("Medium").copied().unwrap_or(0);
        
        // Фильтруем изменения: исключаем переключения режима SELinux
        let security_changes = rollback_manager.change_history.iter()
            .filter(|c| !c.action.contains("SELinux mode") && !c.description.contains("SELinux mode"))
            .count();
        
        let risk_score = (high_severity_count as f64 * 10.0) 
            + (medium_severity_count as f64 * 5.0)
            + (booleans_changed as f64 * 2.0)
            + (security_changes as f64 * 0.5); // Уменьшили вес изменений
        
        SystemStats {
            total_avc_alerts: total_avc,
            avc_by_severity,
            avc_by_permission,
            avc_by_source,
            total_booleans,
            booleans_changed,
            total_modules,
            modules_enabled,
            total_changes,
            recent_changes,
            risk_score,
        }
    }
    
    pub fn get_risk_level(risk_score: f64) -> (&'static str, ratatui::style::Color) {
        use ratatui::style::Color;
        if risk_score >= 50.0 {
            ("High", Color::Red)
        } else if risk_score >= 20.0 {
            ("Medium", Color::Yellow)
        } else {
            ("Low", Color::Green)
        }
    }
}

