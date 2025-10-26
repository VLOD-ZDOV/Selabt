use serde::{Deserialize, Serialize};
use std::process::Command;
use regex::Regex;
use anyhow::Result;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AVCAlert {
    pub timestamp: String,
    pub source_context: String,
    pub target_context: String,
    pub target_class: String,
    pub permission: String,
    pub comm: String,
    pub path: String,
    pub severity: AVCSeverity,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum AVCSeverity {
    High,
    Medium,
    Low,
}

pub struct AVCManager {
    pub alerts: Vec<AVCAlert>,
}

impl AVCManager {
    pub fn new() -> Self {
        Self { alerts: Vec::new() }
    }

    pub fn load_avc_logs(&mut self) -> Result<()> {
        let output = Command::new("ausearch")
        .args(&["-m", "avc", "--raw", "-ts", "recent"])
        .output()?
        .stdout;

        let logs = String::from_utf8_lossy(&output);
        let re = Regex::new(r"type=AVC msg=audit\((.*?)\): avc:  denied  \{ (.*?) \} for  pid=\d+ comm=(.*?) (?:name=(.*?))? (?:dev=(.*?))? (?:ino=\d+ )?scontext=(.*?) tcontext=(.*?) tclass=(.*?) permissive=\d")?;

        self.alerts.clear();
        for cap in re.captures_iter(&logs) {
            let timestamp = cap[1].to_string();
            let permission = cap[2].to_string();
            let comm = cap[3].to_string().replace("\"", "");
            let path = cap.get(4).map_or("".to_string(), |m| m.as_str().to_string().replace("\"", ""));
            let source_context = cap[6].to_string();
            let target_context = cap[7].to_string();
            let target_class = cap[8].to_string();

            let severity = match permission.as_str() {
                "execute" | "write" | "unlink" => AVCSeverity::High,
                "read" | "getattr" => AVCSeverity::Medium,
                _ => AVCSeverity::Low,
            };

            self.alerts.push(AVCAlert {
                timestamp,
                source_context,
                target_context,
                target_class,
                permission,
                comm,
                path,
                severity,
            });
        }

        Ok(())
    }

    pub fn load_simulation_data(&mut self) {
        self.alerts = vec![
            AVCAlert {
                timestamp: "2024-01-15 10:30:00".to_string(),
                source_context: "httpd_t".to_string(),
                target_context: "user_home_t".to_string(),
                target_class: "file".to_string(),
                permission: "read".to_string(),
                comm: "httpd".to_string(),
                path: "/home/user/file.txt".to_string(),
                severity: AVCSeverity::Medium,
            },
        ];
    }

    pub fn analyze_avc(&self, alert: &AVCAlert) -> Option<AVCSolution> {
        let mut module_content = String::new();
        let mut commands = vec![];

        if alert.source_context.contains("httpd_t") && alert.permission == "read" && alert.target_context.contains("home") {
            module_content = format!("allow {} {}:{} {{ {} }};", alert.source_context, alert.target_context, alert.target_class, alert.permission);
            commands.push(format!("audit2allow -M mymodule -i <(ausearch -m avc -ts recent)"));
            commands.push("semodule -i mymodule.pp".to_string());
        } else if alert.permission == "execute" {
            commands.push(format!("setsebool -P allow_execmem 1"));
        }

        Some(AVCSolution {
            description: format!("Allow {} for {} on {}", alert.permission, alert.source_context, alert.target_context),
             module_content,
             commands,
        })
    }

    pub fn apply_solution(&self, solution: &AVCSolution, simulation: bool) -> Result<()> {
        if simulation {
            return Ok(());
        }
        for cmd in &solution.commands {
            Command::new("sh").arg("-c").arg(cmd).output()?;
        }
        Ok(())
    }
}

#[derive(Debug, Clone)]
pub struct AVCSolution {
    pub description: String,
    pub module_content: String,
    pub commands: Vec<String>,
}
