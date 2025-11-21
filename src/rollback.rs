use serde::{Deserialize, Serialize};
use std::collections::VecDeque;
use std::fs;
use std::path::PathBuf;
use chrono::Utc;
use anyhow::{Result, anyhow, Context};
use super::booleans::BooleanState;
use super::modules::SELinuxModule;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SystemState {
    pub timestamp: String,
    pub selinux_mode: String,
    pub booleans: Vec<BooleanState>,
    pub modules: Vec<SELinuxModule>,
    pub file_contexts: Vec<String>,
    pub ports: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChangeRecord {
    pub id: String,
    pub timestamp: String,
    pub action: String,
    pub description: String,
    pub previous_state: SystemState,
    pub new_state: SystemState,
    pub rollback_commands: Vec<String>,
    pub applied_commands: Vec<String>,
}

pub struct RollbackManager {
    pub change_history: VecDeque<ChangeRecord>,
    pub max_history: usize,
    history_path: PathBuf,
}

impl RollbackManager {
    pub fn new() -> Self {
        let history_path = Self::default_history_path();
        let mut manager = Self {
            change_history: VecDeque::new(),
            max_history: 200,
            history_path,
        };
        let _ = manager.load_history_from_disk(); // тихая попытка загрузки
        manager
    }

    fn default_history_path() -> PathBuf {
        if let Some(mut dir) = dirs::config_dir() {
            dir.push("selab");
            let _ = fs::create_dir_all(&dir);
            dir.push("rollback.json");
            return dir;
        }
        let mut home = std::env::var_os("HOME").map(PathBuf::from).unwrap_or_else(|| PathBuf::from("."));
        home.push(".selab_rollback.json");
        home
    }

    fn load_history_from_disk(&mut self) -> Result<()> {
        if self.history_path.exists() {
            let data = fs::read_to_string(&self.history_path)
                .with_context(|| format!("Failed to read rollback history at {:?}", self.history_path))?;
            if !data.trim().is_empty() {
                let list: Vec<ChangeRecord> = serde_json::from_str(&data)
                    .with_context(|| "Failed to parse rollback history JSON")?;
                self.change_history = list.into_iter().collect();
            }
        }
        Ok(())
    }

    fn save_history_to_disk(&self) -> Result<()> {
        let list: Vec<ChangeRecord> = self.change_history.iter().cloned().collect();
        let data = serde_json::to_string_pretty(&list).with_context(|| "Failed to serialize rollback history")?;
        if let Some(parent) = self.history_path.parent() {
            let _ = fs::create_dir_all(parent);
        }
        fs::write(&self.history_path, data)
            .with_context(|| format!("Failed to write rollback history at {:?}", self.history_path))?;
        Ok(())
    }

    fn trim_history(&mut self) {
        while self.change_history.len() > self.max_history {
            self.change_history.pop_back();
        }
    }

    pub fn record_change(
        &mut self,
        action: String,
        description: String,
        previous_state: SystemState,
        new_state: SystemState,
        provided_rollback_commands: Vec<String>,
    ) {
        let mut rollback_commands = provided_rollback_commands;
        // Автогенерация команд отката по дельтам состояний (добавит недостающие)
        let mut auto = Self::generate_rollback_commands(&previous_state, &new_state);
        // Приоритет у явно предоставленных команд — авто добавляем в конец (без дубликатов)
        for cmd in auto.drain(..) {
            if !rollback_commands.iter().any(|c| c == &cmd) {
                rollback_commands.push(cmd);
            }
        }

        let record = ChangeRecord {
            id: format!("chg_{}", Utc::now().timestamp_millis()),
            timestamp: Utc::now().to_rfc3339(),
            action,
            description,
            previous_state,
            new_state,
            rollback_commands,
            applied_commands: Vec::new(),
        };

        self.change_history.push_front(record);
        self.trim_history();
        let _ = self.save_history_to_disk();
    }

    pub fn rollback_last(&mut self, simulation: bool) -> Result<()> {
        if let Some(mut change) = self.change_history.pop_front() {
            if !simulation {
                for cmd in change.rollback_commands {
                    std::process::Command::new("sh")
                    .arg("-c")
                    .arg(&cmd)
                    .output()?;
                    change.applied_commands.push(cmd);
                }
            }
            // Запишем факт отката в историю как запись-метку (без автогенерации)
            let marker = ChangeRecord {
                id: format!("rollback_{}", Utc::now().timestamp_millis()),
                timestamp: Utc::now().to_rfc3339(),
                action: "Rollback".to_string(),
                description: format!("Rolled back: {}", change.id),
                previous_state: change.new_state.clone(),
                new_state: change.previous_state.clone(),
                rollback_commands: Vec::new(),
                applied_commands: change.applied_commands.clone(),
            };
            self.change_history.push_front(marker);
            self.trim_history();
            let _ = self.save_history_to_disk();
            Ok(())
        } else {
            Err(anyhow!("No changes to rollback"))
        }
    }

    pub fn rollback_to_id(&mut self, id: &str, simulation: bool) -> Result<()> {
        // Откатываем по одному сверху, пока не пройдем нужную запись включительно
        loop {
            let found = self.change_history.iter().any(|r| r.id == id);
            if !found {
                return Err(anyhow!("Change ID not found"));
            }
            // Если верхняя запись — это нужная, делаем последний откат и выходим
            if let Some(top) = self.change_history.front() {
                if top.id == id {
                    self.rollback_last(simulation)?;
                    return Ok(());
                }
            }
            self.rollback_last(simulation)?;
        }
    }

    pub fn clear_history(&mut self) -> Result<()> {
        self.change_history.clear();
        self.save_history_to_disk()
    }

    fn generate_rollback_commands(previous: &SystemState, new: &SystemState) -> Vec<String> {
        let mut cmds: Vec<String> = Vec::new();
        // 1) Booleans
        let mut prev_map = std::collections::HashMap::new();
        for b in &previous.booleans {
            prev_map.insert(b.name.clone(), b.current_value);
        }
        let mut new_map = std::collections::HashMap::new();
        for b in &new.booleans {
            new_map.insert(b.name.clone(), b.current_value);
        }
        // Если новое значение отличается от прежнего — для отката нужно выставить прежнее
        for (name, prev_val) in prev_map.iter() {
            if let Some(new_val) = new_map.get(name) {
                if prev_val != new_val {
                    cmds.push(format!("setsebool -P {} {}", name, if *prev_val { "on" } else { "off" }));
                }
            }
        }

        // 2) Modules (enabled toggle)
        let mut prev_mod = std::collections::HashMap::new();
        for m in &previous.modules {
            prev_mod.insert(m.name.clone(), m.enabled);
        }
        let mut new_mod = std::collections::HashMap::new();
        for m in &new.modules {
            new_mod.insert(m.name.clone(), m.enabled);
        }
        for (name, prev_enabled) in prev_mod.iter() {
            if let Some(new_enabled) = new_mod.get(name) {
                if prev_enabled != new_enabled {
                    if *prev_enabled {
                        cmds.push(format!("semodule -e {}", name));
                    } else {
                        cmds.push(format!("semodule -d {}", name));
                    }
                }
            }
        }

        // 3) File contexts: строки формата "path:context"
        use std::collections::HashSet;
        let prev_fc: HashSet<_> = previous.file_contexts.iter().cloned().collect();
        let new_fc: HashSet<_> = new.file_contexts.iter().cloned().collect();
        // То, что было раньше, но пропало в новом — нужно добавить обратно
        for missing in prev_fc.difference(&new_fc) {
            if let Some((path, ctx)) = Self::split_once(missing, ':') {
                cmds.push(format!("semanage fcontext -a -t {} {}", ctx, path));
                // Восстановление метки на FS — опционально, но полезно
                cmds.push(format!("restorecon -v {}", path));
            }
        }
        // То, что появилось в новом и отсутствовало в прежнем — нужно удалить
        for extra in new_fc.difference(&prev_fc) {
            if let Some((path, _ctx)) = Self::split_once(extra, ':') {
                cmds.push(format!("semanage fcontext -d {}", path));
            }
        }

        // 4) Ports: строки формата "port/proto:context"
        let prev_ports: HashSet<_> = previous.ports.iter().cloned().collect();
        let new_ports: HashSet<_> = new.ports.iter().cloned().collect();
        for missing in prev_ports.difference(&new_ports) {
            if let Some((pp, ctx)) = Self::split_once(missing, ':') {
                if let Some((port, proto)) = Self::split_once(&pp, '/') {
                    cmds.push(format!("semanage port -a -t {} -p {} {}", ctx, proto, port));
                }
            }
        }
        for extra in new_ports.difference(&prev_ports) {
            if let Some((pp, _ctx)) = Self::split_once(extra, ':') {
                if let Some((port, proto)) = Self::split_once(&pp, '/') {
                    cmds.push(format!("semanage port -d -p {} {}", proto, port));
                }
            }
        }

        cmds
    }

    fn split_once(s: &str, sep: char) -> Option<(String, String)> {
        let mut it = s.splitn(2, sep);
        let a = it.next()?;
        let b = it.next()?;
        Some((a.to_string(), b.to_string()))
    }
}
