use serde::{Deserialize, Serialize};
use std::process::Command;
use anyhow::Result;
use regex::Regex;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileContext {
    pub path: String,
    pub context: String,
}

#[derive(Clone)]
pub struct FileContextManager {
    pub contexts: Vec<FileContext>,
}

impl FileContextManager {
    pub fn new() -> Self {
        Self { contexts: Vec::new() }
    }

    pub fn load_file_contexts(&mut self) -> Result<()> {
        let output = Command::new("semanage")
        .args(&["fcontext", "-l"])
        .output()?
        .stdout;

        let logs = String::from_utf8_lossy(&output);
        let re = Regex::new(r"^(\S+)\s+all files\s+system_u:object_r:(\S+):s0$")?;

        self.contexts.clear();
        for line in logs.lines() {
            if let Some(cap) = re.captures(line) {
                let path = cap[1].to_string();
                let context = cap[2].to_string();

                self.contexts.push(FileContext { path, context });
            }
        }
        Ok(())
    }

    pub fn add_file_context(&mut self, path: &str, context: &str, simulation: bool) -> Result<()> {
        if simulation {
            self.contexts.push(FileContext {
                path: path.to_string(),
                               context: context.to_string(),
            });
            return Ok(());
        }

        Command::new("semanage")
        .args(&["fcontext", "-a", "-t", context, path])
        .output()?;

        Command::new("restorecon")
        .arg("-v")
        .arg(path)
        .output()?;

        self.load_file_contexts()?;
        Ok(())
    }

    pub fn remove_file_context(&mut self, path: &str, simulation: bool) -> Result<()> {
        if simulation {
            self.contexts.retain(|c| c.path != path);
            return Ok(());
        }

        Command::new("semanage")
        .args(&["fcontext", "-d", path])
        .output()?;

        self.load_file_contexts()?;
        Ok(())
    }
}
