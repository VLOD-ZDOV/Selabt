use std::fs::OpenOptions;
use std::io::Write;
use std::path::PathBuf;
use chrono::Utc;

pub struct Logger {
    log_path: PathBuf,
}

impl Logger {
    pub fn new() -> Self {
        let mut log_path = std::env::temp_dir();
        log_path.push(format!("selab_{}.log", Utc::now().format("%Y%m%d_%H%M%S")));
        
        Self { log_path }
    }
    
    pub fn log(&self, level: &str, message: &str) -> std::io::Result<()> {
        let mut file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.log_path)?;
        
        let timestamp = Utc::now().format("%Y-%m-%d %H:%M:%S");
        writeln!(file, "[{}] [{}] {}", timestamp, level, message)?;
        Ok(())
    }
    
    pub fn info(&self, message: &str) -> std::io::Result<()> {
        self.log("INFO", message)
    }
    
    pub fn error(&self, message: &str) -> std::io::Result<()> {
        self.log("ERROR", message)
    }
    
    pub fn warn(&self, message: &str) -> std::io::Result<()> {
        self.log("WARN", message)
    }
    
    pub fn get_log_path(&self) -> &PathBuf {
        &self.log_path
    }
}

impl Default for Logger {
    fn default() -> Self {
        Self::new()
    }
}

