use serde::{Deserialize, Serialize};
use std::process::Command;
use anyhow::Result;
use regex::Regex;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PortContext {
    pub port: String,
    pub protocol: String,
    pub context: String,
}

#[derive(Clone)]
pub struct PortManager {
    pub ports: Vec<PortContext>,
}

impl PortManager {
    pub fn new() -> Self {
        Self { ports: Vec::new() }
    }

    pub fn load_ports(&mut self) -> Result<()> {
        let output = Command::new("semanage")
        .args(&["port", "-l"])
        .output()?
        .stdout;

        let logs = String::from_utf8_lossy(&output);
        let re = Regex::new(r"^(\S+)\s+(\S+)\s+(\S+)\s+(\d+(?:-\d+)?)$")?;

        self.ports.clear();
        for line in logs.lines() {
            if let Some(cap) = re.captures(line) {
                let context = cap[1].to_string();
                let protocol = cap[2].to_string();
                let _mls = cap[3].to_string();
                let port = cap[4].to_string();

                self.ports.push(PortContext { port, protocol, context });
            }
        }
        Ok(())
    }

    pub fn add_port(&mut self, port: &str, protocol: &str, context: &str, simulation: bool) -> Result<()> {
        if simulation {
            self.ports.push(PortContext {
                port: port.to_string(),
                            protocol: protocol.to_string(),
                            context: context.to_string(),
            });
            return Ok(());
        }

        Command::new("semanage")
        .args(&["port", "-a", "-t", context, "-p", protocol, port])
        .output()?;

        self.load_ports()?;
        Ok(())
    }

    pub fn remove_port(&mut self, port: &str, protocol: &str, simulation: bool) -> Result<()> {
        if simulation {
            self.ports.retain(|p| p.port != port || p.protocol != protocol);
            return Ok(());
        }

        Command::new("semanage")
        .args(&["port", "-d", "-p", protocol, port])
        .output()?;

        self.load_ports()?;
        Ok(())
    }
}
