//! `--resume` checkpoint: JSON list of completed `(host, port)` pairs.

use std::collections::HashSet;
use std::net::IpAddr;
use std::path::Path;

use anyhow::Result;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ResumeState {
    pub completed: Vec<(String, u16)>,
}

impl ResumeState {
    pub fn load(path: &Path) -> Result<Self> {
        let data = std::fs::read_to_string(path)?;
        Ok(serde_json::from_str(&data)?)
    }

    pub fn save(&self, path: &Path) -> Result<()> {
        let data = serde_json::to_string_pretty(self)?;
        std::fs::write(path, data)?;
        Ok(())
    }

    pub fn done_set(&self) -> HashSet<(String, u16)> {
        self.completed.iter().cloned().collect()
    }

    pub fn is_done(&self, host: IpAddr, port: u16) -> bool {
        self.completed
            .iter()
            .any(|(h, p)| h == &host.to_string() && *p == port)
    }

    pub fn merge_from_scan(&mut self, pairs: &[(IpAddr, u16)]) {
        let mut s = self.done_set();
        for (h, p) in pairs {
            s.insert((h.to_string(), *p));
        }
        self.completed = s.into_iter().collect();
        self.completed.sort();
    }
}
