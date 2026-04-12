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

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr};
    use std::path::Path;

    use tempfile::NamedTempFile;

    use super::ResumeState;

    #[test]
    fn is_done_matches_serialized_ip_string() {
        let mut st = ResumeState::default();
        st.completed
            .push((Ipv4Addr::new(10, 0, 0, 1).to_string(), 443));
        let ip = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
        assert!(st.is_done(ip, 443));
        assert!(!st.is_done(ip, 80));
    }

    #[test]
    fn merge_from_scan_dedupes_and_sorts() {
        let mut st = ResumeState::default();
        st.completed.push(("10.0.0.1".to_string(), 80));
        let ip = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
        st.merge_from_scan(&[(ip, 80), (ip, 443), (ip, 80)]);
        st.completed.sort();
        assert_eq!(
            st.completed,
            vec![("10.0.0.1".to_string(), 80), ("10.0.0.1".to_string(), 443),]
        );
    }

    #[test]
    fn save_load_roundtrip() {
        let st = ResumeState {
            completed: vec![("192.0.2.5".to_string(), 22)],
        };
        let f = NamedTempFile::new().expect("tempfile");
        let path = f.path();
        st.save(path).expect("save");
        let loaded = ResumeState::load(path).expect("load");
        assert_eq!(loaded.completed, st.completed);
    }

    #[test]
    fn load_missing_file_errors() {
        let p = Path::new("/nonexistent/nmaprs-resume-xyz.json");
        assert!(ResumeState::load(p).is_err());
    }
}
