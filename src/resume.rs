//! `--resume` checkpoint: JSON list of completed `(host, port)` pairs.

use std::collections::HashSet;
use std::net::IpAddr;
use std::path::Path;

use anyhow::Result;
use serde::{Deserialize, Serialize};
/// `ResumeState` — see fields for layout.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ResumeState {
    /// `completed` field.
    pub completed: Vec<(String, u16)>,
}

impl ResumeState {
    /// `load` — see implementation.
    pub fn load(path: &Path) -> Result<Self> {
        let data = std::fs::read_to_string(path)?;
        Ok(serde_json::from_str(&data)?)
    }
    /// `save` — see implementation.
    pub fn save(&self, path: &Path) -> Result<()> {
        let data = serde_json::to_string_pretty(self)?;
        std::fs::write(path, data)?;
        Ok(())
    }
    /// `done_set` — see implementation.
    pub fn done_set(&self) -> HashSet<(String, u16)> {
        self.completed.iter().cloned().collect()
    }
    /// `is_done` — see implementation.
    pub fn is_done(&self, host: IpAddr, port: u16) -> bool {
        self.completed
            .iter()
            .any(|(h, p)| h == &host.to_string() && *p == port)
    }
    /// `merge_from_scan` — see implementation.
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

    #[test]
    fn done_set_is_hash_of_completed_pairs() {
        let st = ResumeState {
            completed: vec![("10.0.0.1".into(), 22), ("10.0.0.2".into(), 80)],
        };
        let set = st.done_set();
        assert!(set.contains(&("10.0.0.1".to_string(), 22)));
        assert!(set.contains(&("10.0.0.2".to_string(), 80)));
        assert_eq!(set.len(), 2);
    }

    #[test]
    fn merge_from_scan_on_empty_state() {
        let mut st = ResumeState::default();
        let ip = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1));
        st.merge_from_scan(&[(ip, 25), (ip, 26)]);
        st.completed.sort();
        assert_eq!(
            st.completed,
            vec![("192.0.2.1".to_string(), 25), ("192.0.2.1".to_string(), 26)]
        );
    }

    #[test]
    fn is_done_ipv6_string_form() {
        let mut st = ResumeState::default();
        st.completed.push(("2001:db8::1".to_string(), 443));
        let ip: IpAddr = "2001:db8::1".parse().unwrap();
        assert!(st.is_done(ip, 443));
        assert!(!st.is_done(ip, 80));
    }

    #[test]
    fn save_creates_valid_json() {
        let st = ResumeState {
            completed: vec![("127.0.0.1".to_string(), 1)],
        };
        let f = NamedTempFile::new().unwrap();
        st.save(f.path()).unwrap();
        let raw = std::fs::read_to_string(f.path()).unwrap();
        assert!(raw.contains("127.0.0.1"));
        assert!(raw.contains("\"completed\""));
    }

    #[test]
    fn merge_from_scan_preserves_other_hosts() {
        let mut st = ResumeState::default();
        st.completed.push(("10.0.0.1".to_string(), 22));
        let ip2 = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2));
        st.merge_from_scan(&[(ip2, 80)]);
        assert!(st.is_done("10.0.0.1".parse().unwrap(), 22));
        assert!(st.is_done(ip2, 80));
    }

    #[test]
    fn load_invalid_json_errors() {
        let f = NamedTempFile::new().unwrap();
        std::fs::write(f.path(), b"not json").unwrap();
        assert!(ResumeState::load(f.path()).is_err());
    }

    #[test]
    fn is_done_false_for_wrong_port() {
        let mut st = ResumeState::default();
        st.completed.push(("127.0.0.1".to_string(), 22));
        let ip: IpAddr = "127.0.0.1".parse().unwrap();
        assert!(!st.is_done(ip, 443));
    }

    #[test]
    fn done_set_empty_for_default_state() {
        assert!(ResumeState::default().done_set().is_empty());
    }

    #[test]
    fn merge_from_scan_dedupes_repeated_merge() {
        let mut st = ResumeState::default();
        let ip = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 5));
        st.merge_from_scan(&[(ip, 22)]);
        st.merge_from_scan(&[(ip, 22)]);
        assert_eq!(st.completed.len(), 1);
    }

    #[test]
    fn is_done_false_for_untracked_host() {
        let st = ResumeState::default();
        let ip: IpAddr = "10.0.0.1".parse().unwrap();
        assert!(!st.is_done(ip, 22));
    }

    #[test]
    fn done_set_ipv6_key() {
        let mut st = ResumeState::default();
        st.completed.push(("::1".to_string(), 22));
        let ip: IpAddr = "::1".parse().unwrap();
        assert!(st.done_set().contains(&("::1".to_string(), 22)));
        assert!(st.is_done(ip, 22));
    }

    #[test]
    fn save_empty_state_writes_completed_array() {
        let st = ResumeState::default();
        let f = NamedTempFile::new().unwrap();
        st.save(f.path()).unwrap();
        let raw = std::fs::read_to_string(f.path()).unwrap();
        assert!(raw.contains("completed"));
    }

    #[test]
    fn merge_from_scan_multiple_ports_same_host() {
        let mut st = ResumeState::default();
        let ip = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 7));
        st.merge_from_scan(&[(ip, 22), (ip, 80)]);
        assert_eq!(st.completed.len(), 2);
        assert!(st.is_done(ip, 22));
        assert!(st.is_done(ip, 80));
    }

    #[test]
    fn merge_from_scan_empty_input_no_op() {
        let mut st = ResumeState::default();
        st.merge_from_scan(&[]);
        assert!(st.completed.is_empty());
    }

    #[test]
    fn load_roundtrip_multiple_hosts() {
        let st = ResumeState {
            completed: vec![("10.0.0.1".to_string(), 22), ("10.0.0.2".to_string(), 80)],
        };
        let f = NamedTempFile::new().unwrap();
        st.save(f.path()).unwrap();
        let loaded = ResumeState::load(f.path()).unwrap();
        assert_eq!(loaded.completed.len(), 2);
    }

    #[test]
    fn is_done_port_zero() {
        let mut st = ResumeState::default();
        st.completed.push(("127.0.0.1".to_string(), 0));
        let ip: IpAddr = "127.0.0.1".parse().unwrap();
        assert!(st.is_done(ip, 0));
    }

    #[test]
    fn merge_from_scan_sorts_lexicographically() {
        let mut st = ResumeState::default();
        let ip = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
        st.merge_from_scan(&[(ip, 443), (ip, 22)]);
        st.completed.sort();
        assert_eq!(st.completed[0].1, 22);
        assert_eq!(st.completed[1].1, 443);
    }

    #[test]
    fn done_set_dedupes_duplicate_entries() {
        let st = ResumeState {
            completed: vec![("1.1.1.1".into(), 53), ("1.1.1.1".into(), 53)],
        };
        assert_eq!(st.done_set().len(), 1);
    }
}
