//! **`nms`** — same CLI as `nmaprs` ([`nmaprs::run_from_cli_env`]).

use anyhow::Result;

fn main() -> Result<()> {
    nmaprs::run_from_cli_env()
}
