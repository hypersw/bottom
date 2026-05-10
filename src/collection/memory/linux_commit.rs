//! Linux-only commit-charge reader.
//!
//! Returns `(Committed_AS, CommitLimit)` packed into a [`MemData`] so it
//! reuses the same gauge / time-series infrastructure as RAM, swap and
//! cache. Under `vm.overcommit_memory=2` (strict no-overbooking) this is
//! the *only* gauge that predicts whether the next `mmap` will succeed:
//! `Committed_AS / CommitLimit` is what the kernel actually checks. RAM
//! free + swap free can look healthy while this gauge is at 99 % and the
//! next big VM start fails with ENOMEM.

use std::{
    fs::File,
    io::{BufRead, BufReader},
    num::NonZeroU64,
};

use super::MemData;

/// Read `CommitLimit` and `Committed_AS` from `/proc/meminfo`.
///
/// Both fields are reported in kB. Returns `None` if the file can't be
/// opened or either field is missing — i.e., on a kernel that doesn't
/// expose them, the gauge stays absent rather than showing zeros.
pub(crate) fn get_commit_usage() -> Option<MemData> {
    const KB: u64 = 1024;

    let f = File::open("/proc/meminfo").ok()?;
    let mut reader = BufReader::new(f);

    let mut commit_limit: Option<u64> = None;
    let mut committed_as: Option<u64> = None;
    let mut line = String::new();

    while reader.read_line(&mut line).ok()? > 0 {
        if let Some(rest) = line.strip_prefix("CommitLimit:") {
            if let Some(tok) = rest.split_whitespace().next() {
                commit_limit = tok.parse::<u64>().ok().map(|v| v.saturating_mul(KB));
            }
        } else if let Some(rest) = line.strip_prefix("Committed_AS:") {
            if let Some(tok) = rest.split_whitespace().next() {
                committed_as = tok.parse::<u64>().ok().map(|v| v.saturating_mul(KB));
            }
        }
        if commit_limit.is_some() && committed_as.is_some() {
            break;
        }
        line.clear();
    }

    let total_bytes = NonZeroU64::new(commit_limit?)?;
    Some(MemData {
        used_bytes: committed_as?,
        total_bytes,
    })
}
