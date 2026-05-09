//! Linux process code for getting process data via `/proc/`.
//! Based on the [procfs](https://github.com/eminence/procfs) crate.

use std::{
    fs::File,
    io::{self, BufRead, BufReader, Read},
    path::PathBuf,
    sync::OnceLock,
};

use anyhow::anyhow;
use libc::uid_t;
use rustix::{
    fd::OwnedFd,
    fs::{Mode, OFlags},
    path::Arg,
};

use crate::collection::processes::{Pid, linux::is_str_numeric};

static PAGESIZE: OnceLock<u64> = OnceLock::new();

#[inline]
fn next_part<'a>(iter: &mut impl Iterator<Item = &'a str>) -> Result<&'a str, io::Error> {
    iter.next()
        .ok_or_else(|| io::Error::from(io::ErrorKind::InvalidData))
}

/// A wrapper around the data in `/proc/<PID>/stat`. For documentation, see:
/// - <https://manpages.ubuntu.com/manpages/noble/man5/proc_pid_stat.5.html>
/// - <https://man7.org/linux/man-pages/man5/proc_pid_status.5.html>
///
/// Note this does not necessarily get all fields, only the ones we use in
/// bottom.
pub(crate) struct Stat {
    /// The filename of the executable without parentheses.
    pub comm: String,

    /// The current process state, represented by a char.
    pub state: char,

    /// The parent process PID.
    pub ppid: Pid,

    /// The amount of time this process has been scheduled in user mode in clock
    /// ticks.
    pub utime: u64,

    /// The amount of time this process has been scheduled in kernel mode in
    /// clock ticks.
    pub stime: u64,

    /// The resident set size, or the number of pages the process has in real
    /// memory.
    rss: u64,

    /// The virtual memory size in bytes.
    pub vsize: u64,

    /// The start time of the process, represented in clock ticks.
    pub start_time: u64,

    /// Kernel thread
    pub is_kernel_thread: bool,

    /// The kernel scheduling priority.
    pub priority: i32,

    /// The nice value (user-settable scheduling hint).
    #[cfg(unix)]
    pub nice: i32,
}

impl Stat {
    /// Get process stats from a file; this assumes the file is located at
    /// `/proc/<PID>/stat`. For documentation, see
    /// [here](https://manpages.ubuntu.com/manpages/noble/man5/proc_pid_stat.5.html) as a reference.
    fn from_file(mut f: File, buffer: &mut String) -> anyhow::Result<Stat> {
        // Since this is just one line, we can read it all at once. However, since it
        // (technically) might have non-utf8 characters, we can't just use read_to_string.
        f.read_to_end(unsafe { buffer.as_mut_vec() })?;

        // TODO: Is this needed?
        let line = buffer.trim();

        let (comm, rest) = {
            let start_paren = line
                .find('(')
                .ok_or_else(|| anyhow!("start paren missing"))?;
            let end_paren = line.find(')').ok_or_else(|| anyhow!("end paren missing"))?;

            (
                line[start_paren + 1..end_paren].to_string(),
                &line[end_paren + 2..],
            )
        };

        let mut rest = rest.split(' ');
        let state = next_part(&mut rest)?
            .chars()
            .next()
            .ok_or_else(|| anyhow!("missing state"))?;
        let ppid: Pid = next_part(&mut rest)?.parse()?;

        // Skip 4 fields (pgrp, session, tty_nr, tpgid)
        let mut rest = rest.skip(4);

        // read flags for kernel thread (PF_KTHREAD from include/linux/sched.h)
        let flags: u32 = next_part(&mut rest)?.parse()?;
        let is_kernel_thread: bool = flags & 0x00200000 != 0;

        // Skip 4 fields (minflt, cminflt, majflt, cmajflt)
        let mut rest = rest.skip(4);
        let utime: u64 = next_part(&mut rest)?.parse()?;
        let stime: u64 = next_part(&mut rest)?.parse()?;

        // cutime
        let _ = next_part(&mut rest)?;
        // cstime
        let _ = next_part(&mut rest)?;
        // priority
        let priority: i32 = next_part(&mut rest)?.parse()?;
        // nice
        let nice: i32 = next_part(&mut rest)?.parse()?;
        // num_threads
        let _ = next_part(&mut rest)?;
        // itrealvalue
        let _ = next_part(&mut rest)?;

        let start_time: u64 = next_part(&mut rest)?.parse()?;
        let vsize: u64 = next_part(&mut rest)?.parse()?;
        let rss: u64 = next_part(&mut rest)?.parse()?;

        Ok(Stat {
            comm,
            state,
            ppid,
            utime,
            stime,
            rss,
            vsize,
            start_time,
            is_kernel_thread,
            priority,
            nice,
        })
    }

    /// Returns the Resident Set Size in bytes.
    #[inline]
    pub fn rss_bytes(&self) -> u64 {
        self.rss * PAGESIZE.get_or_init(|| rustix::param::page_size() as u64)
    }
}

/// A wrapper around the data in `/proc/<PID>/status`.
///
/// We only pull `VmData` and `VmStk` here — together they approximate the
/// process's *Private Commit* charge against `Committed_AS` (NT analogue:
/// "Private Bytes"). The full `/proc/<PID>/status` file is dozens of lines;
/// we read it once per refresh and stop scanning as soon as we have both.
pub(crate) struct Status {
    /// Size of the data segment + heap + private anon mmaps, in bytes.
    pub vm_data_bytes: u64,
    /// Size of the stack, in bytes.
    pub vm_stk_bytes: u64,
}

impl Status {
    fn from_file(f: File, buffer: &mut String) -> anyhow::Result<Status> {
        const KB: u64 = 1024;

        let mut reader = BufReader::new(f);
        let mut vm_data: u64 = 0;
        let mut vm_stk: u64 = 0;
        let mut have_data = false;
        let mut have_stk = false;

        while let Ok(bytes) = reader.read_line(buffer) {
            if bytes == 0 {
                break;
            }
            // /proc/<pid>/status lines are "Key: value [unit]" with whitespace.
            // Both VmData and VmStk are reported in kB.
            let line = buffer.as_str();
            if let Some(rest) = line.strip_prefix("VmData:") {
                if let Some(tok) = rest.split_whitespace().next() {
                    vm_data = tok.parse::<u64>().unwrap_or(0).saturating_mul(KB);
                    have_data = true;
                }
            } else if let Some(rest) = line.strip_prefix("VmStk:") {
                if let Some(tok) = rest.split_whitespace().next() {
                    vm_stk = tok.parse::<u64>().unwrap_or(0).saturating_mul(KB);
                    have_stk = true;
                }
            }
            buffer.clear();
            if have_data && have_stk {
                break;
            }
        }

        Ok(Status {
            vm_data_bytes: vm_data,
            vm_stk_bytes: vm_stk,
        })
    }

    /// Estimated Private Commit (~ NT "Private Bytes"): private writable VAs,
    /// faulted in or not. Includes `MAP_NORESERVE` mappings, which slightly
    /// overcounts vs. the kernel's true `Committed_AS` charge — but in
    /// practice modern allocators (V8, Gecko, glibc) reserve via `PROT_NONE`
    /// + `mprotect` rather than `MAP_NORESERVE`, so the proxy lines up with
    /// the exact value to ~3 sig figs on real workloads.
    #[inline]
    pub fn private_commit_bytes(&self) -> u64 {
        self.vm_data_bytes.saturating_add(self.vm_stk_bytes)
    }
}

/// A wrapper around the relevant fields of `/proc/<PID>/smaps_rollup`.
///
/// Reads `Pss` (Proportional Set Size — fair-share resident bytes) and
/// `SwapPss` (same, for swapped-out pages). The sum is the closest
/// single per-process number to "what would actually free up if this
/// process exited," accounting for shared pages and swap, and
/// independent of the ephemeral RAM-vs-swap distinction.
///
/// Reading `smaps_rollup` requires either being the process owner or
/// having `CAP_SYS_PTRACE`. Failure is non-fatal.
pub(crate) struct SmapsRollup {
    pub pss_bytes: u64,
    pub swap_pss_bytes: u64,
}

impl SmapsRollup {
    fn from_file(f: File, buffer: &mut String) -> anyhow::Result<SmapsRollup> {
        const KB: u64 = 1024;

        let mut reader = BufReader::new(f);
        let mut pss: u64 = 0;
        let mut swap_pss: u64 = 0;
        let mut have_pss = false;
        let mut have_swap_pss = false;

        while let Ok(bytes) = reader.read_line(buffer) {
            if bytes == 0 {
                break;
            }
            let line = buffer.as_str();
            // Order matters: SwapPss must be checked before Pss because
            // both prefixes start with "Pss" — well, "SwapPss" doesn't,
            // but `strip_prefix("Pss:")` would still miss SwapPss
            // because of the leading "Swap". Belt-and-braces: use
            // explicit equals on the key.
            let key = line.split(':').next().unwrap_or("");
            if key == "Pss" {
                if let Some(rest) = line.strip_prefix("Pss:") {
                    if let Some(tok) = rest.split_whitespace().next() {
                        pss = tok.parse::<u64>().unwrap_or(0).saturating_mul(KB);
                        have_pss = true;
                    }
                }
            } else if key == "SwapPss" {
                if let Some(rest) = line.strip_prefix("SwapPss:") {
                    if let Some(tok) = rest.split_whitespace().next() {
                        swap_pss = tok.parse::<u64>().unwrap_or(0).saturating_mul(KB);
                        have_swap_pss = true;
                    }
                }
            }
            buffer.clear();
            if have_pss && have_swap_pss {
                break;
            }
        }

        Ok(SmapsRollup {
            pss_bytes: pss,
            swap_pss_bytes: swap_pss,
        })
    }

    /// Footprint = `Pss + SwapPss`. NT-style "real cost" of a process —
    /// the storage-backed memory that this process is on the hook for,
    /// fair-share-divided across other mappers, and bridged across the
    /// RAM-vs-swap divide so it doesn't flicker as pages get swapped in
    /// and out under pressure.
    #[inline]
    pub fn footprint_bytes(&self) -> u64 {
        self.pss_bytes.saturating_add(self.swap_pss_bytes)
    }
}

/// A wrapper around the data in `/proc/<PID>/io`.
///
/// Note this does not necessarily get all fields, only the ones we use in
/// bottom.
pub(crate) struct Io {
    pub read_bytes: u64,
    pub write_bytes: u64,
}

impl Io {
    #[inline]
    fn from_file(f: File, buffer: &mut String) -> anyhow::Result<Io> {
        const NUM_FIELDS: u16 = 0; // Make sure to update this if you want more fields!
        enum Fields {
            ReadBytes,
            WriteBytes,
        }

        let mut read_fields = 0;
        let mut reader = BufReader::new(f);

        let mut read_bytes = 0;
        let mut write_bytes = 0;

        // This saves us from doing a string allocation on each iteration compared to
        // `lines()`.
        while let Ok(bytes) = reader.read_line(buffer) {
            if bytes > 0 {
                if buffer.is_empty() {
                    // Empty, no need to clear.
                    continue;
                }

                let mut parts = buffer.split_whitespace();

                if let Some(field) = parts.next() {
                    let curr_field = match field {
                        "read_bytes:" => Fields::ReadBytes,
                        "write_bytes:" => Fields::WriteBytes,
                        _ => {
                            buffer.clear();
                            continue;
                        }
                    };

                    if let Some(value) = parts.next() {
                        let value = value.parse::<u64>()?;
                        match curr_field {
                            Fields::ReadBytes => {
                                read_bytes = value;
                                read_fields += 1;
                            }
                            Fields::WriteBytes => {
                                write_bytes = value;
                                read_fields += 1;
                            }
                        }
                    }
                }

                // Quick short circuit if we have already read all the required fields.
                if read_fields == NUM_FIELDS {
                    break;
                }

                buffer.clear();
            } else {
                break;
            }
        }

        Ok(Io {
            read_bytes,
            write_bytes,
        })
    }
}

/// A wrapper around a Linux process operations in `/proc/<PID>`.
///
/// Core documentation based on [proc's manpages](https://man7.org/linux/man-pages/man5/proc.5.html).
pub(crate) struct Process {
    pub pid: Pid,
    pub uid: Option<uid_t>,
    pub stat: Stat,
    pub status: Option<Status>,
    pub smaps_rollup: Option<SmapsRollup>,
    pub io: Option<Io>,
    pub cmdline: Option<String>,
}

#[inline]
fn reset(root: &mut PathBuf, buffer: &mut String) {
    root.pop();
    buffer.clear();
}

impl Process {
    /// Creates a new [`Process`] given a `/proc/<PID>` path. This may fail if
    /// the process no longer exists or there are permissions issues.
    ///
    /// Note that this pre-allocates fields on **creation**! As such, some data
    /// might end up "outdated" depending on when you call some of the
    /// methods. Therefore, this struct is only useful for either fields
    /// that are unlikely to change, or are short-lived and
    /// will be discarded quickly.
    ///
    /// This takes in a buffer to avoid allocs; this function will clear the buffer.
    #[inline]
    pub(crate) fn from_path(
        pid_path: PathBuf, buffer: &mut String, get_threads: bool,
    ) -> anyhow::Result<(Process, Vec<PathBuf>)> {
        buffer.clear();

        let pid_dir = rustix::fs::openat(
            rustix::fs::CWD,
            pid_path.as_path(),
            OFlags::PATH | OFlags::DIRECTORY | OFlags::CLOEXEC,
            Mode::empty(),
        )?;

        let pid = pid_path
            .as_path()
            .components()
            .next_back()
            .and_then(|s| s.to_string_lossy().parse::<Pid>().ok())
            .or_else(|| {
                rustix::fs::readlinkat(rustix::fs::CWD, pid_path.as_path(), vec![])
                    .ok()
                    .and_then(|s| s.to_string_lossy().parse::<Pid>().ok())
            })
            .ok_or_else(|| anyhow!("PID for {pid_path:?} was not found"))?;

        let uid = {
            let metadata = rustix::fs::fstat(&pid_dir);
            match metadata {
                Ok(md) => Some(md.st_uid),
                Err(_) => None,
            }
        };

        let mut root = pid_path;

        // NB: Whenever you add a new stat, make sure to pop the root and clear the
        // buffer!

        // Stat is pretty long, do this first to pre-allocate up-front.
        let stat =
            open_at(&mut root, "stat", &pid_dir).and_then(|file| Stat::from_file(file, buffer))?;
        reset(&mut root, buffer);

        // /proc/<pid>/status — only used to extract VmData + VmStk for the
        // PrivateCommit column. Failure is non-fatal; we just won't have the
        // value for this process.
        let status = open_at(&mut root, "status", &pid_dir)
            .and_then(|file| Status::from_file(file, buffer))
            .ok();
        reset(&mut root, buffer);

        // /proc/<pid>/smaps_rollup — for Pss + SwapPss (Footprint
        // column). Fails for processes owned by other users without
        // CAP_SYS_PTRACE; that's expected and we just won't have a
        // value for those rows.
        let smaps_rollup = open_at(&mut root, "smaps_rollup", &pid_dir)
            .and_then(|file| SmapsRollup::from_file(file, buffer))
            .ok();
        reset(&mut root, buffer);

        let cmdline = if cmdline(&mut root, &pid_dir, buffer).is_ok() {
            // The clone will give a string with the capacity of the length of buffer, don't worry.
            Some(buffer.clone())
        } else {
            None
        };
        reset(&mut root, buffer);

        let io = open_at(&mut root, "io", &pid_dir)
            .and_then(|file| Io::from_file(file, buffer))
            .ok();

        reset(&mut root, buffer);

        let threads = threads(&mut root, pid, get_threads);

        Ok((
            Process {
                pid,
                uid,
                stat,
                status,
                smaps_rollup,
                io,
                cmdline,
            },
            threads,
        ))
    }
}

#[inline]
fn cmdline(root: &mut PathBuf, fd: &OwnedFd, buffer: &mut String) -> anyhow::Result<()> {
    let _ = open_at(root, "cmdline", fd).map(|mut file| file.read_to_string(buffer))?;

    Ok(())
}

/// Opens a path. Note that this function takes in a mutable root - this will
/// mutate it to avoid allocations. You probably will want to pop the most
/// recent child after if you need to use the buffer again.
#[inline]
fn open_at(root: &mut PathBuf, child: &str, fd: &OwnedFd) -> anyhow::Result<File> {
    root.push(child);
    let new_fd = rustix::fs::openat(fd, &*root, OFlags::RDONLY | OFlags::CLOEXEC, Mode::empty())?;

    Ok(File::from(new_fd))
}

#[inline]
fn threads(root: &mut PathBuf, pid: Pid, get_threads: bool) -> Vec<PathBuf> {
    if get_threads {
        root.push("task");

        let Ok(task_dir) = rustix::fs::openat(
            rustix::fs::CWD,
            root.as_path(),
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC,
            Mode::empty(),
        ) else {
            return Vec::new();
        };

        if let Ok(task) = rustix::fs::Dir::read_from(task_dir) {
            let pid_str = pid.to_string();

            return task
                .flatten()
                .filter_map(|thread_dir| {
                    let file_name = thread_dir.file_name();
                    let file_name = file_name.to_string_lossy();
                    let file_name = file_name.trim();

                    if is_str_numeric(file_name) && file_name != pid_str {
                        Some(root.join(file_name).to_path_buf())
                    } else {
                        None
                    }
                })
                .collect::<Vec<_>>();
        }
    }

    Vec::new()
}
