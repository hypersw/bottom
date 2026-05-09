use std::{fs, path::Path, sync::OnceLock};

/// Whether the temperature should *actually* be read during enumeration.
/// Will return false if the state is not D0/unknown, or if it does not support
/// `device/power_state`.
///
/// `path` is a path to the device itself (e.g. `/sys/class/hwmon/hwmon1/device`).
#[inline]
pub fn is_device_awake(device: &Path) -> bool {
    // Whether the temperature should *actually* be read during enumeration.
    // Set to false if the device is in ACPI D3cold.
    // Documented at https://www.kernel.org/doc/Documentation/ABI/testing/sysfs-devices-power_state
    let power_state = device.join("power_state");
    if power_state.exists() {
        if let Ok(state) = fs::read_to_string(power_state) {
            let state = state.trim();
            // The zenpower3 kernel module (incorrectly?) reports "unknown", causing this
            // check to fail and temperatures to appear as zero instead of
            // having the file not exist.
            //
            // Their self-hosted git instance has disabled sign up, so this bug can't be
            // reported either.
            state == "D0" || state == "unknown"
        } else {
            true
        }
    } else {
        true
    }
}

/// `vm.overcommit_memory` mode, cached for the lifetime of the process.
///
/// Possible values per Documentation/admin-guide/sysctl/vm.rst:
///   0 = heuristic (default)
///   1 = always overcommit
///   2 = strict — never exceed `CommitLimit`; mmap fails with `ENOMEM`
///       once `Committed_AS` would cross the limit
///
/// We read this exactly once. Operators *can* change it at runtime via
/// sysctl, but the practical reason we care (column visibility, gauge
/// display) is set up at app start and rebuilding everything mid-session is
/// not worth the complexity. Restart `btm` to pick up a change.
pub fn overcommit_mode() -> u8 {
    static MODE: OnceLock<u8> = OnceLock::new();
    *MODE.get_or_init(|| {
        fs::read_to_string("/proc/sys/vm/overcommit_memory")
            .ok()
            .and_then(|s| s.trim().parse::<u8>().ok())
            .unwrap_or(0)
    })
}

/// Convenience: are we under strict no-overcommit (`overcommit_memory=2`)?
/// On non-Linux this function is absent — gate callers with `cfg(target_os
/// = "linux")` or check via [`overcommit_mode`] only inside Linux paths.
#[inline]
pub fn is_strict_overcommit() -> bool {
    overcommit_mode() == 2
}
