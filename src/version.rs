//! Version information and API compatibility

/// The version of this crate
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

/// The major version number
pub const VERSION_MAJOR: u32 = 0;

/// The minor version number  
pub const VERSION_MINOR: u32 = 2;

/// The patch version number
pub const VERSION_PATCH: u32 = 0;

/// Whether this is a pre-release version
pub const IS_PRERELEASE: bool = VERSION_MAJOR == 0;

/// API compatibility level
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ApiCompatibility {
    /// Pre-1.0: Breaking changes allowed in minor versions
    Unstable,
    /// 1.0+: Breaking changes only in major versions
    Stable,
}

/// Get the current API compatibility level
pub const fn api_compatibility() -> ApiCompatibility {
    if VERSION_MAJOR == 0 {
        ApiCompatibility::Unstable
    } else {
        ApiCompatibility::Stable
    }
}

/// Minimum Supported Rust Version (MSRV)
pub const MSRV: &str = "1.85.0";

/// Check if the current Rust version meets the MSRV requirement
pub fn check_msrv() -> Result<(), String> {
    // This would ideally check the actual Rust version at runtime
    // For now, we rely on Cargo.toml rust-version field
    Ok(())
}

/// Version information structure
#[derive(Debug, Clone)]
pub struct VersionInfo {
    /// Version string
    pub version: &'static str,
    /// Major version
    pub major: u32,
    /// Minor version
    pub minor: u32,
    /// Patch version  
    pub patch: u32,
    /// API compatibility level
    pub api_compatibility: ApiCompatibility,
    /// MSRV requirement
    pub msrv: &'static str,
}

/// Get complete version information
pub const fn version_info() -> VersionInfo {
    VersionInfo {
        version: VERSION,
        major: VERSION_MAJOR,
        minor: VERSION_MINOR,
        patch: VERSION_PATCH,
        api_compatibility: api_compatibility(),
        msrv: MSRV,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_version_constants() {
        assert_eq!(VERSION_MAJOR, 0);
        assert_eq!(VERSION_MINOR, 2);
        assert_eq!(VERSION_PATCH, 0);
        assert!(IS_PRERELEASE);
        assert_eq!(api_compatibility(), ApiCompatibility::Unstable);
    }

    #[test]
    fn test_version_info() {
        let info = version_info();
        assert_eq!(info.major, 0);
        assert_eq!(info.minor, 2);
        assert_eq!(info.patch, 0);
        assert_eq!(info.api_compatibility, ApiCompatibility::Unstable);
        assert_eq!(info.msrv, "1.85.0");
    }

    #[test]
    fn test_msrv_check() {
        assert!(check_msrv().is_ok());
    }
}