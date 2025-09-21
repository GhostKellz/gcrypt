//! Permission system for Guardian Framework
//!
//! Defines granular permissions for Ghostchain ecosystem services.

use core::fmt;

#[cfg(feature = "alloc")]
use alloc::{vec::Vec, string::String};

/// Permission for a specific service and operations
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg(feature = "alloc")]
pub struct Permission {
    /// Service name (e.g., "ghostd", "walletd", "cns", "gid")
    pub service: String,
    /// Allowed operations for this service
    pub operations: Vec<String>,
    /// Optional constraints on the permission
    pub constraints: Option<PermissionConstraints>,
}

#[cfg(feature = "alloc")]
impl Permission {
    /// Create a new permission
    pub fn new(service: String, operations: Vec<String>) -> Self {
        Self {
            service,
            operations,
            constraints: None,
        }
    }

    /// Create a permission with constraints
    pub fn with_constraints(
        service: String,
        operations: Vec<String>,
        constraints: PermissionConstraints,
    ) -> Self {
        Self {
            service,
            operations,
            constraints: Some(constraints),
        }
    }

    /// Check if this permission allows a specific operation
    pub fn allows_operation(&self, operation: &str) -> bool {
        self.operations.iter().any(|op| op == operation)
    }

    /// Check if constraints are satisfied
    pub fn check_constraints(&self, context: &PermissionContext) -> bool {
        match &self.constraints {
            Some(constraints) => constraints.is_satisfied(context),
            None => true,
        }
    }

    /// Add an operation to this permission
    pub fn add_operation(&mut self, operation: String) {
        if !self.operations.contains(&operation) {
            self.operations.push(operation);
        }
    }

    /// Remove an operation from this permission
    pub fn remove_operation(&mut self, operation: &str) {
        self.operations.retain(|op| op != operation);
    }

    /// Get all operations as a slice
    pub fn operations(&self) -> &[String] {
        &self.operations
    }
}

/// Constraints that can be applied to permissions
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg(feature = "alloc")]
pub struct PermissionConstraints {
    /// Time-based constraints
    pub time_constraints: Option<TimeConstraints>,
    /// Resource-based constraints
    pub resource_constraints: Option<ResourceConstraints>,
    /// Rate limiting constraints
    pub rate_constraints: Option<RateConstraints>,
}

#[cfg(feature = "alloc")]
impl PermissionConstraints {
    /// Create new empty constraints
    pub fn new() -> Self {
        Self {
            time_constraints: None,
            resource_constraints: None,
            rate_constraints: None,
        }
    }

    /// Add time constraints
    pub fn with_time_constraints(mut self, constraints: TimeConstraints) -> Self {
        self.time_constraints = Some(constraints);
        self
    }

    /// Add resource constraints
    pub fn with_resource_constraints(mut self, constraints: ResourceConstraints) -> Self {
        self.resource_constraints = Some(constraints);
        self
    }

    /// Add rate constraints
    pub fn with_rate_constraints(mut self, constraints: RateConstraints) -> Self {
        self.rate_constraints = Some(constraints);
        self
    }

    /// Check if all constraints are satisfied
    pub fn is_satisfied(&self, context: &PermissionContext) -> bool {
        // Check time constraints
        if let Some(time_constraints) = &self.time_constraints {
            if !time_constraints.is_satisfied(context.timestamp) {
                return false;
            }
        }

        // Check resource constraints
        if let Some(resource_constraints) = &self.resource_constraints {
            if !resource_constraints.is_satisfied(&context.resource_path) {
                return false;
            }
        }

        // Check rate constraints
        if let Some(rate_constraints) = &self.rate_constraints {
            if !rate_constraints.is_satisfied(context.request_count, context.time_window) {
                return false;
            }
        }

        true
    }
}

#[cfg(feature = "alloc")]
impl Default for PermissionConstraints {
    fn default() -> Self {
        Self::new()
    }
}

/// Time-based permission constraints
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TimeConstraints {
    /// Permission valid from this timestamp
    pub valid_from: Option<u64>,
    /// Permission valid until this timestamp
    pub valid_until: Option<u64>,
    /// Days of week when permission is valid (0 = Sunday, 6 = Saturday)
    pub valid_days: Option<Vec<u8>>,
    /// Hours of day when permission is valid (0-23)
    pub valid_hours: Option<(u8, u8)>, // (start_hour, end_hour)
}

impl TimeConstraints {
    /// Create new time constraints
    pub fn new() -> Self {
        Self {
            valid_from: None,
            valid_until: None,
            valid_days: None,
            valid_hours: None,
        }
    }

    /// Set validity period
    pub fn with_validity_period(mut self, from: u64, until: u64) -> Self {
        self.valid_from = Some(from);
        self.valid_until = Some(until);
        self
    }

    /// Set valid days of week
    #[cfg(feature = "alloc")]
    pub fn with_valid_days(mut self, days: Vec<u8>) -> Self {
        self.valid_days = Some(days);
        self
    }

    /// Set valid hours
    pub fn with_valid_hours(mut self, start_hour: u8, end_hour: u8) -> Self {
        self.valid_hours = Some((start_hour, end_hour));
        self
    }

    /// Check if time constraints are satisfied
    pub fn is_satisfied(&self, timestamp: u64) -> bool {
        // Check validity period
        if let Some(valid_from) = self.valid_from {
            if timestamp < valid_from {
                return false;
            }
        }

        if let Some(valid_until) = self.valid_until {
            if timestamp >= valid_until {
                return false;
            }
        }

        // For day/hour constraints, we'd need to convert timestamp to local time
        // This is simplified for demonstration
        true
    }
}

impl Default for TimeConstraints {
    fn default() -> Self {
        Self::new()
    }
}

/// Resource-based permission constraints
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg(feature = "alloc")]
pub struct ResourceConstraints {
    /// Allowed resource paths or patterns
    pub allowed_paths: Vec<String>,
    /// Denied resource paths or patterns
    pub denied_paths: Vec<String>,
    /// Maximum resource size (in bytes)
    pub max_size: Option<u64>,
}

#[cfg(feature = "alloc")]
impl ResourceConstraints {
    /// Create new resource constraints
    pub fn new() -> Self {
        Self {
            allowed_paths: Vec::new(),
            denied_paths: Vec::new(),
            max_size: None,
        }
    }

    /// Add allowed path pattern
    pub fn allow_path(mut self, path: String) -> Self {
        self.allowed_paths.push(path);
        self
    }

    /// Add denied path pattern
    pub fn deny_path(mut self, path: String) -> Self {
        self.denied_paths.push(path);
        self
    }

    /// Set maximum resource size
    pub fn with_max_size(mut self, size: u64) -> Self {
        self.max_size = Some(size);
        self
    }

    /// Check if resource constraints are satisfied
    pub fn is_satisfied(&self, resource_path: &str) -> bool {
        // Check denied paths first
        for denied in &self.denied_paths {
            if resource_path.starts_with(denied) {
                return false;
            }
        }

        // Check allowed paths
        if !self.allowed_paths.is_empty() {
            let mut allowed = false;
            for allowed_path in &self.allowed_paths {
                if resource_path.starts_with(allowed_path) {
                    allowed = true;
                    break;
                }
            }
            if !allowed {
                return false;
            }
        }

        true
    }
}

#[cfg(feature = "alloc")]
impl Default for ResourceConstraints {
    fn default() -> Self {
        Self::new()
    }
}

/// Rate limiting constraints
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RateConstraints {
    /// Maximum number of requests
    pub max_requests: u32,
    /// Time window in seconds
    pub window_seconds: u32,
    /// Burst allowance
    pub burst_size: Option<u32>,
}

impl RateConstraints {
    /// Create new rate constraints
    pub fn new(max_requests: u32, window_seconds: u32) -> Self {
        Self {
            max_requests,
            window_seconds,
            burst_size: None,
        }
    }

    /// Set burst allowance
    pub fn with_burst_size(mut self, burst_size: u32) -> Self {
        self.burst_size = Some(burst_size);
        self
    }

    /// Check if rate constraints are satisfied
    pub fn is_satisfied(&self, current_requests: u32, time_window: u32) -> bool {
        if time_window > self.window_seconds {
            // If we're looking at a longer time window, scale the limit
            let scale_factor = time_window as f64 / self.window_seconds as f64;
            let scaled_limit = (self.max_requests as f64 * scale_factor) as u32;
            current_requests <= scaled_limit
        } else {
            current_requests <= self.max_requests
        }
    }
}

/// Context for evaluating permission constraints
#[derive(Debug, Clone)]
#[cfg(feature = "alloc")]
pub struct PermissionContext {
    /// Current timestamp
    pub timestamp: u64,
    /// Resource being accessed
    pub resource_path: String,
    /// Current request count in time window
    pub request_count: u32,
    /// Time window being evaluated
    pub time_window: u32,
    /// Additional context data
    pub metadata: Vec<u8>,
}

#[cfg(feature = "alloc")]
impl PermissionContext {
    /// Create a new permission context
    pub fn new(timestamp: u64, resource_path: String) -> Self {
        Self {
            timestamp,
            resource_path,
            request_count: 0,
            time_window: 0,
            metadata: Vec::new(),
        }
    }

    /// Set request count and time window for rate limiting
    pub fn with_rate_info(mut self, request_count: u32, time_window: u32) -> Self {
        self.request_count = request_count;
        self.time_window = time_window;
        self
    }

    /// Add metadata
    pub fn with_metadata(mut self, metadata: Vec<u8>) -> Self {
        self.metadata = metadata;
        self
    }
}

/// Predefined permissions for Ghostchain services
#[cfg(feature = "alloc")]
pub struct GhostchainPermissions;

#[cfg(feature = "alloc")]
impl GhostchainPermissions {
    /// GHOSTD (blockchain daemon) permissions
    pub fn ghostd_read() -> Permission {
        Permission::new(
            "ghostd".to_string(),
            vec![
                "get_block".to_string(),
                "get_transaction".to_string(),
                "get_balance".to_string(),
                "get_state".to_string(),
            ],
        )
    }

    pub fn ghostd_write() -> Permission {
        Permission::new(
            "ghostd".to_string(),
            vec![
                "submit_transaction".to_string(),
                "broadcast_block".to_string(),
            ],
        )
    }

    pub fn ghostd_admin() -> Permission {
        Permission::new(
            "ghostd".to_string(),
            vec![
                "get_block".to_string(),
                "get_transaction".to_string(),
                "get_balance".to_string(),
                "get_state".to_string(),
                "submit_transaction".to_string(),
                "broadcast_block".to_string(),
                "configure_node".to_string(),
                "manage_peers".to_string(),
            ],
        )
    }

    /// WALLETD (wallet daemon) permissions
    pub fn walletd_read() -> Permission {
        Permission::new(
            "walletd".to_string(),
            vec![
                "list_wallets".to_string(),
                "get_balance".to_string(),
                "get_address".to_string(),
                "list_transactions".to_string(),
            ],
        )
    }

    pub fn walletd_transact() -> Permission {
        Permission::new(
            "walletd".to_string(),
            vec![
                "send_transaction".to_string(),
                "sign_message".to_string(),
                "create_address".to_string(),
            ],
        )
    }

    pub fn walletd_admin() -> Permission {
        Permission::new(
            "walletd".to_string(),
            vec![
                "create_wallet".to_string(),
                "delete_wallet".to_string(),
                "backup_wallet".to_string(),
                "restore_wallet".to_string(),
                "manage_keys".to_string(),
            ],
        )
    }

    /// CNS (Crypto Name Server) permissions
    pub fn cns_read() -> Permission {
        Permission::new(
            "cns".to_string(),
            vec![
                "resolve_name".to_string(),
                "lookup_address".to_string(),
                "get_record".to_string(),
            ],
        )
    }

    pub fn cns_write() -> Permission {
        Permission::new(
            "cns".to_string(),
            vec![
                "register_name".to_string(),
                "update_record".to_string(),
                "transfer_name".to_string(),
            ],
        )
    }

    /// GID (Ghostchain Identity) permissions
    pub fn gid_read() -> Permission {
        Permission::new(
            "gid".to_string(),
            vec![
                "get_identity".to_string(),
                "verify_credential".to_string(),
                "list_credentials".to_string(),
            ],
        )
    }

    pub fn gid_write() -> Permission {
        Permission::new(
            "gid".to_string(),
            vec![
                "create_identity".to_string(),
                "issue_credential".to_string(),
                "revoke_credential".to_string(),
                "update_identity".to_string(),
            ],
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(feature = "alloc")]
    #[test]
    fn test_permission_creation() {
        let permission = Permission::new(
            "ghostd".to_string(),
            vec!["read".to_string(), "write".to_string()],
        );

        assert_eq!(permission.service, "ghostd");
        assert!(permission.allows_operation("read"));
        assert!(permission.allows_operation("write"));
        assert!(!permission.allows_operation("admin"));
    }

    #[cfg(feature = "alloc")]
    #[test]
    fn test_permission_operations() {
        let mut permission = Permission::new("test".to_string(), vec!["read".to_string()]);

        permission.add_operation("write".to_string());
        assert!(permission.allows_operation("write"));

        permission.remove_operation("read");
        assert!(!permission.allows_operation("read"));
    }

    #[test]
    fn test_time_constraints() {
        let constraints = TimeConstraints::new()
            .with_validity_period(1000, 2000);

        assert!(constraints.is_satisfied(1500));
        assert!(!constraints.is_satisfied(500));
        assert!(!constraints.is_satisfied(2500));
    }

    #[cfg(feature = "alloc")]
    #[test]
    fn test_resource_constraints() {
        let constraints = ResourceConstraints::new()
            .allow_path("/api/v1/".to_string())
            .deny_path("/api/v1/admin/".to_string());

        assert!(constraints.is_satisfied("/api/v1/users"));
        assert!(!constraints.is_satisfied("/api/v1/admin/config"));
        assert!(!constraints.is_satisfied("/api/v2/users"));
    }

    #[test]
    fn test_rate_constraints() {
        let constraints = RateConstraints::new(100, 60); // 100 requests per minute

        assert!(constraints.is_satisfied(50, 60));
        assert!(!constraints.is_satisfied(150, 60));
        assert!(constraints.is_satisfied(150, 120)); // Scaled for longer window
    }

    #[cfg(feature = "alloc")]
    #[test]
    fn test_ghostchain_permissions() {
        let read_perm = GhostchainPermissions::ghostd_read();
        assert!(read_perm.allows_operation("get_block"));
        assert!(!read_perm.allows_operation("submit_transaction"));

        let admin_perm = GhostchainPermissions::ghostd_admin();
        assert!(admin_perm.allows_operation("get_block"));
        assert!(admin_perm.allows_operation("submit_transaction"));
        assert!(admin_perm.allows_operation("configure_node"));
    }
}