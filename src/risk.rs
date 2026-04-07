use crate::spec::ResolvedOperation;

/// Risk severity for guardrail rules.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Severity {
    /// High-risk: the command should be blocked by default.
    Block,
    /// Medium-risk: the command should trigger a warning.
    Warn,
}

impl Severity {
    /// Returns the severity as a lowercase string slice.
    #[must_use]
    pub fn as_str(&self) -> &str {
        match self {
            Self::Block => "block",
            Self::Warn => "warn",
        }
    }
}

impl std::fmt::Display for Severity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// High-risk resource patterns — operations on these always block.
const HIGH_RISK: &[&str] = &[
    "database", "db", "instance", "cluster", "volume", "bucket",
    "secret", "key", "vault", "certificate", "credential",
    "namespace", "project", "account", "stack", "zone",
    "item", "role", "auth", "target", "gateway", "producer",
    "migration", "group", "policy", "server",
];

/// Low-risk resource patterns — operations on these only warn.
const LOW_RISK: &[&str] = &[
    "tag", "label", "metric", "alarm", "event", "log",
    "notification", "subscription", "topic", "queue",
    "rule", "permission", "attachment", "association",
];

/// Classify an operation's risk severity based on resource type.
///
/// DELETE on high-risk resources → Block, DELETE on low-risk → Warn,
/// DELETE on unknown → Block (safer default).
/// Non-DELETE destructive verbs on high-risk → Block, otherwise Warn.
#[must_use]
pub fn classify(op: &ResolvedOperation) -> Severity {
    let id_lower = op.operation_id.to_lowercase();
    let path_lower = op.path.to_lowercase();
    let combined = format!("{id_lower} {path_lower}");

    let matches_high = || HIGH_RISK.iter().any(|p| combined.contains(p));
    let matches_low = || LOW_RISK.iter().any(|p| combined.contains(p));

    if op.method == "DELETE" {
        if matches_high() {
            return Severity::Block;
        }
        if matches_low() {
            return Severity::Warn;
        }
        return Severity::Block;
    }

    if matches_high() {
        Severity::Block
    } else {
        Severity::Warn
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::spec::ResolvedOperation;

    fn op(method: &str, id: &str, path: &str) -> ResolvedOperation {
        ResolvedOperation {
            method: method.into(),
            path: path.into(),
            operation_id: id.into(),
            summary: String::new(),
            tags: vec![],
        }
    }

    #[test] fn delete_database_blocks() { assert_eq!(classify(&op("DELETE", "deleteDatabase", "/databases/{id}")), Severity::Block); }
    #[test] fn delete_instance_blocks() { assert_eq!(classify(&op("DELETE", "deleteInstance", "/instances/{id}")), Severity::Block); }
    #[test] fn delete_tag_warns() { assert_eq!(classify(&op("DELETE", "deleteTag", "/tags/{id}")), Severity::Warn); }
    #[test] fn post_delete_item_blocks() { assert_eq!(classify(&op("POST", "deleteItem", "/delete-item")), Severity::Block); }
    #[test] fn post_delete_role_blocks() { assert_eq!(classify(&op("POST", "deleteRole", "/delete-role")), Severity::Block); }
    #[test] fn delete_unknown_blocks() { assert_eq!(classify(&op("DELETE", "deleteFoo", "/foos/{id}")), Severity::Block); }
    #[test] fn post_revoke_credential_blocks() { assert_eq!(classify(&op("POST", "revokeCredential", "/revoke")), Severity::Block); }
}
