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

    // ── Existing: DELETE on high-risk ─────────────────────────────

    #[test] fn delete_database_blocks() { assert_eq!(classify(&op("DELETE", "deleteDatabase", "/databases/{id}")), Severity::Block); }
    #[test] fn delete_instance_blocks() { assert_eq!(classify(&op("DELETE", "deleteInstance", "/instances/{id}")), Severity::Block); }

    // ── Existing: DELETE on low-risk ────────────────────────────

    #[test] fn delete_tag_warns() { assert_eq!(classify(&op("DELETE", "deleteTag", "/tags/{id}")), Severity::Warn); }

    // ── Existing: POST (non-DELETE) on high-risk ────────────────

    #[test] fn post_delete_item_blocks() { assert_eq!(classify(&op("POST", "deleteItem", "/delete-item")), Severity::Block); }
    #[test] fn post_delete_role_blocks() { assert_eq!(classify(&op("POST", "deleteRole", "/delete-role")), Severity::Block); }
    #[test] fn post_revoke_credential_blocks() { assert_eq!(classify(&op("POST", "revokeCredential", "/revoke")), Severity::Block); }

    // ── Existing: DELETE on unknown resource defaults to block ───

    #[test] fn delete_unknown_blocks() { assert_eq!(classify(&op("DELETE", "deleteFoo", "/foos/{id}")), Severity::Block); }

    // ── New: DELETE on various high-risk resources ──────────────

    #[test] fn delete_cluster_blocks() { assert_eq!(classify(&op("DELETE", "deleteCluster", "/clusters/{id}")), Severity::Block); }
    #[test] fn delete_volume_blocks() { assert_eq!(classify(&op("DELETE", "deleteVolume", "/volumes/{id}")), Severity::Block); }
    #[test] fn delete_bucket_blocks() { assert_eq!(classify(&op("DELETE", "deleteBucket", "/buckets/{id}")), Severity::Block); }
    #[test] fn delete_secret_blocks() { assert_eq!(classify(&op("DELETE", "deleteSecret", "/secrets/{id}")), Severity::Block); }
    #[test] fn delete_vault_blocks() { assert_eq!(classify(&op("DELETE", "deleteVault", "/vaults/{id}")), Severity::Block); }
    #[test] fn delete_namespace_blocks() { assert_eq!(classify(&op("DELETE", "deleteNamespace", "/ns/{id}")), Severity::Block); }
    #[test] fn delete_account_blocks() { assert_eq!(classify(&op("DELETE", "deleteAccount", "/accounts/{id}")), Severity::Block); }

    // ── New: DELETE on various low-risk resources ───────────────

    #[test] fn delete_label_warns() { assert_eq!(classify(&op("DELETE", "deleteLabel", "/labels/{id}")), Severity::Warn); }
    #[test] fn delete_metric_warns() { assert_eq!(classify(&op("DELETE", "deleteMetric", "/metrics/{id}")), Severity::Warn); }
    #[test] fn delete_alarm_warns() { assert_eq!(classify(&op("DELETE", "deleteAlarm", "/alarms/{id}")), Severity::Warn); }
    #[test] fn delete_subscription_warns() { assert_eq!(classify(&op("DELETE", "deleteSubscription", "/subs/{id}")), Severity::Warn); }
    #[test] fn delete_topic_warns() { assert_eq!(classify(&op("DELETE", "deleteTopic", "/topics/{id}")), Severity::Warn); }
    #[test] fn delete_queue_warns() { assert_eq!(classify(&op("DELETE", "deleteQueue", "/queues/{id}")), Severity::Warn); }

    // ── New: non-DELETE destructive on low-risk resource warns ──

    #[test] fn post_revoke_label_warns() { assert_eq!(classify(&op("POST", "revokeLabel", "/labels")), Severity::Warn); }
    #[test] fn post_disable_alarm_warns() { assert_eq!(classify(&op("POST", "disableAlarm", "/alarms")), Severity::Warn); }

    // ── New: non-DELETE destructive on high-risk resource blocks ─

    #[test] fn post_terminate_instance_blocks() { assert_eq!(classify(&op("POST", "terminateInstance", "/instances")), Severity::Block); }
    #[test] fn post_destroy_cluster_blocks() { assert_eq!(classify(&op("POST", "destroyCluster", "/clusters")), Severity::Block); }
    #[test] fn post_purge_vault_blocks() { assert_eq!(classify(&op("POST", "purgeVault", "/vaults")), Severity::Block); }

    // ── New: path-based classification ──────────────────────────

    #[test]
    fn high_risk_detected_from_path_only() {
        assert_eq!(classify(&op("POST", "removeXyz", "/databases/xyz")), Severity::Block);
    }

    #[test]
    fn low_risk_detected_from_path_only() {
        assert_eq!(classify(&op("DELETE", "deleteFoo", "/notifications/{id}")), Severity::Warn);
    }

    // ── Severity Display / as_str ───────────────────────────────

    #[test]
    fn severity_display_block() {
        assert_eq!(format!("{}", Severity::Block), "block");
    }

    #[test]
    fn severity_display_warn() {
        assert_eq!(format!("{}", Severity::Warn), "warn");
    }

    #[test]
    fn severity_as_str_block() {
        assert_eq!(Severity::Block.as_str(), "block");
    }

    #[test]
    fn severity_as_str_warn() {
        assert_eq!(Severity::Warn.as_str(), "warn");
    }

    #[test]
    fn severity_clone_and_copy() {
        let s = Severity::Block;
        let s2 = s;
        #[allow(clippy::clone_on_copy)]
        let s3 = s.clone();
        assert_eq!(s, s2);
        assert_eq!(s, s3);
    }

    #[test]
    fn severity_debug_format() {
        assert_eq!(format!("{:?}", Severity::Block), "Block");
        assert_eq!(format!("{:?}", Severity::Warn), "Warn");
    }
}
