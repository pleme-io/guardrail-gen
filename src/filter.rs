use crate::spec::ResolvedOperation;

/// Destructive verb patterns — matched case-insensitively against operation IDs.
const DESTRUCTIVE_VERBS: &[&str] = &[
    "delete", "destroy", "terminate", "remove", "purge",
    "revoke", "drop", "truncate", "flush", "reset",
    "disable", "deregister", "cancel", "uninstall",
    "detach", "disassociate", "release", "abandon",
];

/// Non-destructive verbs — explicitly excluded even if they contain a substring
/// of a destructive verb (e.g. "describe" contains "de").
const SAFE_VERBS: &[&str] = &[
    "create", "get", "list", "describe", "update", "put",
    "read", "fetch", "search", "query", "check", "verify",
    "validate", "test", "ping", "health", "status",
    "enable", "register", "associate", "attach",
    "tag", "untag", "start", "begin",
];

/// Check if an operation is destructive based on HTTP method + operation name.
#[must_use]
pub fn is_destructive(op: &ResolvedOperation) -> bool {
    // DELETE HTTP method is always destructive
    if op.method == "DELETE" {
        return true;
    }

    let id_lower = op.operation_id.to_lowercase();

    // Check safe verbs first — if the operation starts with a safe verb, skip it
    for safe in SAFE_VERBS {
        if id_lower.starts_with(safe) {
            return false;
        }
    }

    // Check destructive verbs
    for verb in DESTRUCTIVE_VERBS {
        if id_lower.contains(verb) {
            return true;
        }
    }

    false
}

/// Filter a list of operations to only destructive ones.
#[must_use]
pub fn filter_destructive(ops: &[ResolvedOperation]) -> Vec<&ResolvedOperation> {
    ops.iter().filter(|op| is_destructive(op)).collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::spec::ResolvedOperation;

    fn op(method: &str, id: &str) -> ResolvedOperation {
        ResolvedOperation {
            method: method.into(),
            path: "/test".into(),
            operation_id: id.into(),
            summary: String::new(),
            tags: vec![],
        }
    }

    // ── DELETE method ────────────────────────────────────────────

    #[test] fn delete_method_always_destructive() { assert!(is_destructive(&op("DELETE", "anything"))); }
    #[test] fn get_method_safe() { assert!(!is_destructive(&op("GET", "listItems"))); }

    // ── Destructive verbs ────────────────────────────────────────

    #[test] fn post_delete_item() { assert!(is_destructive(&op("POST", "deleteItem"))); }
    #[test] fn post_destroy_cluster() { assert!(is_destructive(&op("POST", "destroyCluster"))); }
    #[test] fn post_terminate_instances() { assert!(is_destructive(&op("POST", "terminateInstances"))); }
    #[test] fn post_remove_role() { assert!(is_destructive(&op("POST", "removeRole"))); }
    #[test] fn post_purge_queue() { assert!(is_destructive(&op("POST", "purgeQueue"))); }
    #[test] fn post_revoke_creds() { assert!(is_destructive(&op("POST", "revokeCreds"))); }
    #[test] fn post_drop_table() { assert!(is_destructive(&op("POST", "dropTable"))); }
    #[test] fn post_truncate_table() { assert!(is_destructive(&op("POST", "truncateTable"))); }
    #[test] fn post_flush_all() { assert!(is_destructive(&op("POST", "flushAll"))); }
    #[test] fn post_reset_key() { assert!(is_destructive(&op("POST", "resetAccessKey"))); }
    #[test] fn post_disable_user() { assert!(is_destructive(&op("POST", "disableUser"))); }
    #[test] fn post_deregister() { assert!(is_destructive(&op("POST", "deregisterTarget"))); }
    #[test] fn post_cancel_job() { assert!(is_destructive(&op("POST", "cancelJob"))); }

    // ── Safe operations ──────────────────────────────────────────

    #[test] fn post_create_item() { assert!(!is_destructive(&op("POST", "createItem"))); }
    #[test] fn get_list_items() { assert!(!is_destructive(&op("GET", "listItems"))); }
    #[test] fn get_describe_instances() { assert!(!is_destructive(&op("GET", "describeInstances"))); }
    #[test] fn post_update_item() { assert!(!is_destructive(&op("POST", "updateItem"))); }
    #[test] fn put_update_role() { assert!(!is_destructive(&op("PUT", "updateRole"))); }

    // ── Edge cases ───────────────────────────────────────────────

    #[test] fn camel_case_delete() { assert!(is_destructive(&op("POST", "DeleteItem"))); }
    #[test] fn snake_case_delete() { assert!(is_destructive(&op("POST", "delete_item"))); }
    #[test] fn mixed_case() { assert!(is_destructive(&op("POST", "DELETEITEM"))); }

    // ── Filter ───────────────────────────────────────────────────

    #[test]
    fn filter_keeps_only_destructive() {
        let ops = vec![
            op("GET", "listItems"),
            op("POST", "deleteItem"),
            op("POST", "createItem"),
            op("DELETE", "removeUser"),
        ];
        let filtered = filter_destructive(&ops);
        assert_eq!(filtered.len(), 2);
        assert!(filtered.iter().any(|o| o.operation_id == "deleteItem"));
        assert!(filtered.iter().any(|o| o.operation_id == "removeUser"));
    }
}
