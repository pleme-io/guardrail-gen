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
///
/// DELETE HTTP method is always destructive. For other methods, checks the
/// operation ID against known destructive verb patterns (after excluding
/// operations that start with safe verb prefixes).
#[must_use]
pub fn is_destructive(op: &ResolvedOperation) -> bool {
    if op.method == "DELETE" {
        return true;
    }

    let id_lower = op.operation_id.to_lowercase();

    if SAFE_VERBS.iter().any(|safe| id_lower.starts_with(safe)) {
        return false;
    }

    DESTRUCTIVE_VERBS
        .iter()
        .any(|verb| id_lower.contains(verb))
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

    // ── Additional destructive verbs ────────────────────────────

    #[test] fn post_uninstall() { assert!(is_destructive(&op("POST", "uninstallAgent"))); }
    #[test] fn post_detach() { assert!(is_destructive(&op("POST", "detachVolume"))); }
    #[test] fn post_disassociate() { assert!(is_destructive(&op("POST", "disassociateAddress"))); }
    #[test] fn post_release() { assert!(is_destructive(&op("POST", "releaseAddress"))); }
    #[test] fn post_abandon() { assert!(is_destructive(&op("POST", "abandonLifecycleAction"))); }

    // ── Additional safe operations ──────────────────────────────

    #[test] fn get_fetch_item() { assert!(!is_destructive(&op("GET", "fetchItem"))); }
    #[test] fn get_search_items() { assert!(!is_destructive(&op("GET", "searchItems"))); }
    #[test] fn get_query_logs() { assert!(!is_destructive(&op("GET", "queryLogs"))); }
    #[test] fn post_validate() { assert!(!is_destructive(&op("POST", "validateConfig"))); }
    #[test] fn post_enable_user() { assert!(!is_destructive(&op("POST", "enableUser"))); }
    #[test] fn post_register() { assert!(!is_destructive(&op("POST", "registerTarget"))); }
    #[test] fn post_associate() { assert!(!is_destructive(&op("POST", "associateAddress"))); }
    #[test] fn post_attach() { assert!(!is_destructive(&op("POST", "attachVolume"))); }
    #[test] fn post_tag() { assert!(!is_destructive(&op("POST", "tagResource"))); }
    #[test] fn post_start() { assert!(!is_destructive(&op("POST", "startInstance"))); }

    // ── Edge cases ───────────────────────────────────────────────

    #[test] fn camel_case_delete() { assert!(is_destructive(&op("POST", "DeleteItem"))); }
    #[test] fn snake_case_delete() { assert!(is_destructive(&op("POST", "delete_item"))); }
    #[test] fn mixed_case() { assert!(is_destructive(&op("POST", "DELETEITEM"))); }

    #[test]
    fn unknown_verb_is_not_destructive() {
        assert!(!is_destructive(&op("POST", "doSomething")));
    }

    #[test]
    fn empty_operation_id_not_destructive() {
        assert!(!is_destructive(&op("POST", "")));
    }

    #[test]
    fn delete_method_any_operation_id() {
        assert!(is_destructive(&op("DELETE", "")));
        assert!(is_destructive(&op("DELETE", "listItems")));
        assert!(is_destructive(&op("DELETE", "createFoo")));
    }

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

    #[test]
    fn filter_empty_input() {
        let ops: Vec<ResolvedOperation> = vec![];
        let filtered = filter_destructive(&ops);
        assert!(filtered.is_empty());
    }

    #[test]
    fn filter_all_destructive() {
        let ops = vec![
            op("DELETE", "deleteA"),
            op("POST", "destroyB"),
            op("POST", "terminateC"),
        ];
        let filtered = filter_destructive(&ops);
        assert_eq!(filtered.len(), 3);
    }

    #[test]
    fn filter_all_safe() {
        let ops = vec![
            op("GET", "listItems"),
            op("POST", "createItem"),
            op("PUT", "updateItem"),
        ];
        let filtered = filter_destructive(&ops);
        assert!(filtered.is_empty());
    }
}
