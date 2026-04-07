use serde::Serialize;

use crate::filter;
use crate::mapping::{self, CliMapping};
use crate::risk;
use crate::spec::ResolvedOperation;

/// A generated guardrail rule (matches guardrail's Rule format).
#[derive(Debug, Serialize)]
pub struct Rule {
    pub name: String,
    pub pattern: String,
    pub severity: String,
    pub message: String,
    pub category: String,
    /// Command that MUST match this rule (for testing).
    pub test_block: String,
    /// Command that must NOT match this rule (for testing).
    pub test_allow: String,
}

/// Generate guardrail rules from a list of operations.
///
/// Filters to destructive operations, classifies risk, generates regex patterns.
#[must_use]
pub fn generate_rules(
    ops: &[ResolvedOperation],
    provider: &str,
    cli_prefix: &str,
    category: &str,
    mapping: Option<&CliMapping>,
) -> Vec<Rule> {
    let destructive = filter::filter_destructive(ops);

    destructive
        .into_iter()
        .map(|op| {
            let severity = risk::classify(op);
            let pattern = mapping::build_pattern(cli_prefix, &op.operation_id, mapping);
            let kebab = mapping::to_kebab_case(&op.operation_id);
            let name = format!("{provider}-{kebab}");
            let message = if op.summary.is_empty() {
                format!("{} — destructive operation", op.operation_id)
            } else {
                op.summary.clone()
            };

            // Derive the CLI command from the mapping or kebab-case operation
            let cli_op = if let Some(m) = mapping {
                m.services.values()
                    .filter_map(|s| s.operations.get(&op.operation_id))
                    .map(|o| o.cli.clone())
                    .next()
                    .unwrap_or(kebab.clone())
            } else {
                kebab.clone()
            };

            Rule {
                name,
                pattern,
                severity: severity.as_str().to_owned(),
                message,
                category: category.to_owned(),
                test_block: format!("{cli_prefix} {cli_op} --id test-123"),
                test_allow: format!("{cli_prefix} list-resources --output json"),
            }
        })
        .collect()
}

/// Serialize rules to YAML string.
///
/// # Errors
///
/// Returns an error if serialization fails.
pub fn to_yaml(rules: &[Rule]) -> anyhow::Result<String> {
    Ok(serde_yaml_ng::to_string(rules)?)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::spec::ResolvedOperation;

    fn ops() -> Vec<ResolvedOperation> {
        vec![
            ResolvedOperation {
                method: "POST".into(),
                path: "/delete-item".into(),
                operation_id: "deleteItem".into(),
                summary: "Delete a secret item".into(),
                tags: vec![],
            },
            ResolvedOperation {
                method: "GET".into(),
                path: "/list-items".into(),
                operation_id: "listItems".into(),
                summary: "List all items".into(),
                tags: vec![],
            },
            ResolvedOperation {
                method: "POST".into(),
                path: "/create-item".into(),
                operation_id: "createItem".into(),
                summary: "Create item".into(),
                tags: vec![],
            },
            ResolvedOperation {
                method: "DELETE".into(),
                path: "/users/{id}".into(),
                operation_id: "removeUser".into(),
                summary: "Remove a user account".into(),
                tags: vec![],
            },
        ]
    }

    #[test]
    fn generates_only_destructive() {
        let rules = generate_rules(&ops(), "test", "test-cli", "test", None);
        assert_eq!(rules.len(), 2);
        assert!(rules.iter().any(|r| r.name == "test-delete-item"));
        assert!(rules.iter().any(|r| r.name == "test-remove-user"));
    }

    #[test]
    fn excludes_safe_operations() {
        let rules = generate_rules(&ops(), "test", "test-cli", "test", None);
        assert!(!rules.iter().any(|r| r.name.contains("list")));
        assert!(!rules.iter().any(|r| r.name.contains("create")));
    }

    #[test]
    fn assigns_severity() {
        let rules = generate_rules(&ops(), "test", "test-cli", "test", None);
        let delete_item = rules.iter().find(|r| r.name == "test-delete-item").unwrap();
        assert_eq!(delete_item.severity, "block"); // item = high risk
    }

    #[test]
    fn generates_valid_yaml() {
        let rules = generate_rules(&ops(), "test", "test-cli", "test", None);
        let yaml = to_yaml(&rules).unwrap();
        assert!(yaml.contains("test-delete-item"));
        assert!(yaml.contains("block"));
    }

    #[test]
    fn uses_summary_as_message() {
        let rules = generate_rules(&ops(), "test", "test-cli", "test", None);
        let delete_item = rules.iter().find(|r| r.name == "test-delete-item").unwrap();
        assert_eq!(delete_item.message, "Delete a secret item");
    }
}
