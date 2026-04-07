use serde::{Deserialize, Serialize};

use crate::filter;
use crate::mapping::{self, CliMapping};
use crate::risk;
use crate::spec::ResolvedOperation;

/// Errors that can occur during YAML serialization of rules.
#[derive(Debug, thiserror::Error)]
#[error("failed to serialize rules to YAML: {source}")]
pub struct SerializeError {
    #[from]
    source: serde_yaml_ng::Error,
}

/// A generated guardrail rule (matches guardrail's Rule format).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Rule {
    /// Unique rule name (e.g. `aws-terminate-instances`).
    pub name: String,
    /// Regex pattern to match CLI commands.
    pub pattern: String,
    /// Risk severity: `block` or `warn`.
    pub severity: String,
    /// Human-readable description of the operation.
    pub message: String,
    /// Rule category (e.g. `cloud`, `akeyless`).
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
    provider: impl AsRef<str>,
    cli_prefix: impl AsRef<str>,
    category: impl AsRef<str>,
    mapping: Option<&CliMapping>,
) -> Vec<Rule> {
    let provider = provider.as_ref();
    let cli_prefix = cli_prefix.as_ref();
    let category = category.as_ref();
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

            let cli_op = mapping
                .and_then(|m| {
                    m.services.values()
                        .find_map(|s| s.operations.get(&op.operation_id))
                        .map(|o| o.cli.clone())
                })
                .unwrap_or_else(|| kebab.clone());

            Rule {
                name,
                pattern,
                severity: severity.to_string(),
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
/// Returns [`SerializeError`] if serialization fails.
pub fn to_yaml(rules: &[Rule]) -> Result<String, SerializeError> {
    Ok(serde_yaml_ng::to_string(rules)?)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mapping::CliMapping;
    use crate::spec::ResolvedOperation;
    use pretty_assertions::assert_eq;

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
        assert_eq!(delete_item.severity, "block");
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

    // ── New tests ───────────────────────────────────────────────

    #[test]
    fn empty_input_produces_no_rules() {
        let rules = generate_rules(&[], "test", "test-cli", "test", None);
        assert!(rules.is_empty());
    }

    #[test]
    fn all_safe_ops_produce_no_rules() {
        let safe_ops = vec![
            ResolvedOperation {
                method: "GET".into(),
                path: "/items".into(),
                operation_id: "listItems".into(),
                summary: "List items".into(),
                tags: vec![],
            },
            ResolvedOperation {
                method: "POST".into(),
                path: "/items".into(),
                operation_id: "createItem".into(),
                summary: "Create item".into(),
                tags: vec![],
            },
        ];
        let rules = generate_rules(&safe_ops, "test", "test-cli", "test", None);
        assert!(rules.is_empty());
    }

    #[test]
    fn rule_name_uses_provider_prefix() {
        let ops = vec![ResolvedOperation {
            method: "DELETE".into(),
            path: "/buckets/{id}".into(),
            operation_id: "deleteBucket".into(),
            summary: "Delete bucket".into(),
            tags: vec![],
        }];
        let rules = generate_rules(&ops, "aws", "aws", "cloud", None);
        assert_eq!(rules[0].name, "aws-delete-bucket");
    }

    #[test]
    fn rule_category_set_correctly() {
        let ops = vec![ResolvedOperation {
            method: "DELETE".into(),
            path: "/items/{id}".into(),
            operation_id: "deleteItem".into(),
            summary: "Delete item".into(),
            tags: vec![],
        }];
        let rules = generate_rules(&ops, "test", "test-cli", "my-category", None);
        assert_eq!(rules[0].category, "my-category");
    }

    #[test]
    fn rule_pattern_is_valid_regex() {
        let rules = generate_rules(&ops(), "test", "test-cli", "test", None);
        for rule in &rules {
            regex::Regex::new(&rule.pattern).unwrap();
        }
    }

    #[test]
    fn test_block_matches_pattern() {
        let rules = generate_rules(&ops(), "test", "test-cli", "test", None);
        for rule in &rules {
            let re = regex::Regex::new(&rule.pattern).unwrap();
            assert!(
                re.is_match(&rule.test_block),
                "test_block '{}' should match pattern '{}'",
                rule.test_block,
                rule.pattern
            );
        }
    }

    #[test]
    fn test_allow_does_not_match_pattern() {
        let rules = generate_rules(&ops(), "test", "test-cli", "test", None);
        for rule in &rules {
            let re = regex::Regex::new(&rule.pattern).unwrap();
            assert!(
                !re.is_match(&rule.test_allow),
                "test_allow '{}' should NOT match pattern '{}'",
                rule.test_allow,
                rule.pattern
            );
        }
    }

    #[test]
    fn missing_summary_uses_operation_id_in_message() {
        let ops = vec![ResolvedOperation {
            method: "DELETE".into(),
            path: "/things/{id}".into(),
            operation_id: "deleteThing".into(),
            summary: String::new(),
            tags: vec![],
        }];
        let rules = generate_rules(&ops, "test", "test-cli", "test", None);
        assert!(rules[0].message.contains("deleteThing"));
        assert!(rules[0].message.contains("destructive operation"));
    }

    #[test]
    fn with_mapping_uses_mapped_cli() {
        let mapping_yaml = r#"
provider: aws
prefix: aws
services:
  ec2:
    operations:
      terminateInstances:
        cli: "ec2 terminate-instances"
"#;
        let mapping: CliMapping = serde_yaml_ng::from_str(mapping_yaml).unwrap();
        let ops = vec![ResolvedOperation {
            method: "POST".into(),
            path: "/terminate".into(),
            operation_id: "terminateInstances".into(),
            summary: "Terminate EC2 instances".into(),
            tags: vec![],
        }];
        let rules = generate_rules(&ops, "aws", "aws", "cloud", Some(&mapping));
        assert_eq!(rules.len(), 1);
        assert!(rules[0].test_block.contains("ec2 terminate-instances"));
    }

    #[test]
    fn with_mapping_unmapped_op_falls_back() {
        let mapping_yaml = r#"
provider: aws
prefix: aws
services:
  ec2:
    operations:
      TerminateInstances:
        cli: "ec2 terminate-instances"
"#;
        let mapping: CliMapping = serde_yaml_ng::from_str(mapping_yaml).unwrap();
        let ops = vec![ResolvedOperation {
            method: "DELETE".into(),
            path: "/buckets/{id}".into(),
            operation_id: "deleteBucket".into(),
            summary: "Delete bucket".into(),
            tags: vec![],
        }];
        let rules = generate_rules(&ops, "aws", "aws", "cloud", Some(&mapping));
        assert!(rules[0].test_block.contains("delete-bucket"));
    }

    #[test]
    fn to_yaml_empty_rules() {
        let yaml = to_yaml(&[]).unwrap();
        assert_eq!(yaml.trim(), "[]");
    }

    #[test]
    fn to_yaml_roundtrip_preserves_fields() {
        let rules = generate_rules(&ops(), "test", "test-cli", "test", None);
        let yaml = to_yaml(&rules).unwrap();

        assert!(yaml.contains("name:"));
        assert!(yaml.contains("pattern:"));
        assert!(yaml.contains("severity:"));
        assert!(yaml.contains("message:"));
        assert!(yaml.contains("category:"));
        assert!(yaml.contains("test_block:"));
        assert!(yaml.contains("test_allow:"));
    }

    #[test]
    fn to_yaml_contains_all_rule_names() {
        let rules = generate_rules(&ops(), "test", "test-cli", "test", None);
        let yaml = to_yaml(&rules).unwrap();
        for rule in &rules {
            assert!(yaml.contains(&rule.name));
        }
    }

    #[test]
    fn serialize_error_display() {
        use serde::ser::Error as _;
        let err = SerializeError {
            source: serde_yaml_ng::Error::custom("test error"),
        };
        let msg = err.to_string();
        assert!(msg.contains("failed to serialize rules to YAML"));
    }

    #[test]
    fn rule_yaml_deserialize_round_trip() {
        let rules = generate_rules(&ops(), "test", "test-cli", "test", None);
        let yaml = to_yaml(&rules).unwrap();
        let back: Vec<Rule> = serde_yaml_ng::from_str(&yaml).unwrap();
        assert_eq!(rules, back);
    }
}
