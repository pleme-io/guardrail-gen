use std::collections::BTreeMap;
use std::path::Path;

use serde::Deserialize;

/// CLI mapping spec — maps API operations to CLI command patterns.
/// For providers where CLI syntax doesn't match operation names directly.
#[derive(Debug, Deserialize)]
pub struct CliMapping {
    pub provider: String,
    pub prefix: String,
    #[serde(default)]
    pub services: BTreeMap<String, ServiceMapping>,
}

#[derive(Debug, Deserialize)]
pub struct ServiceMapping {
    #[serde(default)]
    pub operations: BTreeMap<String, OperationMapping>,
}

#[derive(Debug, Deserialize)]
pub struct OperationMapping {
    pub cli: String,
    #[serde(default)]
    pub cli_alt: Option<String>,
}

/// Load a CLI mapping file.
///
/// # Errors
///
/// Returns an error if the file can't be read or parsed.
pub fn load_mapping(path: &Path) -> anyhow::Result<CliMapping> {
    let content = std::fs::read_to_string(path)?;
    Ok(serde_yaml::from_str(&content)?)
}

/// Convert a camelCase/PascalCase operation ID to kebab-case CLI pattern.
/// e.g. "deleteItem" → "delete-item", "DeleteAuthMethod" → "delete-auth-method"
#[must_use]
pub fn to_kebab_case(s: &str) -> String {
    let mut result = String::with_capacity(s.len() + 4);
    for (i, ch) in s.chars().enumerate() {
        if ch.is_uppercase() && i > 0 {
            result.push('-');
        }
        result.push(ch.to_lowercase().next().unwrap_or(ch));
    }
    result
}

/// Build a CLI regex pattern for a given provider + operation.
///
/// If a CLI mapping is available, uses the exact mapping.
/// Otherwise, derives from operationId via kebab-case conversion.
#[must_use]
pub fn build_pattern(
    provider_prefix: &str,
    operation_id: &str,
    mapping: Option<&CliMapping>,
) -> String {
    // Check mapping first
    if let Some(m) = mapping {
        for (_service, svc) in &m.services {
            if let Some(op) = svc.operations.get(operation_id) {
                let escaped = regex::escape(&op.cli);
                return format!("(?i){}\\s+{}", regex::escape(&m.prefix), escaped);
            }
        }
    }

    // Default: kebab-case conversion
    let kebab = to_kebab_case(operation_id);
    format!("(?i){}\\s+{}\\b", regex::escape(provider_prefix), regex::escape(&kebab))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn kebab_camel_case() {
        assert_eq!(to_kebab_case("deleteItem"), "delete-item");
    }

    #[test]
    fn kebab_pascal_case() {
        assert_eq!(to_kebab_case("DeleteAuthMethod"), "delete-auth-method");
    }

    #[test]
    fn kebab_already_lower() {
        assert_eq!(to_kebab_case("list"), "list");
    }

    #[test]
    fn kebab_acronym() {
        assert_eq!(to_kebab_case("deleteGWCluster"), "delete-g-w-cluster");
    }

    #[test]
    fn pattern_without_mapping() {
        let pattern = build_pattern("akeyless", "deleteItem", None);
        assert_eq!(pattern, r"(?i)akeyless\s+delete\-item\b");
    }

    #[test]
    fn pattern_with_mapping() {
        let yaml = r#"
provider: aws
prefix: aws
services:
  ec2:
    operations:
      TerminateInstances:
        cli: "ec2 terminate-instances"
"#;
        let mapping: CliMapping = serde_yaml::from_str(yaml).unwrap();
        let pattern = build_pattern("aws", "TerminateInstances", Some(&mapping));
        assert!(pattern.contains("ec2 terminate\\-instances"));
    }
}
