use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use serde::Deserialize;

/// Errors that can occur when loading a CLI mapping file.
#[derive(Debug, thiserror::Error)]
pub enum MappingError {
    /// Failed to read the mapping file from disk.
    #[error("failed to read mapping file {path}: {source}")]
    ReadFile {
        /// Path that could not be read.
        path: PathBuf,
        /// Underlying I/O error.
        source: std::io::Error,
    },
    /// Failed to parse the mapping YAML.
    #[error("failed to parse mapping from {path}: {source}")]
    Parse {
        /// Path whose content failed to parse.
        path: PathBuf,
        /// Underlying YAML parse error.
        source: serde_yaml_ng::Error,
    },
}

/// CLI mapping spec — maps API operations to CLI command patterns.
/// For providers where CLI syntax doesn't match operation names directly.
#[derive(Debug, Deserialize)]
pub struct CliMapping {
    /// Cloud provider name (e.g. `aws`, `gcp`).
    pub provider: String,
    /// CLI binary prefix (e.g. `aws`, `gcloud`).
    pub prefix: String,
    /// Per-service operation mappings.
    #[serde(default)]
    pub services: BTreeMap<String, ServiceMapping>,
}

/// Mapping of operations within a single service.
#[derive(Debug, Deserialize)]
pub struct ServiceMapping {
    /// Individual operation → CLI command mappings.
    #[serde(default)]
    pub operations: BTreeMap<String, OperationMapping>,
}

/// A single operation's CLI command mapping.
#[derive(Debug, Deserialize)]
pub struct OperationMapping {
    /// Primary CLI command string (e.g. `ec2 terminate-instances`).
    pub cli: String,
    /// Alternative CLI command form, if any.
    #[serde(default)]
    pub cli_alt: Option<String>,
}

/// Load a CLI mapping file.
///
/// # Errors
///
/// Returns [`MappingError::ReadFile`] if the file cannot be read,
/// or [`MappingError::Parse`] if the YAML content is invalid.
pub fn load_mapping(path: &Path) -> Result<CliMapping, MappingError> {
    let content = std::fs::read_to_string(path).map_err(|e| MappingError::ReadFile {
        path: path.to_path_buf(),
        source: e,
    })?;
    serde_yaml_ng::from_str(&content).map_err(|e| MappingError::Parse {
        path: path.to_path_buf(),
        source: e,
    })
}

/// Convert a `camelCase`/`PascalCase` operation ID to kebab-case CLI pattern.
/// e.g. `deleteItem` → `delete-item`, `DeleteAuthMethod` → `delete-auth-method`
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
        for svc in m.services.values() {
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
        let mapping: CliMapping = serde_yaml_ng::from_str(yaml).unwrap();
        let pattern = build_pattern("aws", "TerminateInstances", Some(&mapping));
        assert!(pattern.contains("ec2 terminate\\-instances"));
    }
}
