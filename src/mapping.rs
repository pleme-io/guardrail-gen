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
#[derive(Debug, Clone, Deserialize)]
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
#[derive(Debug, Clone, Deserialize)]
pub struct ServiceMapping {
    /// Individual operation → CLI command mappings.
    #[serde(default)]
    pub operations: BTreeMap<String, OperationMapping>,
}

/// A single operation's CLI command mapping.
#[derive(Debug, Clone, Deserialize)]
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
    use pretty_assertions::assert_eq;
    use std::io::Write;

    // ── to_kebab_case ───────────────────────────────────────────

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
    fn kebab_single_char() {
        assert_eq!(to_kebab_case("x"), "x");
    }

    #[test]
    fn kebab_empty_string() {
        assert_eq!(to_kebab_case(""), "");
    }

    #[test]
    fn kebab_all_uppercase() {
        assert_eq!(to_kebab_case("ABC"), "a-b-c");
    }

    #[test]
    fn kebab_trailing_uppercase() {
        assert_eq!(to_kebab_case("listA"), "list-a");
    }

    #[test]
    fn kebab_numbers_preserved() {
        assert_eq!(to_kebab_case("deleteV2Item"), "delete-v2-item");
    }

    // ── build_pattern ───────────────────────────────────────────

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

    #[test]
    fn pattern_mapping_miss_falls_back_to_kebab() {
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
        let pattern = build_pattern("aws", "DeleteBucket", Some(&mapping));
        assert_eq!(pattern, r"(?i)aws\s+delete\-bucket\b");
    }

    #[test]
    fn pattern_escapes_special_chars_in_prefix() {
        let pattern = build_pattern("my.cli", "deleteItem", None);
        assert!(pattern.contains(r"my\.cli"));
    }

    #[test]
    fn pattern_with_mapping_uses_mapping_prefix() {
        let yaml = r#"
provider: gcp
prefix: gcloud
services:
  compute:
    operations:
      deleteInstance:
        cli: "compute instances delete"
"#;
        let mapping: CliMapping = serde_yaml_ng::from_str(yaml).unwrap();
        let pattern = build_pattern("gcloud", "deleteInstance", Some(&mapping));
        assert!(pattern.starts_with("(?i)gcloud"));
        assert!(pattern.contains("compute instances delete"));
    }

    // ── load_mapping ────────────────────────────────────────────

    #[test]
    fn load_mapping_from_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("mapping.yaml");
        let mut f = std::fs::File::create(&path).unwrap();
        write!(
            f,
            r#"
provider: aws
prefix: aws
services:
  s3:
    operations:
      DeleteBucket:
        cli: "s3 rb"
        cli_alt: "s3api delete-bucket"
"#
        )
        .unwrap();

        let mapping = load_mapping(&path).unwrap();
        assert_eq!(mapping.provider, "aws");
        assert_eq!(mapping.prefix, "aws");
        assert!(mapping.services.contains_key("s3"));
        let s3 = &mapping.services["s3"];
        let op = &s3.operations["DeleteBucket"];
        assert_eq!(op.cli, "s3 rb");
        assert_eq!(op.cli_alt.as_deref(), Some("s3api delete-bucket"));
    }

    #[test]
    fn load_mapping_nonexistent_file() {
        let err = load_mapping(Path::new("/nonexistent/mapping.yaml")).unwrap_err();
        assert!(matches!(err, MappingError::ReadFile { .. }));
        assert!(err.to_string().contains("failed to read mapping file"));
    }

    #[test]
    fn load_mapping_invalid_yaml() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("bad.yaml");
        std::fs::write(&path, "{{{{not valid yaml at all}}}}").unwrap();

        let err = load_mapping(&path).unwrap_err();
        assert!(matches!(err, MappingError::Parse { .. }));
        assert!(err.to_string().contains("failed to parse mapping"));
    }

    #[test]
    fn load_mapping_empty_services() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("mapping.yaml");
        let mut f = std::fs::File::create(&path).unwrap();
        write!(
            f,
            r#"
provider: test
prefix: test
"#
        )
        .unwrap();

        let mapping = load_mapping(&path).unwrap();
        assert!(mapping.services.is_empty());
    }

    // ── CliMapping deserialization ───────────────────────────────

    #[test]
    fn cli_mapping_multiple_services() {
        let yaml = r#"
provider: aws
prefix: aws
services:
  ec2:
    operations:
      TerminateInstances:
        cli: "ec2 terminate-instances"
  s3:
    operations:
      DeleteBucket:
        cli: "s3 rb"
"#;
        let mapping: CliMapping = serde_yaml_ng::from_str(yaml).unwrap();
        assert_eq!(mapping.services.len(), 2);
        assert!(mapping.services.contains_key("ec2"));
        assert!(mapping.services.contains_key("s3"));
    }

    #[test]
    fn operation_mapping_without_cli_alt() {
        let yaml = r#"
provider: test
prefix: test
services:
  svc:
    operations:
      DoThing:
        cli: "do-thing"
"#;
        let mapping: CliMapping = serde_yaml_ng::from_str(yaml).unwrap();
        let op = &mapping.services["svc"].operations["DoThing"];
        assert_eq!(op.cli, "do-thing");
        assert!(op.cli_alt.is_none());
    }
}
