use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use serde::Deserialize;

pub use sekkei::{Info, OpenApiSpec, Operation, PathItem};

/// Errors that can occur when parsing an `OpenAPI` or AWS SDK spec file.
#[derive(Debug, thiserror::Error)]
pub enum ParseError {
    /// Failed to read the spec file from disk.
    #[error("failed to read spec file {path}: {source}")]
    ReadFile {
        /// Path that could not be read.
        path: PathBuf,
        /// Underlying I/O error.
        source: std::io::Error,
    },
    /// Failed to parse the spec content.
    #[error("failed to parse spec from {path}: {source}")]
    Parse {
        /// Path whose content failed to parse.
        path: PathBuf,
        /// Underlying parse error from sekkei.
        #[source]
        source: anyhow::Error,
    },
}

/// A parsed operation with its HTTP method and path.
#[derive(Debug, Clone)]
pub struct ResolvedOperation {
    pub method: String,
    pub path: String,
    pub operation_id: String,
    pub summary: String,
    pub tags: Vec<String>,
}

/// Parse an `OpenAPI` spec from a YAML or JSON file.
/// Also supports AWS SDK `.min.json` model format.
///
/// # Errors
///
/// Returns [`ParseError::ReadFile`] if the file cannot be read,
/// or [`ParseError::Parse`] if the content is not valid.
pub fn parse_spec(path: &Path) -> Result<OpenApiSpec, ParseError> {
    let content = std::fs::read_to_string(path).map_err(|e| ParseError::ReadFile {
        path: path.to_path_buf(),
        source: e,
    })?;

    // Try AWS SDK model format first (has "operations" at top level, no "paths")
    if let Ok(aws) = serde_json::from_str::<AwsSdkModel>(&content)
        && !aws.operations.is_empty()
        && aws.metadata.is_some()
    {
        return Ok(aws_to_openapi(aws));
    }

    sekkei::load_spec_from_str(&content, path).map_err(|e| ParseError::Parse {
        path: path.to_path_buf(),
        source: e,
    })
}

// ═══════════════════════════════════════════════════════════════════
// AWS SDK Model format support (domain-specific, stays here)
// ═══════════════════════════════════════════════════════════════════

#[derive(Debug, Deserialize)]
struct AwsSdkModel {
    metadata: Option<AwsMetadata>,
    #[serde(default)]
    operations: BTreeMap<String, AwsOperation>,
}

#[derive(Debug, Deserialize)]
struct AwsMetadata {
    #[serde(alias = "serviceFullName")]
    service_full_name: Option<String>,
}

#[derive(Debug, Deserialize)]
struct AwsOperation {
    #[serde(default)]
    http: Option<AwsHttp>,
}

#[derive(Debug, Deserialize)]
struct AwsHttp {
    method: Option<String>,
    #[serde(alias = "requestUri")]
    request_uri: Option<String>,
}

fn aws_to_openapi(aws: AwsSdkModel) -> OpenApiSpec {
    let mut paths = std::collections::BTreeMap::new();

    for (name, op) in &aws.operations {
        let method = op
            .http
            .as_ref()
            .and_then(|h| h.method.as_deref())
            .unwrap_or("POST")
            .to_uppercase();
        let uri = op
            .http
            .as_ref()
            .and_then(|h| h.request_uri.as_deref())
            .unwrap_or("/");

        let operation = Operation {
            operation_id: Some(name.clone()),
            summary: None,
            description: None,
            parameters: vec![],
            request_body: None,
            responses: std::collections::BTreeMap::new(),
            security: vec![],
            tags: vec![],
        };

        let mut item = PathItem {
            get: None,
            post: None,
            put: None,
            delete: None,
            patch: None,
            parameters: vec![],
        };
        match method.as_str() {
            "GET" => item.get = Some(operation),
            "PUT" => item.put = Some(operation),
            "DELETE" => item.delete = Some(operation),
            "PATCH" => item.patch = Some(operation),
            _ => item.post = Some(operation),
        }

        // Use operation name as unique path key
        paths.insert(format!("{uri}#{name}"), item);
    }

    OpenApiSpec {
        info: Info {
            title: aws
                .metadata
                .and_then(|m| m.service_full_name)
                .unwrap_or_default(),
            description: None,
            version: String::new(),
        },
        paths,
        components: None,
        servers: vec![],
        security: vec![],
    }
}

/// Extract all operations from a spec with their HTTP methods.
#[must_use]
pub fn all_operations(spec: &OpenApiSpec) -> Vec<ResolvedOperation> {
    sekkei::all_operations(spec)
        .into_iter()
        .filter_map(|(method, path, op)| {
            let operation_id = op.operation_id.clone().unwrap_or_default();
            if operation_id.is_empty() {
                return None;
            }
            Some(ResolvedOperation {
                method: method.to_uppercase(),
                path,
                operation_id,
                summary: op
                    .summary
                    .clone()
                    .or_else(|| op.description.clone())
                    .unwrap_or_default(),
                tags: op.tags.clone(),
            })
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_minimal_spec() {
        let yaml = r#"
openapi: "3.0.0"
info:
  title: Test API
  version: "1.0.0"
paths:
  /items:
    get:
      operationId: listItems
      summary: List items
    delete:
      operationId: deleteItem
      summary: Delete an item
  /users:
    post:
      operationId: createUser
      summary: Create user
"#;
        let spec: OpenApiSpec = serde_yaml_ng::from_str(yaml).unwrap();
        let ops = all_operations(&spec);
        assert_eq!(ops.len(), 3);
        assert!(ops
            .iter()
            .any(|o| o.operation_id == "deleteItem" && o.method == "DELETE"));
        assert!(ops
            .iter()
            .any(|o| o.operation_id == "listItems" && o.method == "GET"));
    }
}
