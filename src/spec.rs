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
    /// HTTP method (e.g. `GET`, `POST`, `DELETE`).
    pub method: String,
    /// URL path template (e.g. `/items/{id}`).
    pub path: String,
    /// Unique operation identifier from the spec.
    pub operation_id: String,
    /// Human-readable summary or description.
    pub summary: String,
    /// Tags assigned to this operation.
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
    use pretty_assertions::assert_eq;
    use std::io::Write;

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

    #[test]
    fn parse_spec_from_yaml_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("spec.yaml");
        let mut f = std::fs::File::create(&path).unwrap();
        write!(
            f,
            r#"
openapi: "3.0.0"
info:
  title: File API
  version: "2.0.0"
paths:
  /things:
    get:
      operationId: listThings
      summary: List things
"#
        )
        .unwrap();

        let spec = parse_spec(&path).unwrap();
        assert_eq!(spec.info.title, "File API");
        let ops = all_operations(&spec);
        assert_eq!(ops.len(), 1);
        assert_eq!(ops[0].operation_id, "listThings");
    }

    #[test]
    fn parse_spec_from_json_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("spec.json");
        let mut f = std::fs::File::create(&path).unwrap();
        write!(
            f,
            r#"{{
  "info": {{ "title": "JSON API", "version": "1.0.0" }},
  "paths": {{
    "/items": {{
      "delete": {{
        "operationId": "deleteItem",
        "summary": "Delete item"
      }}
    }}
  }}
}}"#
        )
        .unwrap();

        let spec = parse_spec(&path).unwrap();
        assert_eq!(spec.info.title, "JSON API");
        let ops = all_operations(&spec);
        assert_eq!(ops.len(), 1);
        assert_eq!(ops[0].method, "DELETE");
    }

    #[test]
    fn parse_spec_nonexistent_file() {
        let err = parse_spec(Path::new("/nonexistent/spec.yaml")).unwrap_err();
        assert!(matches!(err, ParseError::ReadFile { .. }));
        let msg = err.to_string();
        assert!(msg.contains("failed to read spec file"));
    }

    #[test]
    fn parse_aws_sdk_model() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("service.min.json");
        let mut f = std::fs::File::create(&path).unwrap();
        write!(
            f,
            r#"{{
  "metadata": {{
    "serviceFullName": "AWS Test Service"
  }},
  "operations": {{
    "DeleteBucket": {{
      "http": {{ "method": "DELETE", "requestUri": "/buckets/{{Bucket}}" }}
    }},
    "ListBuckets": {{
      "http": {{ "method": "GET", "requestUri": "/buckets" }}
    }},
    "CreateThing": {{}}
  }}
}}"#
        )
        .unwrap();

        let spec = parse_spec(&path).unwrap();
        assert_eq!(spec.info.title, "AWS Test Service");

        let ops = all_operations(&spec);
        assert_eq!(ops.len(), 3);
        assert!(ops.iter().any(|o| o.operation_id == "DeleteBucket" && o.method == "DELETE"));
        assert!(ops.iter().any(|o| o.operation_id == "ListBuckets" && o.method == "GET"));
        assert!(ops.iter().any(|o| o.operation_id == "CreateThing" && o.method == "POST"));
    }

    #[test]
    fn aws_model_without_metadata_falls_through() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("no-meta.json");
        let mut f = std::fs::File::create(&path).unwrap();
        write!(
            f,
            r#"{{
  "operations": {{
    "Foo": {{}}
  }}
}}"#
        )
        .unwrap();

        let result = parse_spec(&path);
        assert!(result.is_err());
    }

    #[test]
    fn aws_model_empty_operations_falls_through() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("empty-ops.json");
        let mut f = std::fs::File::create(&path).unwrap();
        write!(
            f,
            r#"{{
  "metadata": {{ "serviceFullName": "Empty" }},
  "operations": {{}}
}}"#
        )
        .unwrap();

        let result = parse_spec(&path);
        assert!(result.is_err());
    }

    #[test]
    fn all_operations_skips_missing_operation_id() {
        let yaml = r#"
openapi: "3.0.0"
info:
  title: Test
  version: "1.0.0"
paths:
  /items:
    get:
      operationId: listItems
      summary: List items
    post:
      summary: No operation ID here
"#;
        let spec: OpenApiSpec = serde_yaml_ng::from_str(yaml).unwrap();
        let ops = all_operations(&spec);
        assert_eq!(ops.len(), 1);
        assert_eq!(ops[0].operation_id, "listItems");
    }

    #[test]
    fn all_operations_uses_description_as_fallback_summary() {
        let yaml = r#"
openapi: "3.0.0"
info:
  title: Test
  version: "1.0.0"
paths:
  /items:
    get:
      operationId: getItem
      description: Fetches a single item
"#;
        let spec: OpenApiSpec = serde_yaml_ng::from_str(yaml).unwrap();
        let ops = all_operations(&spec);
        assert_eq!(ops.len(), 1);
        assert_eq!(ops[0].summary, "Fetches a single item");
    }

    #[test]
    fn all_operations_prefers_summary_over_description() {
        let yaml = r#"
openapi: "3.0.0"
info:
  title: Test
  version: "1.0.0"
paths:
  /items:
    get:
      operationId: getItem
      summary: Get item
      description: Long description
"#;
        let spec: OpenApiSpec = serde_yaml_ng::from_str(yaml).unwrap();
        let ops = all_operations(&spec);
        assert_eq!(ops[0].summary, "Get item");
    }

    #[test]
    fn all_operations_method_uppercased() {
        let yaml = r#"
openapi: "3.0.0"
info:
  title: Test
  version: "1.0.0"
paths:
  /items:
    put:
      operationId: updateItem
    patch:
      operationId: patchItem
"#;
        let spec: OpenApiSpec = serde_yaml_ng::from_str(yaml).unwrap();
        let ops = all_operations(&spec);
        assert!(ops.iter().any(|o| o.method == "PUT"));
        assert!(ops.iter().any(|o| o.method == "PATCH"));
    }

    #[test]
    fn all_operations_empty_paths() {
        let yaml = r#"
openapi: "3.0.0"
info:
  title: Empty
  version: "1.0.0"
paths: {}
"#;
        let spec: OpenApiSpec = serde_yaml_ng::from_str(yaml).unwrap();
        let ops = all_operations(&spec);
        assert!(ops.is_empty());
    }

    #[test]
    fn aws_model_default_method_is_post() {
        let json = r#"{
  "metadata": { "serviceFullName": "Test" },
  "operations": {
    "DoSomething": {}
  }
}"#;
        let aws: AwsSdkModel = serde_json::from_str(json).unwrap();
        let spec = aws_to_openapi(aws);
        let ops = all_operations(&spec);
        assert_eq!(ops.len(), 1);
        assert_eq!(ops[0].method, "POST");
    }

    #[test]
    fn aws_model_title_defaults_when_missing_service_name() {
        let json = r#"{
  "metadata": {},
  "operations": {
    "Foo": {}
  }
}"#;
        let aws: AwsSdkModel = serde_json::from_str(json).unwrap();
        let spec = aws_to_openapi(aws);
        assert!(spec.info.title.is_empty());
    }

    #[test]
    fn aws_model_put_method() {
        let json = r#"{
  "metadata": { "serviceFullName": "PutTest" },
  "operations": {
    "PutObject": {
      "http": { "method": "PUT", "requestUri": "/objects" }
    }
  }
}"#;
        let aws: AwsSdkModel = serde_json::from_str(json).unwrap();
        let spec = aws_to_openapi(aws);
        let ops = all_operations(&spec);
        assert_eq!(ops[0].method, "PUT");
    }

    #[test]
    fn aws_model_patch_method() {
        let json = r#"{
  "metadata": { "serviceFullName": "PatchTest" },
  "operations": {
    "UpdateItem": {
      "http": { "method": "PATCH", "requestUri": "/items" }
    }
  }
}"#;
        let aws: AwsSdkModel = serde_json::from_str(json).unwrap();
        let spec = aws_to_openapi(aws);
        let ops = all_operations(&spec);
        assert_eq!(ops[0].method, "PATCH");
    }

    #[test]
    fn parse_error_display() {
        let err = ParseError::ReadFile {
            path: PathBuf::from("/foo/bar.yaml"),
            source: std::io::Error::new(std::io::ErrorKind::NotFound, "no such file"),
        };
        let msg = err.to_string();
        assert!(msg.contains("/foo/bar.yaml"));
        assert!(msg.contains("no such file"));
    }
}
