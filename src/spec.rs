use indexmap::IndexMap;
use serde::Deserialize;
use std::path::Path;

/// Minimal OpenAPI 3.x spec — only what we need for guardrail generation.
#[derive(Debug, Deserialize)]
pub struct OpenApiSpec {
    pub info: Option<Info>,
    #[serde(default)]
    pub paths: IndexMap<String, PathItem>,
}

#[derive(Debug, Deserialize)]
pub struct Info {
    pub title: Option<String>,
}

#[derive(Debug, Default, Deserialize)]
pub struct PathItem {
    pub get: Option<Operation>,
    pub post: Option<Operation>,
    pub put: Option<Operation>,
    pub delete: Option<Operation>,
    pub patch: Option<Operation>,
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Operation {
    pub operation_id: Option<String>,
    pub summary: Option<String>,
    pub description: Option<String>,
    #[serde(default)]
    pub tags: Vec<String>,
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

/// Parse an OpenAPI spec from a YAML or JSON file.
///
/// # Errors
///
/// Returns an error if the file can't be read or parsed.
pub fn parse_spec(path: &Path) -> anyhow::Result<OpenApiSpec> {
    let content = std::fs::read_to_string(path)?;
    if path.extension().is_some_and(|e| e == "json") {
        Ok(serde_json::from_str(&content)?)
    } else {
        Ok(serde_yaml::from_str(&content)?)
    }
}

/// Extract all operations from a spec with their HTTP methods.
pub fn all_operations(spec: &OpenApiSpec) -> Vec<ResolvedOperation> {
    let mut ops = Vec::new();
    for (path, item) in &spec.paths {
        let methods: Vec<(&str, &Option<Operation>)> = vec![
            ("GET", &item.get),
            ("POST", &item.post),
            ("PUT", &item.put),
            ("DELETE", &item.delete),
            ("PATCH", &item.patch),
        ];
        for (method, op_opt) in methods {
            if let Some(op) = op_opt {
                let operation_id = op.operation_id.clone().unwrap_or_default();
                if operation_id.is_empty() {
                    continue;
                }
                ops.push(ResolvedOperation {
                    method: method.to_owned(),
                    path: path.clone(),
                    operation_id,
                    summary: op.summary.clone()
                        .or_else(|| op.description.clone())
                        .unwrap_or_default(),
                    tags: op.tags.clone(),
                });
            }
        }
    }
    ops
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
        let spec: OpenApiSpec = serde_yaml::from_str(yaml).unwrap();
        let ops = all_operations(&spec);
        assert_eq!(ops.len(), 3);
        assert!(ops.iter().any(|o| o.operation_id == "deleteItem" && o.method == "DELETE"));
        assert!(ops.iter().any(|o| o.operation_id == "listItems" && o.method == "GET"));
    }
}
