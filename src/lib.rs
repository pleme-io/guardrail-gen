//! Auto-generate guardrail rules from `OpenAPI` 3.x and AWS SDK specs.
//!
//! The pipeline: parse spec → extract operations → filter destructive ones →
//! classify risk → generate regex patterns and YAML rules.

/// Destructive operation detection by verb pattern matching.
pub mod filter;
/// Guardrail rule generation and YAML serialization.
pub mod generator;
/// CLI command mapping for non-standard provider CLIs.
pub mod mapping;
/// Risk classification of destructive operations.
pub mod risk;
/// `OpenAPI` and AWS SDK spec parsing.
pub mod spec;
