# guardrail-gen — Auto-generate Guardrail Rules from API Specs

Parses OpenAPI 3.x specs and AWS SDK models, identifies destructive operations,
classifies risk severity, and generates YAML rule files for the `guardrail` tool.

## Pipeline

```
OpenAPI / AWS SDK spec
    │
    ▼
spec::parse_spec()          ← Dual-format: OpenAPI 3.x YAML/JSON + AWS .min.json
    │
    ▼
filter::filter_destructive() ← 18 destructive verbs, 18 safe verb exclusions
    │
    ▼
risk::classify()            ← Block (high-risk resources) vs Warn (low-risk)
    │
    ▼
mapping::build_pattern()    ← kebab-case regex: (?i)prefix\s+operation\b
    │
    ▼
generator::generate_rules() ← Rule structs with test_block + test_allow
    │
    ▼
generator::to_yaml()        ← YAML output (stdout or file)
```

## CLI

```bash
# Generate rules from OpenAPI spec
guardrail-gen generate \
  --spec akeyless-api.yaml \
  --provider akeyless \
  --cli-prefix akeyless \
  --category akeyless \
  -o rules/akeyless-generated.yaml

# Generate from AWS SDK model
guardrail-gen generate \
  --spec aws/ec2.min.json \
  --provider aws \
  --cli-prefix aws \
  -o generated/aws/ec2.yaml

# Analyze without generating
guardrail-gen analyze --spec api.yaml
```

## Modules

| Module | Purpose |
|--------|---------|
| `spec` | Parse OpenAPI 3.x + AWS SDK `.min.json` → `ResolvedOperation` |
| `filter` | Identify destructive operations by verb + HTTP method |
| `risk` | Classify Block vs Warn based on resource type |
| `mapping` | Convert operation IDs to kebab-case CLI patterns; optional CLI mapping files |
| `generator` | Compose pipeline, generate Rule structs with test commands, serialize to YAML |

## Destructive Verb Detection

**Always destructive:** DELETE HTTP method

**Destructive verbs** (case-insensitive `contains` on operation ID):
delete, destroy, terminate, remove, purge, revoke, drop, truncate,
flush, reset, disable, deregister, cancel, uninstall, detach,
disassociate, release, abandon

**Safe verb exclusions** (case-insensitive `starts_with` — checked first):
create, get, list, describe, update, put, read, fetch, search, query,
check, verify, validate, test, ping, health, status, enable, register,
associate, attach, tag, untag, start, begin

## Risk Classification

**Block** (high-risk resources): database, db, instance, cluster, volume,
bucket, secret, key, vault, certificate, credential, namespace, project,
account, stack, zone, item, role, auth, target, gateway, producer,
migration, group, policy, server

**Warn** (low-risk resources): tag, label, metric, alarm, event, log,
notification, subscription, topic, queue, rule, permission, attachment,
association

**Default:** DELETE on unknown resource → Block (conservative)

## Generated Output Format

```yaml
- name: aws-delete-bucket
  pattern: (?i)aws\s+delete\-bucket\b
  severity: block
  message: DeleteBucket — destructive operation
  category: cloud
  test_block: aws delete-bucket --id test-123
  test_allow: aws list-resources --output json
```

`test_block` and `test_allow` are auto-generated: the generator knows the exact
CLI syntax at generation time, so test commands are deterministic.

## Generated Rule Inventory

| Directory | Service count | Rule count | Source format |
|-----------|--------------|------------|---------------|
| `generated/aws/` | 298 | ~2,347 | AWS SDK `.min.json` |
| `generated/akeyless/` | 1 | 22 | OpenAPI 3.x YAML |

## CLI Mapping Files

For providers where CLI syntax doesn't match operation IDs (e.g., AWS subcommands):

```yaml
provider: aws
prefix: aws
services:
  ec2:
    operations:
      TerminateInstances:
        cli: "ec2 terminate-instances"
```

Without mapping, pattern is derived via kebab-case: `deleteItem` → `delete-item`.

## Conventions

- Edition 2024, Rust 1.89.0+, MIT, clippy pedantic
- Generated files committed to `generated/` for validation
- Output is consumed by `guardrail` (copied to `rules/` or `rules.d/`)
- 43 tests across all modules
