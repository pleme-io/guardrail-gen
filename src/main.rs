use std::fs;
use std::path::PathBuf;

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};

use guardrail_gen::{generator, mapping, spec};

#[derive(Parser)]
#[command(name = "guardrail-gen", about = "Auto-generate guardrail rules from OpenAPI specs")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Generate guardrail rules from an OpenAPI spec.
    Generate {
        /// Path to the OpenAPI spec (YAML or JSON).
        #[arg(long)]
        spec: PathBuf,

        /// Provider name (e.g. akeyless, aws, gcp).
        #[arg(long)]
        provider: String,

        /// CLI prefix for regex patterns (e.g. "akeyless", "aws", "gcloud").
        #[arg(long)]
        cli_prefix: String,

        /// Category for generated rules (e.g. akeyless, cloud).
        #[arg(long, default_value = "cloud")]
        category: String,

        /// Optional CLI mapping file for providers with non-standard CLI syntax.
        #[arg(long)]
        cli_mapping: Option<PathBuf>,

        /// Output file (default: stdout).
        #[arg(long, short)]
        output: Option<PathBuf>,
    },

    /// Show stats about destructive operations in a spec without generating rules.
    Analyze {
        /// Path to the OpenAPI spec.
        #[arg(long)]
        spec: PathBuf,
    },
}

fn main() -> Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Command::Generate {
            spec: spec_path,
            provider,
            cli_prefix,
            category,
            cli_mapping,
            output,
        } => {
            let parsed = spec::parse_spec(&spec_path)
                .with_context(|| format!("parsing {}", spec_path.display()))?;
            let ops = spec::all_operations(&parsed);

            let mapping = cli_mapping
                .as_ref()
                .map(|p| mapping::load_mapping(p))
                .transpose()
                .context("loading CLI mapping")?;

            let rules = generator::generate_rules(
                &ops,
                &provider,
                &cli_prefix,
                &category,
                mapping.as_ref(),
            );

            let yaml = generator::to_yaml(&rules)?;

            if let Some(out) = output {
                fs::write(&out, &yaml)
                    .with_context(|| format!("writing {}", out.display()))?;
                eprintln!(
                    "guardrail-gen: {} rules generated from {} operations → {}",
                    rules.len(),
                    ops.len(),
                    out.display()
                );
            } else {
                print!("{yaml}");
                eprintln!(
                    "guardrail-gen: {} rules generated from {} operations",
                    rules.len(),
                    ops.len()
                );
            }

            Ok(())
        }
        Command::Analyze { spec: spec_path } => {
            let parsed = spec::parse_spec(&spec_path)
                .with_context(|| format!("parsing {}", spec_path.display()))?;
            let ops = spec::all_operations(&parsed);
            let destructive = guardrail_gen::filter::filter_destructive(&ops);

            let title = if parsed.info.title.is_empty() {
                "Unknown API"
            } else {
                &parsed.info.title
            };

            eprintln!("API: {title}");
            eprintln!("Total operations: {}", ops.len());
            eprintln!("Destructive operations: {}", destructive.len());
            eprintln!();

            for op in &destructive {
                let sev = guardrail_gen::risk::classify(op);
                eprintln!(
                    "  [{:5}] {:6} {:<40} {}",
                    sev.as_str().to_uppercase(),
                    op.method,
                    op.operation_id,
                    if op.summary.is_empty() { "-" } else { &op.summary }
                );
            }

            Ok(())
        }
    }
}
