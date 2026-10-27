//! The `errand` command-line tool.
//!
//! * `errand run prepare TASK`  : phase 1, with whatever credentials this container was given. No model.
//! * `errand run model TASK`    : phases 2 to 5; refuses (exit 72) unless the boundary verifies.
//! * `errand verify-boundary`   : print the boundary report as JSON; exit 72 if it does not verify.
//! * `errand schema --out DIR`  : write the JSON Schemas.
#![forbid(unsafe_code)]

use std::collections::BTreeMap;
use std::path::PathBuf;
use std::process::ExitCode;
use std::time::Duration;

use clap::{Parser, Subcommand, ValueEnum};
use errand_kit::engine::{self, ModelOptions, EXIT_BOUNDARY};
use errand_kit::gates::recipe::Recipe;
use errand_kit::patchmake::WorkDirs;
use errand_kit::sandbox::{bubblewrap::Bubblewrap, container::ContainerBoundary, Sandbox};
use errand_kit::task::Task;
use errand_kit::worker::claude::ClaudeCli;

#[derive(Parser)]
#[command(name = "errand", version, about = "Gated, sandboxed agent runs")]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Clone, Copy, ValueEnum)]
enum Phase {
    /// Credentialed data gathering; no model.
    Prepare,
    /// Boundary, worker, gates, record; must run with no credentials present.
    Model,
}

#[derive(Clone, Copy, ValueEnum)]
enum Boundary {
    /// The container is the boundary; the Kit verifies it.
    Container,
    /// Wrap the worker in bubblewrap (a Linux host).
    Bubblewrap,
}

#[derive(Subcommand)]
enum Cmd {
    /// Run one phase of a task.
    Run {
        /// Which phase.
        #[arg(value_enum)]
        phase: Phase,
        /// Task name (a directory under --tasks-root).
        task: String,
        /// Directory holding task directories.
        #[arg(long, default_value = "/opt/runner/tasks")]
        tasks_root: PathBuf,
        /// Output directory.
        #[arg(long, default_value = "/out")]
        out: PathBuf,
        /// Which boundary to verify.
        #[arg(long, value_enum, default_value = "container")]
        boundary: Boundary,
        /// A repo-side recipe (JSON), required for L1 and above.
        #[arg(long)]
        recipe: Option<PathBuf>,
        /// Worker wall-clock limit in seconds.
        #[arg(long, default_value_t = 900)]
        timeout: u64,
        /// File holding the worker's own token.
        #[arg(long, default_value = "/run/secrets/claude-token")]
        token_file: PathBuf,
        /// L1+: the pristine tree (no .git). The Kit builds the patch itself from --base and --tree.
        #[arg(long, requires = "tree")]
        base: Option<PathBuf>,
        /// L1+: the worker's edited copy of the tree.
        #[arg(long, requires = "base")]
        tree: Option<PathBuf>,
        /// Extra directories the worker may read (repeatable), for example a read-only folder with the ticket text.
        #[arg(long = "extra-dir")]
        extra_dirs: Vec<PathBuf>,
    },
    /// Verify the boundary and print the report as JSON.
    VerifyBoundary {
        /// Which boundary to verify.
        #[arg(long, value_enum, default_value = "container")]
        boundary: Boundary,
    },
    /// Write the JSON Schemas for the contract.
    Schema {
        /// Output directory.
        #[arg(long, default_value = "schema")]
        out: PathBuf,
    },
}

fn sandbox(b: Boundary) -> Box<dyn Sandbox> {
    match b {
        Boundary::Container => Box::new(ContainerBoundary::new()),
        Boundary::Bubblewrap => Box::new(Bubblewrap::default()),
    }
}

fn run() -> Result<i32, errand_kit::ErrandError> {
    let cli = Cli::parse();
    match cli.cmd {
        Cmd::Schema { out } => {
            errand_kit::schema::write_all(&out)?;
            tracing::info!(dir = %out.display(), "schemas written");
            Ok(0)
        }
        Cmd::VerifyBoundary { boundary } => {
            let report = sandbox(boundary).verify();
            println!("{}", serde_json::to_string_pretty(&report)?);
            Ok(if report.ok { 0 } else { EXIT_BOUNDARY })
        }
        Cmd::Run {
            phase,
            task,
            tasks_root,
            out,
            boundary,
            recipe,
            timeout,
            token_file,
        } => {
            let task = Task::load(&tasks_root, &task)?;
            match phase {
                Phase::Prepare => engine::run_prepare(&task, &out),
                Phase::Model => {
                    let token = std::env::var("CLAUDE_CODE_OAUTH_TOKEN")
                        .ok()
                        .or_else(|| {
                            std::fs::read_to_string(&token_file)
                                .ok()
                                .map(|s| s.trim().to_string())
                        })
                        .filter(|s| !s.is_empty());
                    let recipe = recipe.map(|p| Recipe::load(&p)).transpose()?;
                    let sb = sandbox(boundary);
                    let worker = ClaudeCli::default();
                    let parent_env: BTreeMap<String, String> = std::env::vars().collect();
                    let opts = ModelOptions {
                        out_dir: &out,
                        sandbox: sb.as_ref(),
                        worker: &worker,
                        token,
                        parent_env,
                        recipe,
                        timeout: Duration::from_secs(timeout),
                        work: base.zip(tree).map(|(base, tree)| WorkDirs { base, tree }),
                        extra_dirs,
                    };
                    let rec = engine::run_model(&task, &opts)?;
                    if let Some(d) = &rec.digest {
                        if let Ok(text) = std::fs::read_to_string(out.join(d)) {
                            println!("{text}");
                        }
                    }
                    for g in rec.gates.iter().filter(|g| !g.ok) {
                        eprintln!("errand: gate {} failed: {}", g.name, g.detail);
                    }
                    Ok(rec.exit_code)
                }
            }
        }
    }
}

fn main() -> ExitCode {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .with_writer(std::io::stderr)
        .init();
    match run() {
        Ok(code) => ExitCode::from(u8::try_from(code).unwrap_or(1)),
        Err(e) => {
            eprintln!("errand: {e}");
            ExitCode::from(64)
        }
    }
}
