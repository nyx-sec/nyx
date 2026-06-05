//! `nyx repro` subcommand.
//!
//! Replays dynamic verification bundles written for Confirmed findings. The
//! cache is keyed by spec hash, while users and the browser UI usually start
//! from a stable finding id, so this command resolves by manifest first and
//! then delegates to the bundle's `reproduce.sh`.

use crate::dynamic::repro::{self, LocatedReproBundle, ReplayResult, ReproManifest};
use crate::errors::{NyxError, NyxResult};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::exit;

#[derive(Debug)]
struct ResolvedBundle {
    root: PathBuf,
    manifest: Option<ReproManifest>,
    matching_bundle_count: usize,
}

pub fn handle(
    finding: Option<String>,
    spec_hash: Option<String>,
    bundle: Option<PathBuf>,
    docker: bool,
    print_path: bool,
    list: bool,
) -> NyxResult<()> {
    if list {
        let finding_id = finding.as_deref().ok_or_else(|| {
            NyxError::Msg("`nyx repro --list` requires `--finding <ID>`".to_owned())
        })?;
        return list_bundles_for_finding(finding_id);
    }

    let resolved = resolve_one(finding.as_deref(), spec_hash.as_deref(), bundle.as_deref())?;
    if print_path {
        println!("{}", resolved.root.display());
        return Ok(());
    }

    if let Some(manifest) = &resolved.manifest
        && resolved.matching_bundle_count > 1
    {
        eprintln!(
            "note: found {} repro bundles for finding {}; using newest spec hash {}",
            resolved.matching_bundle_count, manifest.finding_id, manifest.spec_hash
        );
    }

    replay(resolved, docker)
}

fn list_bundles_for_finding(finding_id: &str) -> NyxResult<()> {
    let bundles = repro::find_bundles_by_finding_id(finding_id).map_err(repro_error)?;
    if bundles.is_empty() {
        return Err(NyxError::Msg(missing_finding_message(finding_id)));
    }

    println!(
        "{} repro bundle{} for finding {} (newest first)",
        bundles.len(),
        if bundles.len() == 1 { "" } else { "s" },
        finding_id
    );
    for bundle in bundles {
        println!(
            "{}\tspec_hash={}\ttoolchain={}",
            bundle.root.display(),
            bundle.manifest.spec_hash,
            bundle.manifest.toolchain_id.as_deref().unwrap_or("-")
        );
    }
    Ok(())
}

fn resolve_one(
    finding: Option<&str>,
    spec_hash: Option<&str>,
    bundle: Option<&Path>,
) -> NyxResult<ResolvedBundle> {
    match (finding, spec_hash, bundle) {
        (Some(finding_id), None, None) => resolve_by_finding(finding_id),
        (None, Some(spec_hash), None) => resolve_by_spec_hash(spec_hash),
        (None, None, Some(path)) => resolve_by_bundle_path(path),
        _ => Err(NyxError::Msg(
            "choose exactly one repro target: --finding, --spec-hash, or --bundle".to_owned(),
        )),
    }
}

fn resolve_by_finding(finding_id: &str) -> NyxResult<ResolvedBundle> {
    let mut bundles = repro::find_bundles_by_finding_id(finding_id).map_err(repro_error)?;
    if bundles.is_empty() {
        return Err(NyxError::Msg(missing_finding_message(finding_id)));
    }

    let matching_bundle_count = bundles.len();
    let LocatedReproBundle { root, manifest, .. } = bundles.remove(0);
    Ok(ResolvedBundle {
        root,
        manifest: Some(manifest),
        matching_bundle_count,
    })
}

fn resolve_by_spec_hash(spec_hash: &str) -> NyxResult<ResolvedBundle> {
    let Some(root) = repro::bundle_root_for(spec_hash) else {
        return Err(NyxError::Msg(
            "cannot determine the Nyx repro cache directory on this host".to_owned(),
        ));
    };
    if !root.is_dir() {
        return Err(NyxError::Msg(format!(
            "no repro bundle found for spec hash `{spec_hash}` at {}",
            root.display()
        )));
    }

    let manifest = repro::read_manifest(&root).map_err(repro_error)?;
    if manifest.spec_hash != spec_hash {
        return Err(NyxError::Msg(format!(
            "manifest at {} belongs to spec hash `{}`, not `{spec_hash}`",
            root.display(),
            manifest.spec_hash
        )));
    }

    Ok(ResolvedBundle {
        root,
        manifest: Some(manifest),
        matching_bundle_count: 1,
    })
}

fn resolve_by_bundle_path(path: &Path) -> NyxResult<ResolvedBundle> {
    let root = path.canonicalize().map_err(|e| {
        NyxError::Msg(format!(
            "cannot resolve repro bundle path {}: {e}",
            path.display()
        ))
    })?;
    if !root.is_dir() {
        return Err(NyxError::Msg(format!(
            "repro bundle path is not a directory: {}",
            root.display()
        )));
    }

    let manifest_path = root.join("manifest.json");
    let manifest = if manifest_path.is_file() {
        Some(repro::read_manifest(&root).map_err(repro_error)?)
    } else {
        None
    };

    Ok(ResolvedBundle {
        root,
        manifest,
        matching_bundle_count: 1,
    })
}

fn replay(resolved: ResolvedBundle, docker: bool) -> NyxResult<()> {
    let mut stdout = std::io::stdout().lock();
    let mut stderr = std::io::stderr().lock();

    writeln!(stdout, "Repro bundle: {}", resolved.root.display())?;
    if let Some(manifest) = &resolved.manifest {
        writeln!(
            stdout,
            "Finding: {}  Spec: {}",
            manifest.finding_id, manifest.spec_hash
        )?;
        if let Some(toolchain) = &manifest.toolchain_id {
            writeln!(stdout, "Toolchain: {toolchain}")?;
        }
    }
    writeln!(
        stdout,
        "Backend: {}",
        if docker { "docker" } else { "process" }
    )?;

    let extra_args: Vec<&str> = if docker { vec!["--docker"] } else { Vec::new() };
    let replay = repro::replay_bundle_capture(&resolved.root, &extra_args);
    stdout.write_all(&replay.stdout)?;
    if !replay.stdout.is_empty() && !replay.stdout.ends_with(b"\n") {
        writeln!(stdout)?;
    }
    stderr.write_all(&replay.stderr)?;
    if !replay.stderr.is_empty() && !replay.stderr.ends_with(b"\n") {
        writeln!(stderr)?;
    }

    match replay.result {
        ReplayResult::Pass => {
            writeln!(stdout, "Replay result: pass")?;
            Ok(())
        }
        ReplayResult::Mismatch => {
            writeln!(stderr, "Replay result: mismatch")?;
            exit(1);
        }
        ReplayResult::DockerUnavailable => {
            writeln!(stderr, "Replay result: docker unavailable")?;
            exit(2);
        }
        ReplayResult::ToolchainMismatch => {
            writeln!(
                stderr,
                "Replay result: host toolchain mismatch; retry with --docker"
            )?;
            exit(3);
        }
        ReplayResult::UnexpectedError { exit_code } => {
            writeln!(stderr, "Replay result: unexpected script exit {exit_code}")?;
            exit(exit_code);
        }
        ReplayResult::ScriptInvocationFailed { message } => Err(NyxError::Msg(message)),
    }
}

fn missing_finding_message(finding_id: &str) -> String {
    let cache = repro::repro_base_dir()
        .map(|p| p.display().to_string())
        .unwrap_or_else(|| "(no cache directory available)".to_owned());
    format!(
        "no repro bundle found for finding `{finding_id}` in {cache}; \
         run `nyx scan --verify` to create one, or pass --spec-hash/--bundle for an explicit bundle"
    )
}

fn repro_error(err: repro::ReproError) -> NyxError {
    NyxError::Msg(format!("repro bundle error: {err}"))
}
