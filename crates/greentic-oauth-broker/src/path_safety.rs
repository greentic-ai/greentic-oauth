use std::path::{Path, PathBuf};

use anyhow::{Context, Result};

/// Normalize a user-supplied path and ensure it stays within an allowed root.
/// Rejects absolute paths and any that escape via `..`.
pub fn normalize_under_root(root: &Path, candidate: &Path) -> Result<PathBuf> {
    if candidate.is_absolute() {
        anyhow::bail!("absolute paths are not allowed: {}", candidate.display());
    }

    let canon_root = root
        .canonicalize()
        .with_context(|| format!("failed to canonicalize root {}", root.display()))?;

    let mut normalized = canon_root.clone();
    for component in candidate.components() {
        use std::path::Component;
        match component {
            Component::Prefix(_) | Component::RootDir => {
                anyhow::bail!("absolute paths are not allowed: {}", candidate.display());
            }
            Component::CurDir => {}
            Component::ParentDir => {
                if !normalized.pop() {
                    anyhow::bail!(
                        "path escapes root ({}): {}",
                        canon_root.display(),
                        candidate.display()
                    );
                }
            }
            Component::Normal(part) => normalized.push(part),
        }
    }

    if !normalized.starts_with(&canon_root) {
        anyhow::bail!("normalized path escapes root: {}", normalized.display());
    }

    Ok(normalized)
}
