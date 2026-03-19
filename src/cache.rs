use crate::error::{Error, Result};
use crate::index::MergedIndex;
use std::path::Path;

/// Save a MergedIndex to a file using bincode serialization.
pub fn save_index(index: &MergedIndex, path: &Path) -> Result<()> {
    let encoded = bincode::serialize(index).map_err(|e| Error::Cache(e.to_string()))?;
    std::fs::write(path, encoded)?;
    log::info!("Index cache saved to {}", path.display());
    Ok(())
}

/// Load a MergedIndex from a cached file.
pub fn load_index(path: &Path) -> Result<MergedIndex> {
    let data = std::fs::read(path)?;
    let index: MergedIndex =
        bincode::deserialize(&data).map_err(|e| Error::Cache(e.to_string()))?;
    log::info!(
        "Index cache loaded from {} ({} packets)",
        path.display(),
        index.packets.len()
    );
    Ok(index)
}

/// Validate a cached index by checking that all source files still exist
/// with the same mtime and size.
pub fn validate_index(index: &MergedIndex) -> bool {
    for sf in &index.source_files {
        match std::fs::metadata(&sf.path) {
            Ok(meta) => {
                let mtime = meta.modified().unwrap_or(std::time::UNIX_EPOCH);
                if mtime != sf.mtime || meta.len() != sf.size {
                    log::info!(
                        "Cache invalidated: {} changed (mtime or size mismatch)",
                        sf.path.display()
                    );
                    return false;
                }
            }
            Err(_) => {
                log::info!("Cache invalidated: {} no longer exists", sf.path.display());
                return false;
            }
        }
    }
    true
}
