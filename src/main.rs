mod cache;
mod error;
mod fs;
mod index;
mod pcap_reader;
mod pcapng_writer;

use clap::Parser;
use std::path::{Path, PathBuf};
use std::sync::Arc;

#[derive(Parser, Debug)]
#[command(
    name = "pcapfuse",
    about = "FUSE filesystem serving a virtual merged pcapng"
)]
struct Args {
    /// Directory containing pcap/pcapng source files
    #[arg(short, long)]
    source: PathBuf,

    /// Mountpoint directory
    #[arg(short, long)]
    mount: PathBuf,

    /// Path to store/load the serialized index cache
    #[arg(short, long)]
    cache: Option<PathBuf>,

    /// Name of the virtual file
    #[arg(short, long, default_value = "merged.pcapng")]
    name: String,

    /// Recurse into subdirectories
    #[arg(short, long)]
    recursive: bool,

    /// Glob pattern to filter source files (e.g. "*.pcap")
    #[arg(short, long)]
    filter: Option<String>,
}

fn enumerate_sources(args: &Args) -> error::Result<Vec<PathBuf>> {
    let source = &args.source;
    if !source.exists() {
        return Err(error::Error::Io(std::io::Error::new(
            std::io::ErrorKind::NotFound,
            format!("source path does not exist: {}", source.display()),
        )));
    }

    let mut paths = Vec::new();

    if source.is_file() {
        paths.push(source.clone());
        return Ok(paths);
    }

    if let Some(ref filter_pattern) = args.filter {
        let pattern = format!("{}/{}", source.display(), filter_pattern);
        for path in glob::glob(&pattern)?.flatten() {
            if path.is_file() && is_pcap_file(&path) {
                paths.push(path);
            }
        }
    } else if args.recursive {
        collect_recursive(source, &mut paths)?;
    } else {
        collect_flat(source, &mut paths)?;
    }

    paths.sort();

    if paths.is_empty() {
        return Err(error::Error::NoSourceFiles {
            path: source.clone(),
        });
    }

    Ok(paths)
}

fn collect_flat(dir: &Path, paths: &mut Vec<PathBuf>) -> error::Result<()> {
    for entry in std::fs::read_dir(dir)? {
        let entry = entry?;
        let path = entry.path();
        if path.is_file() && is_pcap_file(&path) {
            paths.push(path);
        }
    }
    Ok(())
}

fn collect_recursive(dir: &Path, paths: &mut Vec<PathBuf>) -> error::Result<()> {
    for entry in std::fs::read_dir(dir)? {
        let entry = entry?;
        let path = entry.path();
        if path.is_dir() {
            collect_recursive(&path, paths)?;
        } else if path.is_file() && is_pcap_file(&path) {
            paths.push(path);
        }
    }
    Ok(())
}

fn is_pcap_file(path: &Path) -> bool {
    matches!(
        path.extension().and_then(|e| e.to_str()),
        Some("pcap") | Some("pcapng") | Some("cap")
    )
}

fn main() {
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info")).init();

    let args = Args::parse();

    // Validate mountpoint
    if !args.mount.exists() || !args.mount.is_dir() {
        eprintln!(
            "Error: mountpoint {} does not exist or is not a directory",
            args.mount.display()
        );
        std::process::exit(1);
    }

    // Enumerate source files
    let sources = match enumerate_sources(&args) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("Error: {}", e);
            std::process::exit(1);
        }
    };

    eprintln!("Found {} source file(s)", sources.len());

    // Build or load index
    let merged_index = if let Some(ref cache_path) = args.cache {
        if cache_path.exists() {
            match cache::load_index(cache_path) {
                Ok(idx) if cache::validate_index(&idx) => {
                    eprintln!("Using cached index ({} packets)", idx.packets.len());
                    idx
                }
                Ok(_) => {
                    eprintln!("Cache invalidated, rebuilding index...");
                    build_and_cache(&sources, cache_path)
                }
                Err(_) => {
                    eprintln!("Building index...");
                    build_and_cache(&sources, cache_path)
                }
            }
        } else {
            eprintln!("Building index...");
            build_and_cache(&sources, cache_path)
        }
    } else {
        eprintln!("Building index...");
        match index::build_index(&sources) {
            Ok(i) => i,
            Err(e) => {
                eprintln!("Error building index: {}", e);
                std::process::exit(1);
            }
        }
    };

    eprintln!(
        "Index ready: {} packets, {} virtual bytes",
        merged_index.packets.len(),
        merged_index.total_virtual_size
    );

    let fuse_fs = fs::PcapFuseFs::new(Arc::new(merged_index), args.name.clone());

    eprintln!("Mounting {} at {}", args.name, args.mount.display());

    let mut config = fuser::Config::default();
    config.mount_options = vec![
        fuser::MountOption::RO,
        fuser::MountOption::FSName("pcapfuse".to_string()),
    ];

    if let Err(e) = fuser::mount2(fuse_fs, &args.mount, &config) {
        eprintln!("FUSE mount error: {}", e);
        eprintln!("Hint: make sure FUSE is installed (apt install fuse3) and user_allow_other is enabled in /etc/fuse.conf");
        std::process::exit(1);
    }
}

fn build_and_cache(sources: &[PathBuf], cache_path: &Path) -> index::MergedIndex {
    let idx = match index::build_index(sources) {
        Ok(i) => i,
        Err(e) => {
            eprintln!("Error building index: {}", e);
            std::process::exit(1);
        }
    };
    if let Err(e) = cache::save_index(&idx, cache_path) {
        eprintln!("Warning: failed to save cache: {}", e);
    }
    idx
}
