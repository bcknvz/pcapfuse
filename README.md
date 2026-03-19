# pcapfuse

A FUSE filesystem that mounts a directory of pcap/pcapng files as a single virtual `merged.pcapng`. Wireshark and tshark open this file as if it were a normal capture on disk — no intermediate merged copy is written.

## Why

Wireshark only opens one capture file at a time. The usual workaround is `mergecap`, which writes a full merged copy to disk before you can open it. That doesn't scale to large corpora (hundreds of GB across thousands of files). pcapfuse solves this by building an in-memory index at mount time and serving packet data lazily on demand.

## Prerequisites

- **Linux** with FUSE support (kernel module `fuse` loaded)
- **fuse3** user-space libraries: `sudo apt install fuse3` (Debian/Ubuntu) or `sudo dnf install fuse3` (Fedora)
- **Rust toolchain** (1.70+): install via [rustup](https://rustup.rs/) if not present

Verify FUSE is available:

```bash
ls /dev/fuse        # should exist
modinfo fuse        # should show module info
```

## Install

```bash
cd pcapfuse

# Debug build (fast compile, slower runtime)
make build

# Release build (slower compile, optimized runtime — use this for large corpora)
make release

# Optionally copy to your PATH
cp target/release/pcapfuse ~/.local/bin/
```

## Usage

### Basic: mount a directory of captures

```bash
mkdir /tmp/fuse
pcapfuse --source /path/to/pcaps --mount /tmp/fuse

# In another terminal:
wireshark /tmp/fuse/merged.pcapng
# or
tshark -r /tmp/fuse/merged.pcapng -c 100

# When done:
fusermount -u /tmp/fuse
```

pcapfuse runs in the foreground and blocks until unmounted. Status messages go to stderr.

### Recursive: include subdirectories

```bash
pcapfuse --source /data/captures --mount /tmp/fuse --recursive
```

### Filter: select specific files with a glob

```bash
pcapfuse --source /data/captures --mount /tmp/fuse --filter "**/*.pcapng"
pcapfuse --source /data/captures --mount /tmp/fuse --filter "2024-03-*.pcap"
```

### Cache the index for faster re-mounts

```bash
pcapfuse --source /data/captures --mount /tmp/fuse --cache /tmp/captures.idx
```

On the first mount, the index is built by scanning every packet header in every source file, then serialized to the cache path. On subsequent mounts, pcapfuse loads the cache and validates it by checking each source file's mtime and size. If any file changed, the cache is rebuilt automatically.

### Custom virtual filename

```bash
pcapfuse --source ./pcaps --mount /tmp/fuse --name incident-2024.pcapng
```

### All CLI flags

| Flag | Short | Description | Default |
|------|-------|-------------|---------|
| `--source` | `-s` | Directory (or single file) of pcap/pcapng sources | required |
| `--mount` | `-m` | Mountpoint directory (must exist, should be empty) | required |
| `--cache` | `-c` | Path to store/load serialized index | none (index rebuilt each mount) |
| `--name` | `-n` | Virtual filename inside the mountpoint | `merged.pcapng` |
| `--recursive` | `-r` | Recurse into subdirectories of `--source` | off |
| `--filter` | `-f` | Glob pattern to select source files | none (all .pcap/.pcapng/.cap) |

### Makefile shortcuts

From the `pcapfuse/` directory:

```bash
make mount SOURCE=../pcaps MOUNT=/tmp/fuse EXTRA="--recursive"
make unmount MOUNT=/tmp/fuse
make validate SOURCE=../pcaps MOUNT=/tmp/fuse    # tshark integration test suite
make all                                          # fmt + lint + test + build
```

### Logging

pcapfuse uses `env_logger`. Control verbosity with `RUST_LOG`:

```bash
RUST_LOG=debug pcapfuse --source ./pcaps --mount /tmp/fuse   # everything
RUST_LOG=warn  pcapfuse --source ./pcaps --mount /tmp/fuse   # quiet (errors + warnings only)
RUST_LOG=pcapfuse=debug pcapfuse ...                         # debug only for pcapfuse, not fuser
```

## Troubleshooting

### Checking if pcapfuse is already mounted

```bash
mount | grep pcapfuse
# or, cleaner:
findmnt -t fuse -o TARGET,SOURCE,FSTYPE | grep pcapfuse
# or list all FUSE mounts:
findmnt -t fuse
```

To unmount: `fusermount -u /path/to/mountpoint`

### "FUSE mount error: fusermount3: option allow_other only allowed..."

pcapfuse does not require `allow_other`. If you see this, something else is passing that option. The default configuration mounts with owner-only access, which is correct for typical use.

### "Transport endpoint is not connected" when accessing mountpoint

The pcapfuse process crashed or was killed without unmounting. Fix:

```bash
fusermount -u /tmp/fuse
```

### "mountpoint is not empty"

FUSE will refuse to mount over a non-empty directory. Use an empty directory, or remove the contents first.

### tshark shows 0 packets or garbled output

Run with `RUST_LOG=debug` and look for "Skipping" messages — pcapfuse silently skips files it can't parse (corrupt headers, truncated files, unknown magic bytes). Check that your source files are valid:

```bash
capinfos /path/to/suspect.pcap
```

### Slow mount with thousands of files

The bottleneck is reading every packet header in every source file. Use `--cache` to avoid repeating this on subsequent mounts:

```bash
pcapfuse --source /data/big-corpus --mount /tmp/fuse --cache /data/big-corpus.idx
```

The cache is invalidated automatically if any source file's mtime or size changes.

### Mount works but Wireshark shows wrong packet count

Confirm by comparing against mergecap:

```bash
mergecap -w /tmp/baseline.pcapng /path/to/pcaps/*.pcap
capinfos /tmp/baseline.pcapng                        # expected count
tshark -r /tmp/fuse/merged.pcapng 2>/dev/null | wc -l  # pcapfuse count
```

If counts differ, file a bug with the source files that reproduce the discrepancy.

## Design

### Architecture overview

pcapfuse operates in two phases:

**Mount-time indexing.** Scan every source file, parse packet record headers (not payload data), and build an in-memory index. The index records each packet's timestamp, source file, byte offset within the source, capture length, and assigned position in the virtual merged file.

**Read-time serving.** When Wireshark calls `read(offset, size)`, pcapfuse binary-searches the index to find which packets overlap the requested byte range, constructs pcapng Enhanced Packet Blocks on the fly, reads payload bytes from the relevant source files, and returns the assembled data. No full copy of the merged file exists anywhere.

```
source files ──scan──> MergedIndex ──FUSE read()──> synthetic pcapng bytes ──> Wireshark
                           │
                     (optional cache)
```

### Source modules

```
src/
  main.rs           CLI parsing, source enumeration, mount orchestration
  error.rs          Error enum (thiserror)
  pcap_reader.rs    Parses legacy pcap and pcapng source files
  index.rs          Builds the MergedIndex: IDB dedup, timestamp sort, offset layout
  pcapng_writer.rs  Constructs synthetic pcapng blocks (SHB, IDB, EPB)
  cache.rs          Serializes/deserializes the index to disk (serde + bincode)
  fs.rs             FUSE filesystem implementation (fuser::Filesystem trait)
```

### Key data structures

**`MergedIndex`** (defined in `index.rs`) is the central structure, built once at mount time and shared immutably across all FUSE read calls:

- `source_files: Vec<SourceFile>` — metadata for each input file (path, mtime, size, format, interfaces)
- `idb_table: Vec<(u16, u32)>` — deduplicated (link_type, snap_len) pairs, one per virtual interface
- `packets: Vec<PacketEntry>` — every packet across all sources, sorted by timestamp, with pre-computed virtual offsets
- `header_bytes: Vec<u8>` — pre-built pcapng Section Header Block + Interface Description Blocks
- `total_virtual_size: u64` — what `stat()` returns as the file size

**`PacketEntry`** maps a position in the virtual file back to a position in a source file:

| Field | Purpose |
|-------|---------|
| `timestamp_ns` | Nanosecond timestamp (common unit for sorting) |
| `source_file_id` | Which source file this packet came from |
| `source_interface_idx` | Interface index within that source file |
| `source_offset` | Byte offset of the packet record in the source file |
| `capture_len` / `original_len` | Packet lengths |
| `virtual_offset` | Byte offset in the virtual merged file |
| `virtual_len` | Total EPB block size (32 + pad4(capture_len)) |

### Virtual file layout

```
┌─────────────────────────────────────────────────────────────────┐
│ SHB (28 bytes)                                                  │
├─────────────────────────────────────────────────────────────────┤
│ IDB #0 (20 bytes)                                               │
│ IDB #1 (20 bytes)  ← one per unique (link_type, snap_len) pair │
│ ...                                                             │
├─────────────────────────────────────────────────────────────────┤
│ EPB: [hdr 28B] [packet data, padded to 4B] [trailer 4B]        │
│ EPB: [hdr 28B] [packet data, padded to 4B] [trailer 4B]        │
│ ...  ← packets in timestamp order across all source files       │
└─────────────────────────────────────────────────────────────────┘
```

### Read path (the hot path)

`fs.rs:do_read(offset, size)` handles every FUSE read call:

1. Clamp the request to `[offset, min(offset+size, total_virtual_size))`.
2. If the range overlaps the header region, copy pre-built header bytes.
3. Binary search (`partition_point`) to find the first packet whose virtual range overlaps the request.
4. For each overlapping packet, construct a fresh EPB on the fly:
   - **Header** (28 bytes): block type, block length, interface ID (remapped to virtual IDB), timestamp (converted to microseconds), capture/original lengths.
   - **Data** (pad4(capture_len) bytes): read from the source file at the packet's source offset, zero-padded to 4-byte alignment.
   - **Trailer** (4 bytes): block total length repeated.
5. `copy_overlap()` handles partial reads — only the bytes that fall within the requested range are copied into the output buffer.

EPB headers are always constructed fresh from indexed metadata, never copied from source files. This means legacy pcap and pcapng sources are handled identically — the virtual file is always valid pcapng regardless of input format.

### Format support

| Format | Detection | Timestamps | Notes |
|--------|-----------|------------|-------|
| Legacy pcap (little-endian) | Magic `0xA1B2C3D4` | microseconds → nanoseconds | Single interface per file |
| Legacy pcap (big-endian) | Magic `0xD4C3B2A1` | microseconds → nanoseconds | Single interface per file |
| Legacy pcap nanosecond (LE) | Magic `0xA1B23C4D` | nanoseconds native | Single interface per file |
| Legacy pcap nanosecond (BE) | Magic `0x4D3CB2A1` | nanoseconds native | Single interface per file |
| pcapng | SHB magic `0x0A0D0D0A` | per-interface `if_tsresol` option | Multiple interfaces, multiple sections |

All timestamps are normalized to nanoseconds at index time for correct cross-file sorting.

### IDB deduplication

Different source files may define different capture interfaces. pcapfuse collects all (link_type, snap_len) pairs across all source interfaces, deduplicates them, and assigns each unique pair a virtual IDB index. Each packet's EPB is written with the remapped interface ID so the virtual file has a single coherent IDB table.

### Threading model

The `MergedIndex` is immutable after construction and shared via `Arc`. FUSE read calls are handled by the fuser library's thread pool. Each read opens the relevant source file, reads payload bytes, and closes it. There is no shared mutable state and no locking. The OS page cache handles repeated reads of the same source regions efficiently.

### What pcapfuse does NOT do

- **Write or capture.** The virtual file is strictly read-only.
- **Filter or dissect packets.** That's Wireshark's job.
- **Modify Wireshark.** pcapfuse is a standard FUSE filesystem; any program that reads files can use it.

## License

GPL-2.0-or-later (compatible with Wireshark's license).
