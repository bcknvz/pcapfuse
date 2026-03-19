use crate::error::Result;
use crate::pcap_reader::{self, RawPacketMeta};
use crate::pcapng_writer;
use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use std::time::SystemTime;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum SourceFormat {
    Pcap {
        snaplen: u32,
        linktype: u16,
        big_endian: bool,
        nanosecond_ts: bool,
    },
    Pcapng,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SourceInterface {
    pub link_type: u16,
    pub snap_len: u32,
    pub virtual_idb_index: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SourceFile {
    pub id: u16,
    pub path: PathBuf,
    pub mtime: SystemTime,
    pub size: u64,
    pub format: SourceFormat,
    pub interfaces: Vec<SourceInterface>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PacketEntry {
    pub timestamp_ns: u64,
    pub source_file_id: u16,
    pub source_interface_idx: u8,
    pub source_offset: u64,
    pub capture_len: u32,
    pub original_len: u32,
    pub virtual_offset: u64,
    pub virtual_len: u32,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct MergedIndex {
    pub source_files: Vec<SourceFile>,
    pub idb_table: Vec<(u16, u32)>, // deduplicated (link_type, snap_len) pairs
    pub packets: Vec<PacketEntry>,
    pub header_bytes: Vec<u8>,
    pub total_virtual_size: u64,
}

/// Pad a length up to the next multiple of 4.
pub fn pad4(len: u32) -> u32 {
    (len + 3) & !3
}

/// Compute the total EPB block size for a given capture length.
pub fn epb_block_size(capture_len: u32) -> u32 {
    // EPB: block_type(4) + block_len(4) + interface_id(4) + ts_high(4) + ts_low(4)
    //      + caplen(4) + origlen(4) + data(pad4(caplen)) + block_len(4)
    32 + pad4(capture_len)
}

/// Build the merged index from a list of source file paths.
pub fn build_index(paths: &[PathBuf]) -> Result<MergedIndex> {
    let mut source_files: Vec<SourceFile> = Vec::new();
    let mut all_packets: Vec<(u16, RawPacketMeta)> = Vec::new(); // (file_id, meta)

    // Phase 1: Scan all source files
    for (i, path) in paths.iter().enumerate() {
        let file_id = i as u16;
        log::info!("Scanning [{}/{}]: {}", i + 1, paths.len(), path.display());

        match pcap_reader::scan_file(path, file_id) {
            Ok((sf, packets)) => {
                log::info!("  {} packets found", packets.len());
                for pkt in packets {
                    all_packets.push((file_id, pkt));
                }
                source_files.push(sf);
            }
            Err(e) => {
                log::warn!("Skipping {}: {}", path.display(), e);
            }
        }
    }

    // Phase 2: IDB deduplication
    let mut idb_table: Vec<(u16, u32)> = Vec::new();
    for sf in &mut source_files {
        for iface in &mut sf.interfaces {
            let key = (iface.link_type, iface.snap_len);
            let idx = match idb_table.iter().position(|entry| *entry == key) {
                Some(pos) => pos as u32,
                None => {
                    let pos = idb_table.len() as u32;
                    idb_table.push(key);
                    pos
                }
            };
            iface.virtual_idb_index = idx;
        }
    }

    // Phase 3: Build synthetic header
    let header_bytes = pcapng_writer::build_header(&idb_table);

    // Phase 4: Sort packets by timestamp and assign virtual offsets
    all_packets.sort_by_key(|(_, pkt)| pkt.timestamp_ns);

    let mut packets: Vec<PacketEntry> = Vec::with_capacity(all_packets.len());
    let mut virtual_offset = header_bytes.len() as u64;

    for (file_id, raw) in &all_packets {
        let vlen = epb_block_size(raw.capture_len);

        packets.push(PacketEntry {
            timestamp_ns: raw.timestamp_ns,
            source_file_id: *file_id,
            source_interface_idx: raw.interface_idx,
            source_offset: raw.file_offset,
            capture_len: raw.capture_len,
            original_len: raw.original_len,
            virtual_offset,
            virtual_len: vlen,
        });

        virtual_offset += vlen as u64;
    }

    let total_virtual_size = virtual_offset;

    log::info!(
        "Index built: {} files, {} interfaces, {} packets, {} bytes virtual size",
        source_files.len(),
        idb_table.len(),
        packets.len(),
        total_virtual_size
    );

    Ok(MergedIndex {
        source_files,
        idb_table,
        packets,
        header_bytes,
        total_virtual_size,
    })
}

impl MergedIndex {
    /// Get the SourceFile for a given file_id.
    pub fn source_file(&self, file_id: u16) -> Option<&SourceFile> {
        self.source_files.iter().find(|sf| sf.id == file_id)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pad4() {
        assert_eq!(pad4(0), 0);
        assert_eq!(pad4(1), 4);
        assert_eq!(pad4(2), 4);
        assert_eq!(pad4(3), 4);
        assert_eq!(pad4(4), 4);
        assert_eq!(pad4(5), 8);
        assert_eq!(pad4(100), 100);
        assert_eq!(pad4(101), 104);
    }

    #[test]
    fn test_epb_block_size() {
        assert_eq!(epb_block_size(0), 32);
        assert_eq!(epb_block_size(1), 36);
        assert_eq!(epb_block_size(4), 36);
        assert_eq!(epb_block_size(5), 40);
        assert_eq!(epb_block_size(100), 132);
    }
}
