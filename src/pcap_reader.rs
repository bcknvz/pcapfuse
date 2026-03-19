use crate::error::{Error, Result};
use crate::index::{SourceFile, SourceFormat, SourceInterface};
use std::fs::File;
use std::io::{BufReader, Read, Seek, SeekFrom};
use std::path::Path;

/// Metadata extracted from a single packet record during scanning.
pub struct RawPacketMeta {
    pub timestamp_ns: u64,
    pub interface_idx: u8,
    pub file_offset: u64,
    pub capture_len: u32,
    pub original_len: u32,
}

/// Magic numbers for format detection.
const PCAP_MAGIC_LE: u32 = 0xA1B2_C3D4;
const PCAP_MAGIC_BE: u32 = 0xD4C3_B2A1;
const PCAP_MAGIC_NS_LE: u32 = 0xA1B2_3C4D;
const PCAP_MAGIC_NS_BE: u32 = 0x4D3C_B2A1;
const PCAPNG_SHB_MAGIC: u32 = 0x0A0D_0D0A;

/// Scan a source file, returning its metadata and all packet records.
pub fn scan_file(path: &Path, file_id: u16) -> Result<(SourceFile, Vec<RawPacketMeta>)> {
    let mut f = BufReader::new(File::open(path).map_err(Error::Io)?);

    let meta = std::fs::metadata(path)?;
    let mtime = meta.modified().unwrap_or(std::time::UNIX_EPOCH);
    let size = meta.len();

    let mut magic_buf = [0u8; 4];
    f.read_exact(&mut magic_buf).map_err(|_| Error::Parse {
        path: path.to_path_buf(),
        reason: "file too short to read magic".into(),
    })?;
    let magic = u32::from_le_bytes(magic_buf);

    f.seek(SeekFrom::Start(0))?;

    match magic {
        PCAP_MAGIC_LE | PCAP_MAGIC_NS_LE => {
            let nano = magic == PCAP_MAGIC_NS_LE;
            scan_pcap_le(path, file_id, mtime, size, &mut f, nano)
        }
        PCAP_MAGIC_BE | PCAP_MAGIC_NS_BE => {
            let nano = magic == PCAP_MAGIC_NS_BE;
            scan_pcap_be(path, file_id, mtime, size, &mut f, nano)
        }
        PCAPNG_SHB_MAGIC => scan_pcapng(path, file_id, mtime, size, &mut f),
        _ => Err(Error::UnsupportedFormat {
            path: path.to_path_buf(),
            reason: format!("unknown magic: 0x{:08X}", magic),
        }),
    }
}

fn scan_pcap_le(
    path: &Path,
    file_id: u16,
    mtime: std::time::SystemTime,
    size: u64,
    f: &mut BufReader<File>,
    nanosecond_ts: bool,
) -> Result<(SourceFile, Vec<RawPacketMeta>)> {
    let mut hdr = [0u8; 24];
    f.read_exact(&mut hdr).map_err(|_| Error::Parse {
        path: path.to_path_buf(),
        reason: "truncated pcap header".into(),
    })?;

    let snaplen = u32::from_le_bytes(hdr[16..20].try_into().unwrap());
    let linktype = u32::from_le_bytes(hdr[20..24].try_into().unwrap()) as u16;

    let source_file = SourceFile {
        id: file_id,
        path: path.to_path_buf(),
        mtime,
        size,
        format: SourceFormat::Pcap {
            snaplen,
            linktype,
            big_endian: false,
            nanosecond_ts,
        },
        interfaces: vec![SourceInterface {
            link_type: linktype,
            snap_len: snaplen,
            virtual_idb_index: 0, // assigned later
        }],
    };

    let mut packets = Vec::new();
    let mut pos: u64 = 24;

    loop {
        let mut pkt_hdr = [0u8; 16];
        match f.read_exact(&mut pkt_hdr) {
            Ok(()) => {}
            Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => break,
            Err(e) => return Err(Error::Io(e)),
        }

        let ts_sec = u32::from_le_bytes(pkt_hdr[0..4].try_into().unwrap()) as u64;
        let ts_frac = u32::from_le_bytes(pkt_hdr[4..8].try_into().unwrap()) as u64;
        let caplen = u32::from_le_bytes(pkt_hdr[8..12].try_into().unwrap());
        let origlen = u32::from_le_bytes(pkt_hdr[12..16].try_into().unwrap());

        let timestamp_ns = if nanosecond_ts {
            ts_sec * 1_000_000_000 + ts_frac
        } else {
            ts_sec * 1_000_000_000 + ts_frac * 1_000
        };

        packets.push(RawPacketMeta {
            timestamp_ns,
            interface_idx: 0,
            file_offset: pos,
            capture_len: caplen,
            original_len: origlen,
        });

        pos += 16 + caplen as u64;
        f.seek(SeekFrom::Start(pos))?;
    }

    Ok((source_file, packets))
}

fn scan_pcap_be(
    path: &Path,
    file_id: u16,
    mtime: std::time::SystemTime,
    size: u64,
    f: &mut BufReader<File>,
    nanosecond_ts: bool,
) -> Result<(SourceFile, Vec<RawPacketMeta>)> {
    let mut hdr = [0u8; 24];
    f.read_exact(&mut hdr).map_err(|_| Error::Parse {
        path: path.to_path_buf(),
        reason: "truncated pcap header".into(),
    })?;

    let snaplen = u32::from_be_bytes(hdr[16..20].try_into().unwrap());
    let linktype = u32::from_be_bytes(hdr[20..24].try_into().unwrap()) as u16;

    let source_file = SourceFile {
        id: file_id,
        path: path.to_path_buf(),
        mtime,
        size,
        format: SourceFormat::Pcap {
            snaplen,
            linktype,
            big_endian: true,
            nanosecond_ts,
        },
        interfaces: vec![SourceInterface {
            link_type: linktype,
            snap_len: snaplen,
            virtual_idb_index: 0,
        }],
    };

    let mut packets = Vec::new();
    let mut pos: u64 = 24;

    loop {
        let mut pkt_hdr = [0u8; 16];
        match f.read_exact(&mut pkt_hdr) {
            Ok(()) => {}
            Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => break,
            Err(e) => return Err(Error::Io(e)),
        }

        let ts_sec = u32::from_be_bytes(pkt_hdr[0..4].try_into().unwrap()) as u64;
        let ts_frac = u32::from_be_bytes(pkt_hdr[4..8].try_into().unwrap()) as u64;
        let caplen = u32::from_be_bytes(pkt_hdr[8..12].try_into().unwrap());
        let origlen = u32::from_be_bytes(pkt_hdr[12..16].try_into().unwrap());

        let timestamp_ns = if nanosecond_ts {
            ts_sec * 1_000_000_000 + ts_frac
        } else {
            ts_sec * 1_000_000_000 + ts_frac * 1_000
        };

        packets.push(RawPacketMeta {
            timestamp_ns,
            interface_idx: 0,
            file_offset: pos,
            capture_len: caplen,
            original_len: origlen,
        });

        pos += 16 + caplen as u64;
        f.seek(SeekFrom::Start(pos))?;
    }

    Ok((source_file, packets))
}

fn scan_pcapng(
    path: &Path,
    file_id: u16,
    mtime: std::time::SystemTime,
    size: u64,
    f: &mut BufReader<File>,
) -> Result<(SourceFile, Vec<RawPacketMeta>)> {
    let file_data = {
        let mut data = Vec::new();
        f.seek(SeekFrom::Start(0))?;
        f.read_to_end(&mut data)?;
        data
    };

    let mut interfaces: Vec<SourceInterface> = Vec::new();
    let mut packets = Vec::new();
    // Track per-interface timestamp resolution (ticks per second)
    let mut if_ts_resol: Vec<u64> = Vec::new();

    let mut offset = 0usize;
    while offset + 8 <= file_data.len() {
        let block_type = u32::from_le_bytes(file_data[offset..offset + 4].try_into().unwrap());
        let block_len =
            u32::from_le_bytes(file_data[offset + 4..offset + 8].try_into().unwrap()) as usize;

        if block_len < 12 || offset + block_len > file_data.len() {
            break;
        }

        match block_type {
            0x0A0D_0D0A => {
                // Section Header Block — reset interfaces for this section
                interfaces.clear();
                if_ts_resol.clear();
            }
            0x0000_0001 => {
                // Interface Description Block
                if block_len >= 20 {
                    let link_type =
                        u16::from_le_bytes(file_data[offset + 8..offset + 10].try_into().unwrap());
                    let snap_len =
                        u32::from_le_bytes(file_data[offset + 12..offset + 16].try_into().unwrap());
                    interfaces.push(SourceInterface {
                        link_type,
                        snap_len,
                        virtual_idb_index: 0,
                    });

                    // Parse options to find if_tsresol
                    let mut ts_resol: u64 = 1_000_000; // default: microseconds
                    let opts_start = offset + 16;
                    let opts_end = offset + block_len - 4; // before trailing block length
                    let mut opos = opts_start;
                    while opos + 4 <= opts_end {
                        let opt_code =
                            u16::from_le_bytes(file_data[opos..opos + 2].try_into().unwrap());
                        let opt_len =
                            u16::from_le_bytes(file_data[opos + 2..opos + 4].try_into().unwrap())
                                as usize;
                        if opt_code == 0 {
                            break; // opt_endofopt
                        }
                        if opt_code == 9 && opt_len >= 1 {
                            // if_tsresol
                            let val = file_data[opos + 4];
                            if val & 0x80 != 0 {
                                // power of 2
                                let exp = (val & 0x7F) as u32;
                                ts_resol = 1u64 << exp;
                            } else {
                                // power of 10
                                ts_resol = 10u64.pow(val as u32);
                            }
                        }
                        opos += 4 + ((opt_len + 3) & !3); // pad to 4 bytes
                    }
                    if_ts_resol.push(ts_resol);
                }
            }
            0x0000_0006 => {
                // Enhanced Packet Block
                if block_len >= 32 {
                    let interface_id =
                        u32::from_le_bytes(file_data[offset + 8..offset + 12].try_into().unwrap());
                    let ts_high =
                        u32::from_le_bytes(file_data[offset + 12..offset + 16].try_into().unwrap())
                            as u64;
                    let ts_low =
                        u32::from_le_bytes(file_data[offset + 16..offset + 20].try_into().unwrap())
                            as u64;
                    let caplen =
                        u32::from_le_bytes(file_data[offset + 20..offset + 24].try_into().unwrap());
                    let origlen =
                        u32::from_le_bytes(file_data[offset + 24..offset + 28].try_into().unwrap());

                    let raw_ts = (ts_high << 32) | ts_low;

                    // Convert to nanoseconds using interface's timestamp resolution
                    let resol = if (interface_id as usize) < if_ts_resol.len() {
                        if_ts_resol[interface_id as usize]
                    } else {
                        1_000_000 // default microsecond
                    };

                    let timestamp_ns = if resol == 1_000_000_000 {
                        raw_ts
                    } else if resol == 1_000_000 {
                        raw_ts * 1_000
                    } else if resol > 1_000_000_000 {
                        raw_ts / (resol / 1_000_000_000)
                    } else {
                        raw_ts * (1_000_000_000 / resol)
                    };

                    let iface_idx = if (interface_id as usize) < interfaces.len() {
                        interface_id as u8
                    } else {
                        0
                    };

                    packets.push(RawPacketMeta {
                        timestamp_ns,
                        interface_idx: iface_idx,
                        file_offset: offset as u64,
                        capture_len: caplen,
                        original_len: origlen,
                    });
                }
            }
            _ => {} // skip other block types
        }

        offset += block_len;
    }

    let source_file = SourceFile {
        id: file_id,
        path: path.to_path_buf(),
        mtime,
        size,
        format: SourceFormat::Pcapng,
        interfaces,
    };

    Ok((source_file, packets))
}

/// Read packet payload bytes from a source file.
/// For legacy pcap: offset points to packet record start (16-byte header + data).
/// For pcapng: offset points to EPB block start (data at offset+28).
pub fn read_packet_payload(
    path: &Path,
    offset: u64,
    capture_len: u32,
    format: &SourceFormat,
) -> Result<Vec<u8>> {
    let mut f = File::open(path)?;

    let data_offset = match format {
        SourceFormat::Pcap { .. } => offset + 16, // skip 16-byte pcap record header
        SourceFormat::Pcapng => offset + 28,      // skip EPB header (28 bytes to data)
    };

    f.seek(SeekFrom::Start(data_offset))?;
    let mut buf = vec![0u8; capture_len as usize];
    f.read_exact(&mut buf).map_err(|_| Error::Parse {
        path: path.to_path_buf(),
        reason: format!(
            "failed to read {} bytes at offset {}",
            capture_len, data_offset
        ),
    })?;
    Ok(buf)
}
