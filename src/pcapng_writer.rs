/// Build the synthetic pcapng header: SHB + IDBs.
pub fn build_header(idb_table: &[(u16, u32)]) -> Vec<u8> {
    let mut buf = Vec::new();

    // Section Header Block (SHB)
    // Block type
    buf.extend_from_slice(&0x0A0D_0D0Au32.to_le_bytes());
    // Block total length: 28 bytes (minimum SHB with no options)
    buf.extend_from_slice(&28u32.to_le_bytes());
    // Byte-order magic
    buf.extend_from_slice(&0x1A2B_3C4Du32.to_le_bytes());
    // Version major.minor
    buf.extend_from_slice(&1u16.to_le_bytes());
    buf.extend_from_slice(&0u16.to_le_bytes());
    // Section length: -1 (unspecified)
    buf.extend_from_slice(&(-1i64).to_le_bytes());
    // Block total length (trailer)
    buf.extend_from_slice(&28u32.to_le_bytes());

    // Interface Description Blocks
    for &(link_type, snap_len) in idb_table {
        // IDB: 20 bytes minimum (no options)
        let idb_len: u32 = 20;
        // Block type
        buf.extend_from_slice(&0x0000_0001u32.to_le_bytes());
        // Block total length
        buf.extend_from_slice(&idb_len.to_le_bytes());
        // Link type
        buf.extend_from_slice(&link_type.to_le_bytes());
        // Reserved (2 bytes) + snap_len
        buf.extend_from_slice(&0u16.to_le_bytes());
        buf.extend_from_slice(&snap_len.to_le_bytes());
        // Block total length (trailer)
        buf.extend_from_slice(&idb_len.to_le_bytes());
    }

    buf
}

/// Build an EPB header (first 28 bytes of an EPB block, before packet data).
pub fn build_epb_header(
    virtual_idb_index: u32,
    timestamp_ns: u64,
    capture_len: u32,
    original_len: u32,
    block_total_len: u32,
) -> [u8; 28] {
    let mut buf = [0u8; 28];

    // Block type: Enhanced Packet Block
    buf[0..4].copy_from_slice(&0x0000_0006u32.to_le_bytes());
    // Block total length
    buf[4..8].copy_from_slice(&block_total_len.to_le_bytes());
    // Interface ID
    buf[8..12].copy_from_slice(&virtual_idb_index.to_le_bytes());

    // Timestamp: convert nanoseconds to microseconds (default pcapng resolution)
    let ts_us = timestamp_ns / 1_000;
    let ts_high = (ts_us >> 32) as u32;
    let ts_low = ts_us as u32;
    buf[12..16].copy_from_slice(&ts_high.to_le_bytes());
    buf[16..20].copy_from_slice(&ts_low.to_le_bytes());

    // Captured length
    buf[20..24].copy_from_slice(&capture_len.to_le_bytes());
    // Original length
    buf[24..28].copy_from_slice(&original_len.to_le_bytes());

    buf
}

/// Build an EPB trailing block total length (4 bytes).
pub fn build_epb_trailer(block_total_len: u32) -> [u8; 4] {
    block_total_len.to_le_bytes()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_shb_header_size() {
        let header = build_header(&[]);
        assert_eq!(header.len(), 28); // just SHB, no IDBs
    }

    #[test]
    fn test_shb_plus_idbs() {
        let header = build_header(&[(1, 65535), (6, 262144)]);
        // SHB (28) + 2 * IDB (20 each) = 68
        assert_eq!(header.len(), 68);
    }

    #[test]
    fn test_epb_header_block_type() {
        let hdr = build_epb_header(0, 0, 100, 100, 136);
        assert_eq!(
            u32::from_le_bytes(hdr[0..4].try_into().unwrap()),
            0x00000006
        );
    }

    #[test]
    fn test_epb_header_fields() {
        let hdr = build_epb_header(2, 1_500_000_000_000, 64, 128, 96);
        // Interface ID
        assert_eq!(u32::from_le_bytes(hdr[8..12].try_into().unwrap()), 2);
        // Capture len
        assert_eq!(u32::from_le_bytes(hdr[20..24].try_into().unwrap()), 64);
        // Original len
        assert_eq!(u32::from_le_bytes(hdr[24..28].try_into().unwrap()), 128);
    }
}
