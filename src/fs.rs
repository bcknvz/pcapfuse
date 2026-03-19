use crate::index::{self, MergedIndex, PacketEntry};
use crate::pcap_reader;
use crate::pcapng_writer;
use fuser::{
    Errno, FileAttr, FileHandle, FileType, Filesystem, FopenFlags, INodeNo, OpenFlags, ReplyAttr,
    ReplyData, ReplyDirectory, ReplyEmpty, ReplyEntry, ReplyOpen, Request,
};
use std::ffi::OsStr;
use std::sync::Arc;
use std::time::{Duration, UNIX_EPOCH};

const ROOT_INO: INodeNo = INodeNo(1);
const FILE_INO: INodeNo = INodeNo(2);
const TTL: Duration = Duration::from_secs(3600);

pub struct PcapFuseFs {
    index: Arc<MergedIndex>,
    filename: String,
}

impl PcapFuseFs {
    pub fn new(index: Arc<MergedIndex>, filename: String) -> Self {
        Self { index, filename }
    }

    fn root_attr(&self) -> FileAttr {
        FileAttr {
            ino: ROOT_INO,
            size: 0,
            blocks: 0,
            atime: UNIX_EPOCH,
            mtime: UNIX_EPOCH,
            ctime: UNIX_EPOCH,
            crtime: UNIX_EPOCH,
            kind: FileType::Directory,
            perm: 0o555,
            nlink: 2,
            uid: unsafe { libc::getuid() },
            gid: unsafe { libc::getgid() },
            rdev: 0,
            blksize: 4096,
            flags: 0,
        }
    }

    fn file_attr(&self) -> FileAttr {
        FileAttr {
            ino: FILE_INO,
            size: self.index.total_virtual_size,
            blocks: self.index.total_virtual_size.div_ceil(512),
            atime: UNIX_EPOCH,
            mtime: UNIX_EPOCH,
            ctime: UNIX_EPOCH,
            crtime: UNIX_EPOCH,
            kind: FileType::RegularFile,
            perm: 0o444,
            nlink: 1,
            uid: unsafe { libc::getuid() },
            gid: unsafe { libc::getgid() },
            rdev: 0,
            blksize: 4096,
            flags: 0,
        }
    }

    /// Serve a read request for the virtual file.
    fn do_read(&self, offset: u64, size: u32) -> Vec<u8> {
        let total = self.index.total_virtual_size;
        if offset >= total {
            return Vec::new();
        }

        let end = std::cmp::min(offset + size as u64, total);
        let buf_len = (end - offset) as usize;
        let mut buf = vec![0u8; buf_len];

        let header_len = self.index.header_bytes.len() as u64;

        // Region 1: Header bytes
        if offset < header_len {
            let hdr_start = offset as usize;
            let hdr_end = std::cmp::min(header_len, end) as usize;
            let dst_end = hdr_end - hdr_start;
            buf[0..dst_end].copy_from_slice(&self.index.header_bytes[hdr_start..hdr_end]);
        }

        // Region 2: Packet data
        if end > header_len {
            let search_offset = std::cmp::max(offset, header_len);
            let first_idx = self
                .index
                .packets
                .partition_point(|p| p.virtual_offset + p.virtual_len as u64 <= search_offset);

            for pkt in &self.index.packets[first_idx..] {
                if pkt.virtual_offset >= end {
                    break;
                }
                self.serve_epb(pkt, offset, &mut buf);
            }
        }

        buf
    }

    /// Serve the bytes of a single EPB into the output buffer.
    fn serve_epb(&self, pkt: &PacketEntry, read_offset: u64, buf: &mut [u8]) {
        let vo = pkt.virtual_offset;
        let read_end = read_offset + buf.len() as u64;
        let padded_data_len = index::pad4(pkt.capture_len);

        let virtual_idb_index = self
            .index
            .source_file(pkt.source_file_id)
            .and_then(|sf| sf.interfaces.get(pkt.source_interface_idx as usize))
            .map(|iface| iface.virtual_idb_index)
            .unwrap_or(0);

        // Sub-region 1: EPB header [vo, vo+28)
        let hdr_end = vo + 28;
        if read_offset < hdr_end && read_end > vo {
            let epb_hdr = pcapng_writer::build_epb_header(
                virtual_idb_index,
                pkt.timestamp_ns,
                pkt.capture_len,
                pkt.original_len,
                pkt.virtual_len,
            );
            copy_overlap(&epb_hdr, vo, read_offset, buf);
        }

        // Sub-region 2: Packet data [vo+28, vo+28+pad4(caplen))
        let data_start = vo + 28;
        let data_end = data_start + padded_data_len as u64;
        if read_offset < data_end && read_end > data_start {
            if let Some(sf) = self.index.source_file(pkt.source_file_id) {
                match pcap_reader::read_packet_payload(
                    &sf.path,
                    pkt.source_offset,
                    pkt.capture_len,
                    &sf.format,
                ) {
                    Ok(payload) => {
                        let mut padded = payload;
                        padded.resize(padded_data_len as usize, 0);
                        copy_overlap(&padded, data_start, read_offset, buf);
                    }
                    Err(e) => {
                        log::error!("Failed to read packet payload: {}", e);
                    }
                }
            }
        }

        // Sub-region 3: EPB trailer [data_end, vo+virtual_len)
        let trailer_start = data_end;
        let trailer_end = vo + pkt.virtual_len as u64;
        if read_offset < trailer_end && read_end > trailer_start {
            let trailer = pcapng_writer::build_epb_trailer(pkt.virtual_len);
            copy_overlap(&trailer, trailer_start, read_offset, buf);
        }
    }
}

/// Copy the overlapping portion of `src` (at `src_vo` in virtual space)
/// into `buf` (at `buf_vo` in virtual space).
fn copy_overlap(src: &[u8], src_vo: u64, buf_vo: u64, buf: &mut [u8]) {
    let src_end = src_vo + src.len() as u64;
    let buf_end = buf_vo + buf.len() as u64;

    let start = std::cmp::max(src_vo, buf_vo);
    let end = std::cmp::min(src_end, buf_end);

    if start >= end {
        return;
    }

    let s = (start - src_vo) as usize;
    let b = (start - buf_vo) as usize;
    let len = (end - start) as usize;
    buf[b..b + len].copy_from_slice(&src[s..s + len]);
}

impl Filesystem for PcapFuseFs {
    fn lookup(&self, _req: &Request, parent: INodeNo, name: &OsStr, reply: ReplyEntry) {
        if parent == ROOT_INO && name.to_str() == Some(&self.filename) {
            reply.entry(&TTL, &self.file_attr(), fuser::Generation(0));
        } else {
            reply.error(Errno::ENOENT);
        }
    }

    fn getattr(&self, _req: &Request, ino: INodeNo, _fh: Option<FileHandle>, reply: ReplyAttr) {
        match ino {
            ROOT_INO => reply.attr(&TTL, &self.root_attr()),
            FILE_INO => reply.attr(&TTL, &self.file_attr()),
            _ => reply.error(Errno::ENOENT),
        }
    }

    fn readdir(
        &self,
        _req: &Request,
        ino: INodeNo,
        _fh: FileHandle,
        offset: u64,
        mut reply: ReplyDirectory,
    ) {
        if ino != ROOT_INO {
            reply.error(Errno::ENOENT);
            return;
        }

        let entries: Vec<(INodeNo, FileType, &str)> = vec![
            (ROOT_INO, FileType::Directory, "."),
            (ROOT_INO, FileType::Directory, ".."),
            (FILE_INO, FileType::RegularFile, &self.filename),
        ];

        for (i, (ino, kind, name)) in entries.into_iter().enumerate().skip(offset as usize) {
            if reply.add(ino, (i + 1) as u64, kind, name) {
                break;
            }
        }
        reply.ok();
    }

    fn open(&self, _req: &Request, ino: INodeNo, _flags: OpenFlags, reply: ReplyOpen) {
        if ino != FILE_INO {
            reply.error(Errno::ENOENT);
            return;
        }
        reply.opened(FileHandle(0), FopenFlags::FOPEN_KEEP_CACHE);
    }

    fn read(
        &self,
        _req: &Request,
        ino: INodeNo,
        _fh: FileHandle,
        offset: u64,
        size: u32,
        _flags: OpenFlags,
        _lock_owner: Option<fuser::LockOwner>,
        reply: ReplyData,
    ) {
        if ino != FILE_INO {
            reply.error(Errno::ENOENT);
            return;
        }
        let data = self.do_read(offset, size);
        reply.data(&data);
    }

    fn release(
        &self,
        _req: &Request,
        _ino: INodeNo,
        _fh: FileHandle,
        _flags: OpenFlags,
        _lock_owner: Option<fuser::LockOwner>,
        _flush: bool,
        reply: ReplyEmpty,
    ) {
        reply.ok();
    }
}
