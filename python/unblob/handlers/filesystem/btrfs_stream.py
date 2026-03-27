import enum
import io
import zlib
from pathlib import Path

from lzallright import LZOCompressor

from unblob.file_utils import (
    File,
    FileSystem,
    StructParser,
    iterate_file,
)
from unblob.models import (
    Extractor,
    ExtractResult,
    HandlerDoc,
    HandlerType,
    HexString,
    InvalidInputFormat,
    Reference,
    StructHandler,
    ValidChunk,
)
from unblob.report import ExtractionProblem

C_DEFINITIONS = """
typedef struct stream_header {
    char     magic[13];   // "btrfs-stream\0"
    uint32   version;
} stream_header_t;

typedef struct cmd_header {
    uint32 data_len;
    uint16 cmd_type;
    uint32 crc32; // use Castagnoli polynomial and the seed 0x0
} cmd_header_t;

typedef struct tlv_header_no_value {
    uint16 tlv_type;
    uint16 tlv_len;
} tlv_header_no_value_t;

typedef struct tlv_header {
    uint16 tlv_type;
    uint16 tlv_len;
    uint64 value;
} tlv_header_t;

typedef struct tlv_header_path {
    uint16 tlv_type;
    uint16 tlv_len;
    char value[tlv_len];
} tlv_header_path_t;

typedef struct timespec {
    uint64 sec;
    uint32 nsec;
} timespec_t;

typedef struct tlv_header_timespec {
    uint16 tlv_type;
    uint16 tlv_len;
    timespec_t value;
} tlv_header_timespec_t;

typedef struct tlv_header_uuid {
    uint16 tlv_type;
    uint16 tlv_len;
    char value[16];
} tlv_header_uuid_t;

typedef struct mk_cmd {
    tlv_header_path_t path;
    tlv_header_t ino;
} mk_cmd_t;

typedef struct symlink_cmd {
    tlv_header_path_t path;
    tlv_header_t ino;
    tlv_header_path_t path_link;
} symlink_cmd_t;

typedef struct rename_cmd {
    tlv_header_path_t path;
    tlv_header_path_t path_to;
} rename_cmd_t;

typedef struct link_cmd {
    tlv_header_path_t path;
    tlv_header_path_t link_to;
} link_cmd_t;

typedef struct truncate_cmd {
    tlv_header_path_t path;
    tlv_header_t size;
} truncate_cmd_t;

typedef struct mk_special_cmd { // MKNOD, MKSOCK, MKFIFO, in the documentation they don't have this structure
    tlv_header_path_t path;
    tlv_header_t      ino;
    tlv_header_t      rdev;
    tlv_header_t      mode;
} mk_special_cmd_t;

typedef struct rmdir_cmd {
    tlv_header_path_t path;
} rmdir_cmd_t;

typedef struct unlink_cmd {
    tlv_header_path_t path;
} unlink_cmd_t;

typedef struct write_cmd {
    tlv_header_path_t path;
    tlv_header_t offset;
} write_cmd_t;

typedef struct clone_cmd {
    tlv_header_path_t path;
    tlv_header_t offset;
    tlv_header_t clone_len;
    tlv_header_t clone_uuid;
    tlv_header_t clone_ctransid;
    tlv_header_path_t clone_path;
    tlv_header_t clone_offset;
} clone_cmd_t;

typedef struct subvol_cmd {
    tlv_header_path_t   path;
    tlv_header_uuid_t   uuid;
    tlv_header_t        ctransid;
} subvol_cmd_t;

typedef struct snapshot_cmd {
    tlv_header_path_t   path;
    tlv_header_uuid_t   uuid;
    tlv_header_t        ctransid;
    tlv_header_uuid_t   clone_uuid;
    tlv_header_t        clone_ctransid;
} snapshot_cmd_t;

typedef struct chmod_cmd {
    tlv_header_path_t   path;
    tlv_header_t        mode;
} chmod_cmd_t;

typedef struct chown_cmd {
    tlv_header_path_t   path;
    tlv_header_t        uid;
    tlv_header_t        gid;
} chown_cmd_t;

typedef struct utimes_cmd {
    tlv_header_path_t       path;
    tlv_header_timespec_t   atime;
    tlv_header_timespec_t   mtime;
    tlv_header_timespec_t   ctime;
} utimes_cmd_t;

typedef struct set_xattr_cmd {
    tlv_header_path_t   path;
    tlv_header_path_t   xattr_name;
    tlv_header_path_t   xattr_data;
} set_xattr_cmd_t;

typedef struct remove_xattr_cmd {
    tlv_header_path_t   path;
    tlv_header_path_t   xattr_name;
} remove_xattr_cmd_t;

typedef struct update_extent_cmd {
    tlv_header_path_t   path;
    tlv_header_t        file_offset;
    tlv_header_t        size;
} update_extent_cmd_t;


typedef struct fallocate_cmd {
    tlv_header_path_t   path;
    tlv_header_t        fallocate_mode;
    tlv_header_t        file_offset;
    tlv_header_t        size;
} fallocate_cmd_t;

typedef struct fileattr_cmd {
    tlv_header_path_t   path;
    tlv_header_t        fileattr;
} fileattr_cmd_t;

typedef struct encoded_write_cmd {
    tlv_header_path_t   path;
    tlv_header_t        file_offset;
    tlv_header_t        unencoded_file_len;
    tlv_header_t        unencoded_len;
    tlv_header_t        unencoded_offset;
    tlv_header_t        compression;
    tlv_header_t        encryption; // not implemented yet by btrfs send stream
    // DATA has no tlv_len in v2 — length is implicit (cmd.data_len - bytes consumed so far)
} encoded_write_cmd_t;

"""

STREAM_HEADER_LEN = 17


def makecr32ctable():
    table = []
    for i in range(256):
        crc = i
        for _ in range(8):
            if crc & 1:
                crc = (
                    crc >> 1
                ) ^ 0x82F63B78  # Castagnoli reversed polynomial (little-endian)
            else:
                crc >>= 1
        table.append(crc)
    return table


CRC32CTABLE = makecr32ctable()


class CmdType(enum.IntEnum):
    UNSPEC = 0
    SUBVOL = 1
    SNAPSHOT = 2
    MKFILE = 3
    MKDIR = 4
    MKNOD = 5
    MKFIFO = 6
    MKSOCK = 7
    SYMLINK = 8
    RENAME = 9
    LINK = 10
    UNLINK = 11
    RMDIR = 12
    SET_XATTR = 13
    REMOVE_XATTR = 14
    WRITE = 15
    CLONE = 16
    TRUNCATE = 17
    CHMOD = 18
    CHOWN = 19
    UTIMES = 20
    END = 21
    UPDATE_EXTENT = 22
    # V2 commands
    FALLOCATE = 23
    FILEATTR = 24
    ENCODED_WRITE = 25


class BTRFSParser:
    def __init__(self, file: File, start_offset: int):
        self._struct_parser = StructParser(C_DEFINITIONS)
        self.file = file
        self.start_offset = start_offset

    def calculate_crc32(self, data: bytes) -> int:
        crc = 0
        for byte in data:
            crc = (crc >> 8) ^ CRC32CTABLE[(crc ^ byte) & 0xFF]
        return crc

    def valid_crc32(self, file: File, cmd_header) -> bool:
        cmd_header_crc32 = cmd_header.crc32
        cmd_header.crc32 = 0x0
        return cmd_header_crc32 == self.calculate_crc32(
            cmd_header.dumps() + file.read(cmd_header.data_len)
        )

    def replay(self, fs: FileSystem) -> None:
        self.file.seek(self.start_offset + STREAM_HEADER_LEN, io.SEEK_SET)
        cmd_header = self._struct_parser.cparser_le.cmd_header_t(self.file)
        while cmd_header.cmd_type != CmdType.END:
            if not self.valid_crc32(self.file, cmd_header):
                fs.record_problem(
                    ExtractionProblem(
                        problem=f"Command type : {cmd_header.cmd_type} have an invalid checksum",
                        resolution="Skipped",
                    )
                )
            self.file.seek(-cmd_header.data_len, io.SEEK_CUR)
            self.replay_command(cmd_header, fs)
            cmd_header = self._struct_parser.cparser_le.cmd_header_t(self.file)

    def replay_command(self, cmd_header, fs: FileSystem) -> None:  # noqa : C901
        match CmdType(cmd_header.cmd_type):
            case CmdType.MKFILE:
                command = self._struct_parser.cparser_le.mk_cmd_t(self.file)
                path = Path(command.path.value.decode())
                fs.write_bytes(path, b"")
            case CmdType.MKDIR:
                command = self._struct_parser.cparser_le.mk_cmd_t(self.file)
                path = Path(command.path.value.decode())
                fs.mkdir(path, parents=True, exist_ok=True)
            case CmdType.MKNOD:
                command = self._struct_parser.cparser_le.mk_special_cmd_t(self.file)
                path = Path(command.path.value.decode())
                fs.mknod(path, mode=command.mode.value, device=command.rdev.value)
            case CmdType.MKFIFO:
                command = self._struct_parser.cparser_le.mk_special_cmd_t(self.file)
                fs.mkfifo(Path(command.path.value.decode()))
            case CmdType.MKSOCK:
                command = self._struct_parser.cparser_le.mk_special_cmd_t(self.file)
                fs.mknod(
                    Path(command.path.value.decode()),
                    mode=command.mode.value,
                )
            case CmdType.SYMLINK:
                command = self._struct_parser.cparser_le.symlink_cmd_t(self.file)
                fs.create_symlink(
                    src=Path(command.path_link.value.decode()),
                    dst=Path(command.path.value.decode()),
                )
            case CmdType.RENAME:
                command = self._struct_parser.cparser_le.rename_cmd_t(self.file)
                fs.rename(
                    src=Path(command.path.value.decode()),
                    dst=Path(command.path_to.value.decode()),
                )
            case CmdType.LINK:
                command = self._struct_parser.cparser_le.link_cmd_t(self.file)
                fs.create_hardlink(
                    src=Path(command.link_to.value.decode()),
                    dst=Path(command.path.value.decode()),
                )
            case CmdType.RMDIR:
                command = self._struct_parser.cparser_le.link_cmd_t(self.file)
                fs.rmdir(Path(command.path.value.decode()))
            case CmdType.UNLINK:
                command = self._struct_parser.cparser_le.link_cmd_t(self.file)
                fs.unlink(Path(command.path.value.decode()))
            case CmdType.SET_XATTR:
                command = self._struct_parser.cparser_le.set_xattr_cmd_t(self.file)
                path = Path(command.path.value.decode())
                name = command.xattr_name.value.decode()
                data = command.xattr_data.value
                fs.set_xattr(path, name, data)
            case CmdType.REMOVE_XATTR:
                command = self._struct_parser.cparser_le.remove_xattr_cmd_t(self.file)
                path = Path(command.path.value.decode())
                name = command.xattr_name.value.decode()
                fs.remove_xattr(path, name)
            case CmdType.WRITE:
                command = self._struct_parser.cparser_le.write_cmd_t(self.file)
                path = Path(command.path.value.decode())
                offset = command.offset.value
                # ok to handle this TLV this way, otherwise cstruct reads the whole data in ram
                tlv = self._struct_parser.cparser_le.tlv_header_no_value_t(self.file)
                with fs.open(path, "rb+") as f:
                    f.seek(offset)
                    for chunk in iterate_file(self.file, self.file.tell(), tlv.tlv_len):
                        f.write(chunk)
            case CmdType.CLONE:
                command = self._struct_parser.cparser_le.clone_cmd_t(self.file)
                path = Path(command.path.value.decode())
                offset = command.offset.value
                clone_len = command.clone_len.value
                clone_path = Path(command.clone_path.value.decode())
                clone_offset = command.clone_offset.value
                with File.from_path(clone_path) as src, fs.open(path, "rb+") as dst:
                    dst.seek(offset)
                    for chunk in iterate_file(src, clone_offset, clone_len):
                        dst.write(chunk)
            case CmdType.TRUNCATE:
                command = self._struct_parser.cparser_le.truncate_cmd_t(self.file)
                path = Path(command.path.value.decode())
                size = command.size.value
                fs.truncate(path, size)
            case CmdType.ENCODED_WRITE:
                command = self._struct_parser.cparser_le.encoded_write_cmd_t(self.file)
                path = Path(command.path.value.decode())
                offset = command.file_offset.value
                compression_type = command.compression.value
                tlv = self._struct_parser.cparser_le.tlv_header_no_value_t(self.file)
                data_offset = self.file.tell()
                decompressor = (
                    zlib.decompressobj()
                    if compression_type == 1
                    else LZOCompressor()
                    if compression_type == 2
                    else None
                )
                with fs.open(path, "rb+") as f:
                    f.seek(offset)
                    if decompressor:
                        for chunk in iterate_file(self.file, data_offset, tlv.tlv_len):
                            decompressor.decompress(chunk)
                            f.write(chunk)
                    elif compression_type == 3:
                        for chunk in iterate_file(self.file, data_offset, tlv.tlv_len):
                            # TODO: ZSTD decompress ?
                            f.write(chunk)
                    else:
                        for chunk in iterate_file(self.file, data_offset, tlv.tlv_len):
                            f.write(chunk)
            case CmdType.UTIMES:
                command = self._struct_parser.cparser_le.utimes_cmd_t(self.file)
                path = Path(command.path.value.decode())
                times = (command.atime.value.sec, command.mtime.value.sec)
                fs.utime(path, times)
            case _:
                fs.record_problem(
                    ExtractionProblem(
                        problem="Not useful commands for extraction are just parsed",
                        resolution="Skipped",
                    )
                )
                match CmdType(cmd_header.cmd_type):
                    case CmdType.UNSPEC:
                        self._struct_parser.cparser_le.tlv_header_no_value_t(self.file)
                    case CmdType.END:
                        self._struct_parser.cparser_le.cmd_header_t(self.file)
                    case CmdType.SUBVOL:
                        self._struct_parser.cparser_le.subvol_cmd_t(self.file)
                    case CmdType.SNAPSHOT:
                        self._struct_parser.cparser_le.snapshot.cmd_t(self.file)
                    case CmdType.CHMOD:
                        self._struct_parser.cparser_le.chmod_cmd_t(self.file)
                    case CmdType.CHOWN:
                        self._struct_parser.cparser_le.chown_cmd_t(self.file)
                    case CmdType.UPDATE_EXTENT:
                        self._struct_parser.cparser_le.update_extent_cmd_t(self.file)
                    case CmdType.FALLOCATE:
                        self._struct_parser.cparser_le.fallocate_cmd_t(self.file)
                    case CmdType.FILEATTR:
                        self._struct_parser.cparser_le.fileattr_cmd_t(self.file)


class BTRFSStreamExtractor(Extractor):
    def extract(self, inpath: Path, outdir: Path) -> ExtractResult:
        fs = FileSystem(outdir)
        with File.from_path(inpath) as file:
            btrfs_parser = BTRFSParser(file, file.tell())
            btrfs_parser.replay(fs)
        return ExtractResult(reports=fs.problems)


class BTRFSStreamHandler(StructHandler):
    NAME = "btrfs_stream"
    PATTERNS = [HexString("62 74 72 66 73 2d 73 74 72 65 61 6d 00 (01 | 02) 00 00 00")]
    C_DEFINITIONS = C_DEFINITIONS
    EXTRACTOR = BTRFSStreamExtractor()
    HEADER_STRUCT = "stream_header_t"
    DOC = HandlerDoc(
        name="BTRFS Stream",
        description="A BTRFS send stream is a binary format used to transfer btrfs subvolume snapshots between filesystems. It encodes filesystem operations (file creation, directory structure, data writes, metadata) as a sequence of commands that can be replayed by btrfs receive to reconstruct the original snapshot. It supports both full sends (complete snapshot) and incremental sends (diff between two snapshots).",
        handler_type=HandlerType.FILESYSTEM,
        vendor=None,
        references=[
            Reference(
                title="BTRFS Stream Official Documentation",
                url="https://btrfs.readthedocs.io/en/latest/dev/dev-send-stream.html",
            ),
        ],
        limitations=["Does not support incremental streams."],
    )

    def calculate_chunk(self, file: File, start_offset: int) -> ValidChunk | None:
        file.seek(start_offset + STREAM_HEADER_LEN, io.SEEK_SET)
        cmd_header = self.cparser_le.cmd_header_t(file)
        while cmd_header.cmd_type != CmdType.END:
            try:
                CmdType(cmd_header.cmd_type)
            except ValueError as err:
                raise InvalidInputFormat(
                    f"Invalid BTRFS stream command type: {cmd_header.cmd_type}"
                ) from err
            file.seek(cmd_header.data_len, io.SEEK_CUR)
            cmd_header = self.cparser_le.cmd_header_t(file)
        return ValidChunk(start_offset=start_offset, end_offset=file.tell())
