import io

from unblob.extractors import Command
from unblob.file_utils import InvalidInputFormat
from unblob.models import (
    File,
    HandlerDoc,
    HandlerType,
    HexString,
    Reference,
    StructHandler,
    ValidChunk,
)

_MIN_BLOCK_SIZE = 512
_MAX_BLOCK_SIZE = 1024 * 1024  # 1 MB sanity cap


def _fletcher64_valid(block: bytes) -> bool:
    mod = 0xFFFFFFFF
    sum1 = sum2 = 0
    for offset in range(8, len(block), 4):
        sum1 = (sum1 + int.from_bytes(block[offset : offset + 4], "little")) % mod
        sum2 = (sum2 + sum1) % mod
    check1 = mod - ((sum1 + sum2) % mod)
    check2 = mod - ((sum1 + check1) % mod)
    expected = check1 | (check2 << 32)
    return expected == int.from_bytes(block[0:8], "little")


class APFSHandler(StructHandler):
    NAME = "apfs"

    PATTERNS = [
        # Match the superblock's object header, not just the "NXSB" magic, so we don't
        # fire on every occurrence of that string:
        #   01 00 00 80    o_type = 0x80000001 (NX_SUPERBLOCK | PHYSICAL flag), little-endian
        #   ?? ?? ?? ??    o_subtype
        #   4E 58 53 42    nx_magic "NXSB"
        HexString("01 00 00 80 ?? ?? ?? ?? 4E 58 53 42"),
    ]

    # The match starts at o_type, 24 bytes into the superblock; shift start back to block 0.
    PATTERN_MATCH_OFFSET = -24

    # APFS container superblock layout (all fields little-endian):
    #   offset  0: obj_phys_t (32 bytes) — Fletcher-64 checksum + oid + xid + type + subtype
    #   offset 32: nx_magic    uint32  "NXSB" (0x4253584e)
    #   offset 36: nx_block_size  uint32
    #   offset 40: nx_block_count uint64
    C_DEFINITIONS = r"""
        typedef struct apfs_nx_superblock {
            char    o_cksum[8];     // Fletcher-64 checksum
            uint64  o_oid;          // object identifier
            uint64  o_xid;          // transaction identifier
            uint32  o_type;         // object type
            uint32  o_subtype;      // object subtype
            char    nx_magic[4];    // "NXSB"
            uint32  nx_block_size;  // block size in bytes
            uint64  nx_block_count; // number of blocks in the container
        } apfs_nx_superblock_t;
    """
    HEADER_STRUCT = "apfs_nx_superblock_t"

    EXTRACTOR = Command("7z", "x", "-y", "{inpath}", "-o{outdir}")

    DOC = HandlerDoc(
        name="APFS",
        description="Apple File System (APFS) is Apple's proprietary filesystem introduced in macOS High Sierra and iOS 10.3, replacing HFS+. It features copy-on-write semantics, space sharing between volumes, native encryption, snapshots, and sparse files.",
        handler_type=HandlerType.FILESYSTEM,
        vendor="Apple",
        references=[
            Reference(
                title="Apple File System Reference",
                url="https://developer.apple.com/support/downloads/Apple-File-System-Reference.pdf",
            ),
        ],
        limitations=[],
    )

    def is_valid_header(self, header) -> bool:
        # o_type is already guaranteed by PATTERNS; only the container geometry needs checking.
        return (
            _MIN_BLOCK_SIZE <= header.nx_block_size <= _MAX_BLOCK_SIZE
            and header.nx_block_count > 0
        )

    def calculate_chunk(self, file: File, start_offset: int) -> ValidChunk | None:
        header = self.parse_header(file)

        if not self.is_valid_header(header):
            raise InvalidInputFormat("Invalid APFS container superblock")

        file.seek(start_offset, io.SEEK_SET)
        if not _fletcher64_valid(file.read(header.nx_block_size)):
            raise InvalidInputFormat("APFS superblock Fletcher-64 checksum mismatch")

        return ValidChunk(
            start_offset=start_offset,
            end_offset=start_offset + header.nx_block_size * header.nx_block_count,
        )
