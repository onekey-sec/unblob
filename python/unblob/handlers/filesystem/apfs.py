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

_NXSB_MAGIC_OFFSET = 32  # bytes from container start to the NXSB magic

_MIN_BLOCK_SIZE = 512
_MAX_BLOCK_SIZE = 1024 * 1024  # 1 MB sanity cap


class APFSHandler(StructHandler):
    NAME = "apfs"

    PATTERNS = [HexString("4e 58 53 42")]  # "NXSB"

    # NXSB sits 32 bytes into the container superblock; shift start back to block 0.
    PATTERN_MATCH_OFFSET = -_NXSB_MAGIC_OFFSET

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

    def calculate_chunk(self, file: File, start_offset: int) -> ValidChunk | None:
        header = self.parse_header(file)

        if not (_MIN_BLOCK_SIZE <= header.nx_block_size <= _MAX_BLOCK_SIZE):
            raise InvalidInputFormat(
                f"APFS block_size out of range: {header.nx_block_size:#x}"
            )
        if header.nx_block_count == 0:
            raise InvalidInputFormat("APFS block_count is zero")

        return ValidChunk(
            start_offset=start_offset,
            end_offset=start_offset + header.nx_block_size * header.nx_block_count,
        )
