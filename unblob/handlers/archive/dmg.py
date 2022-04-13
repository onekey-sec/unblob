from typing import Optional

from structlog import get_logger

from unblob.extractors.command import Command

from ...file_utils import Endian
from ...models import File, HexString, StructHandler, ValidChunk

logger = get_logger()


class DMGHandler(StructHandler):
    NAME = "dmg"

    PATTERNS = [
        HexString(
            """
            // 'koly' magic, followed by version from 1 to 4, followed by fixed header size of 512
            6b 6f 6c 79 00 00 00 04 00 00 02 00
        """
        )
    ]

    C_DEFINITIONS = r"""
        // source: http://newosxbook.com/DMG.html
        typedef struct dmg_header {
            char     Signature[4];          // Magic ('koly')
            uint32 Version;               // Current version is 4
            uint32 HeaderSize;            // sizeof(this), always 512
            uint32 Flags;                 // Flags
            uint64 RunningDataForkOffset; //
            uint64 DataForkOffset;        // Data fork offset (usually 0, beginning of file)
            uint64 DataForkLength;        // Size of data fork (usually up to the XMLOffset, below)
            uint64 RsrcForkOffset;        // Resource fork offset, if any
            uint64 RsrcForkLength;        // Resource fork length, if any
            uint32 SegmentNumber;         // Usually 1, may be 0
            uint32 SegmentCount;          // Usually 1, may be 0
            uchar   SegmentID[16];             // 128-bit GUID identifier of segment (if SegmentNumber !=0)

            uint32 DataChecksumType;      // Data fork
            uint32 DataChecksumSize;      //  Checksum Information
            uint32 DataChecksum[32];      // Up to 128-bytes (32 x 4) of checksum

            uint64 XMLOffset;             // Offset of property list in DMG, from beginning
            uint64 XMLLength;             // Length of property list
            uint8  Reserved1[120];        // 120 reserved bytes - zeroed

            uint32 ChecksumType;          // Master
            uint32 ChecksumSize;          //  Checksum information
            uint32 Checksum[32];          // Up to 128-bytes (32 x 4) of checksum

            uint32 ImageVariant;          // Commonly 1
            uint64 SectorCount;           // Size of DMG when expanded, in sectors

            uint32 reserved2;             // 0
            uint32 reserved3;             // 0
            uint32 reserved4;             // 0

        } dmg_header_t;
    """
    HEADER_STRUCT = "dmg_header_t"

    # This directory is here for simulating hardlinks and other metadata
    # but the files will be extracted anyway, and we only care about the content
    # See more about this problem: https://newbedev.com/hfs-private-directory-data
    EXTRACTOR = Command(
        "7z", "x", "-xr!*HFS+ Private Data*", "-y", "{inpath}", "-o{outdir}"
    )

    def calculate_chunk(self, file: File, start_offset: int) -> Optional[ValidChunk]:
        header = self.parse_header(file, endian=Endian.BIG)

        # NOTE: the koly block is a trailer
        # ┌─────────────┐ │
        # │Data fork    │ │DataForkLength
        # │contains     │ │
        # │disk blocks  │ │
        # │             │ │
        # │             │ ▼
        # ├─────────────┤ │
        # │XML plist    │ │XMLLength
        # ├─────────────┤ ▼
        # │koly trailer │
        # └─────────────┘
        #

        return ValidChunk(
            start_offset=start_offset - header.XMLLength - header.DataForkLength,
            end_offset=start_offset + len(header),
        )
