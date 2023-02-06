from typing import Optional

from structlog import get_logger

from unblob.file_utils import InvalidInputFormat

from ...extractors import Command
from ...models import File, Regex, StructHandler, ValidChunk

logger = get_logger()


class NTFSHandler(StructHandler):
    NAME = "ntfs"

    PATTERNS = [
        # An initial x86 short jump instruction (EB 52 90)
        # OEMName (8 bytes) = 'NTFS    '
        # bytes per sector, the rule enforce a non-zero value
        # 55 AA is the end of sector marker
        Regex(
            r"\xEB\x52\x90\x4E\x54\x46\x53\x20\x20\x20\x20[\x00-\xFF][\x01-\xFF][\x00-\xFF]{497}\x55\xAA"
        )
    ]

    C_DEFINITIONS = r"""
        typedef struct ntfs_boot {
            uint8 jmp_ins[3];	// jump instruction to boot code.
            char oem_id[8];	// OEM ID, equal "NTFS    "

            // BPB
            uint16 bytes_per_sector;
            uint8 sectors_per_clusters;
            uint8 unused1[7];
            uint8 media_descriptor;
            uint8 unused2[2];
            uint16 sectors_per_track;
            uint16 heads;
            uint32 hidden_sectors;
            uint8 unused3[4];

            // EBPB
            //uint8 bios_drive_num;	// 0x24: BIOS drive number =0x80.
            uint8 unused4[4];
            uint64 total_sectors;
            uint64 mft_cluster_number;
            uint64 mft_mirror_cluster_number;
            uint8 record_size;
            uint8 unused5[3];
            uint8 index_size;
            uint8 unused6[3];
            uint64 serial_num;
            uint32 checksum;

            uint8 bootstrap_code[426];
            uint16 boot_magic;
        } ntfs_boot_t;
    """

    HEADER_STRUCT = "ntfs_boot_t"

    EXTRACTOR = Command("7z", "x", "-x![SYSTEM]", "-y", "{inpath}", "-o{outdir}")

    def calculate_chunk(self, file: File, start_offset: int) -> Optional[ValidChunk]:
        header = self.parse_header(file)

        fsize = header.total_sectors * header.bytes_per_sector
        if fsize == 0:
            raise InvalidInputFormat("NTFS header with null disk size.")

        end_offset = start_offset + len(header) + fsize
        return ValidChunk(
            start_offset=start_offset,
            end_offset=end_offset,
        )
