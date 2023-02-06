from typing import Optional

from dissect.cstruct import Instance
from structlog import get_logger

from unblob.extractors.command import Command
from unblob.file_utils import InvalidInputFormat

from ...models import File, HexString, StructHandler, ValidChunk

logger = get_logger()


VALID_NT_SIGNATURES = [0x28, 0x29]
VALID_MEDIAS = [0xF0, 0xF8, 0xF9, 0xFA, 0xFB, 0xFC, 0xFD, 0xFE, 0xFF]


class FATHandler(StructHandler):
    NAME = "fat"

    PATTERNS = [
        HexString(
            """
            // An initial x86 short jump instruction
            // OEMName (8 bytes)
            // BytesPerSec (2 bytes)
            // SecPerClus (1 byte) "Must be one of 1, 2, 4, 8, 16, 32, 64, 128."
            // 495 (0x1EF) bytes of whatever
            // 55 AA is the "signature". "This will be the end of the sector only in case the
            // sector size is 512."
            ( EB | E9 ) [13] ( 01 | 02 | 04 | 08 | 10 | 20 | 40 | 80 ) [495] 55 AA
        """
        )
    ]

    C_DEFINITIONS = r"""
        // Common between FAT12, FAT16 and FAT32.
        typedef struct bios_param_common {
            char JmpBoot[3];     // An x86 JMP - e.g. EB 3C 90 ("One finds either eb xx 90, or e9 xx xx.")
            char OEMName[8];     // OEM name/version (E.g. "IBM  3.3", "IBM 20.0", "MSDOS5.0", "MSWIN4.0".)
            // "BIOS Parameter Block" starts here
            uint16 BytesPerSec; // Almost always 512? Microsoft operating systems
                                    // will properly support 1024, 2048, and 4096.
            uint8 SecPerClus;   // The legal values are 1, 2, 4, 8, 16, 32, 64,
                                    // and 128.
            uint16 RsvdSecCnt;  // Must not be 0. Should be 1 on FAT12/16? 32 on FAT32?
            uint8 NumFATs;      // Should always be 2?
            uint16 RootEntCnt;  // Number of 32-byte dir entries. Must be 0 for FAT32.
            uint16 TotSectors;    // Old 16-bit count of all sectors on volume
                                    // This field can be 0; if it is 0, then TotSec32 must be
                                    // non-zero. For FAT32, this field must be 0. For FAT12 and
                                    // FAT16 volumes, this field contains the sector count, and
                                    // TotSec32 is 0 if the total sector count fits (is less than
                                    // 0x10000).
            uint8 Media;        // The valid values for this field is 0xF0, 0xF8, 0xF9, 0xFA, 0xFB,
                                    // 0xFC, 0xFD, 0xFE and 0xFF.
            uint16 FATSz16;     // This field is the FAT12/FAT16 16-bit count of sectors occupied by
                                    // ONE FAT. On FAT32 volumes this field must be 0, and
                                    // FATSz32 contains the FAT size count.
            uint16 SecPerTrk;   // Sectors per track for interrupt 0x13.
            uint16 NumHeads;    // Number of heads for interrupt 0x13
        } bios_param_common_t;

        // BIOS params for FAT16.
        typedef struct fat12_16_bootsec {
            bios_param_common_t common;
            uint32 NumHidden;
            uint32 NumSectors;
            uint8 DrvNum;
            uint8 Reserved1;
            uint8 BootSig; // If it's 0x29 (or 0x28 on NT), means that the next 3 fields are present
            char VolID[4];
            char VolLab[11];
            char FileSysType[8]; // Filesystem type (E.g. "FAT12   ", "FAT16   ", "FAT     ", or all zero.)
        } fat12_16_bootsec_t;

        // BIOS params for FAT32.
        typedef struct fat32_bootsec {
            bios_param_common_t common;
            uint32 Num_Hidden;
            uint32 TotSec32;
            uint32 FATSz32;
            uint16 ExtFlags;
            uint16 FSVer;
            uint32 RootClus;
            uint16 FSInfo;
            uint16 BkBootSec;
            uint8 Reserved[12];
            uint8 DrvNum;
            uint8 Reserved1;
            uint8 BootSig;
            char VolID[4];
            char VolLab[11];
            char FileSysType[8];
        } fat32_bootsec_t;

        typedef struct fat_unknown {
            bios_param_common_t common;
        } fat_unknown_t;
    """

    EXTRACTOR = Command("7z", "x", "-y", "{inpath}", "-o{outdir}")

    def valid_name(self, name: bytes) -> bool:
        try:
            name.decode("utf-8")
        except UnicodeDecodeError:
            return False
        return True

    def valid_fat32_header(self, header: Instance) -> bool:
        if header.common.RootEntCnt != 0:
            return False
        if header.common.TotSectors != 0:
            return False
        if header.common.FATSz16 != 0:
            return False
        return True

    def valid_header(self, header: Instance) -> bool:
        if not self.valid_name(header.common.OEMName):
            return False
        if header.common.BytesPerSec % 2 != 0:
            return False
        if header.common.RsvdSecCnt == 0:
            return False
        if header.common.Media not in VALID_MEDIAS:
            return False
        if header.BootSig not in VALID_NT_SIGNATURES:
            return False
        if header.FileSysType not in (b"FAT12   ", b"FAT16   "):
            return self.valid_fat32_header(header)
        return True

    def calculate_chunk(self, file: File, start_offset: int) -> Optional[ValidChunk]:
        header = self.cparser_le.fat12_16_bootsec_t(file)

        if header.FileSysType in (b"FAT12   ", b"FAT16   "):
            if header.common.TotSectors == 0:
                sector_count = header.NumSectors
            else:
                sector_count = header.common.TotSectors
        else:
            file.seek(start_offset)
            header = self.cparser_le.fat32_bootsec_t(file)
            sector_count = header.TotSec32

        if not self.valid_header(header):
            raise InvalidInputFormat("Invalid FAT header.")

        logger.debug("FAT header parsed", header=header, _verbosity=3)

        if sector_count == 0x0:
            sector_count = header.common.TotSectors

        size = header.common.BytesPerSec * sector_count

        return ValidChunk(
            start_offset=start_offset,
            end_offset=start_offset + size,
        )
