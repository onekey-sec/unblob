import io
import struct

from structlog import get_logger

from unblob.extractors import Command

from ...file_utils import InvalidInputFormat
from ...models import (
    File,
    HandlerDoc,
    HandlerType,
    HexString,
    Reference,
    StructHandler,
    ValidChunk,
)

FREE_SECTOR = 0xFFFFFFFF
END_OF_CHAIN = 0xFFFFFFFE
HEADER_SIZE = 512

logger = get_logger()


class MsiHandler(StructHandler):
    NAME = "msi"

    PATTERNS = [HexString("D0 CF 11 E0 A1 B1 1A E1")]
    C_DEFINITIONS = r"""
        typedef struct cfbf_header
        {
                                        // [offset from start (bytes), length (bytes)]
            uint8 signature[8];         // [00H,08] {0xd0, 0xcf, 0x11, 0xe0, 0xa1, 0xb1,
                                        // 0x1a, 0xe1} for current version
            uint8 clsid[16];            // [08H,16] reserved must be zero (WriteClassStg/
                                        // GetClassFile uses root directory class id)
            uint16 minorVersion;        // [18H,02] minor version of the format: 33 is
                                        // written by reference implementation
            uint16 dllVersion;          // [1AH,02] major version of the dll/format: 3 for
                                        // 512-byte sectors, 4 for 4 KB sectors
            uint16 byteOrder;           // [1CH,02] 0xFFFE: indicates Intel byte-ordering
            uint16 sectorShift;         // [1EH,02] size of sectors in power-of-two;
                                        // typically 9 indicating 512-byte sectors
            uint16 miniSectorShift;     // [20H,02] size of mini-sectors in power-of-two;
                                        // typically 6 indicating 64-byte mini-sectors
            uint16 reserved;            // [22H,02] reserved, must be zero
            uint32 reserved1;           // [24H,04] reserved, must be zero
            uint32 csectDir;            // [28H,04] must be zero for 512-byte sectors,
                                        // number of SECTs in directory chain for 4 KB
                                        // sectors
            uint32 csectFat;            // [2CH,04] number of SECTs in the FAT chain
            uint32 sectDirStart;        // [30H,04] first SECT in the directory chain
            uint32 txSignature;         // [34H,04] signature used for transactions; must
                                        // be zero. The reference implementation
                                        // does not support transactions
            uint32 miniSectorCutoff;    // [38H,04] maximum size for a mini stream;
                                        // typically 4096 bytes
            uint32 sectMiniFatStart;    // [3CH,04] first SECT in the MiniFAT chain
            uint32 csectMiniFat;        // [40H,04] number of SECTs in the MiniFAT chain
            uint32 sectDifStart;        // [44H,04] first SECT in the DIFAT chain
            uint32 csectDif;            // [48H,04] number of SECTs in the DIFAT chain
            uint32 sectFat[109];        // [4CH,436] the SECTs of first 109 FAT sectors
         } cfbf_header_t;
    """
    HEADER_STRUCT = "cfbf_header_t"

    EXTRACTOR = Command("7z", "x", "-p", "-y", "{inpath}", "-o{outdir}")

    DOC = HandlerDoc(
        name="MSI",
        description="Microsoft Installer (MSI) files are used for the installation, maintenance, and removal of software.",
        handler_type=HandlerType.ARCHIVE,
        vendor="Microsoft",
        references=[
            Reference(
                title="MSI File Format Documentation",
                url="https://docs.microsoft.com/en-us/windows/win32/msi/overview-of-windows-installer",
            ),
            Reference(
                title="Compound File Binary Format",
                url="https://en.wikipedia.org/wiki/Compound_File_Binary_Format",
            ),
        ],
        limitations=[
            "Limited to CFB based extraction, not full-on MSI extraction",
            "Extracted files have names coming from CFB internal representation, and may not correspond to the one they would have on disk after running the installer",
        ],
    )

    def _read_sector(
        self, file: File, start_offset: int, sector_size: int, sector_id: int
    ) -> bytes:
        # All sectors, including the fixed-size header, occupy full sector_size
        sector_offset = start_offset + sector_size + sector_id * sector_size
        if sector_offset > file.size():
            raise InvalidInputFormat("Invalid MSI file, sector offset too large")

        file.seek(sector_offset, io.SEEK_SET)
        raw_sector = file.read(sector_size)
        if len(raw_sector) != sector_size:
            raise InvalidInputFormat("Invalid MSI file, sector shorter than expected")

        return raw_sector

    def _append_fat_sector(
        self, fat_sectors: list[int], sector_id: int, required_count: int
    ) -> bool:
        if sector_id == FREE_SECTOR:
            return False

        fat_sectors.append(sector_id)
        return len(fat_sectors) >= required_count

    def _extend_fat_from_difat(
        self,
        file: File,
        header,
        start_offset: int,
        sector_size: int,
        entries_per_sector: int,
        fat_sectors: list[int],
    ) -> None:
        difat_sector = header.sectDifStart

        for _ in range(header.csectDif):
            if difat_sector in (FREE_SECTOR, END_OF_CHAIN):
                break

            raw_sector = self._read_sector(
                file, start_offset, sector_size, difat_sector
            )
            entries = struct.unpack(f"<{entries_per_sector}I", raw_sector)

            difat_sector = entries[-1]
            for entry in entries[:-1]:
                if self._append_fat_sector(
                    fat_sectors, entry, required_count=header.csectFat
                ):
                    return

    def _collect_fat_sectors(
        self,
        file: File,
        header,
        start_offset: int,
        sector_size: int,
        entries_per_sector: int,
    ) -> list[int]:
        fat_sectors: list[int] = []

        for sect in header.sectFat:
            if self._append_fat_sector(fat_sectors, sect, header.csectFat):
                return fat_sectors

        if len(fat_sectors) < header.csectFat:
            self._extend_fat_from_difat(
                file, header, start_offset, sector_size, entries_per_sector, fat_sectors
            )

        if len(fat_sectors) != header.csectFat:
            raise InvalidInputFormat("Invalid MSI file, incomplete FAT chain")

        return fat_sectors

    def calculate_chunk(self, file: File, start_offset: int) -> ValidChunk | None:
        file.seek(start_offset, io.SEEK_SET)
        header = self.parse_header(file)

        sector_size = 2**header.sectorShift
        entries_per_sector = sector_size // 4

        if sector_size < HEADER_SIZE:
            raise InvalidInputFormat("Invalid MSI file, sector smaller than header")

        if header.csectFat == 0:
            raise InvalidInputFormat("Invalid MSI file, FAT chain is empty")

        fat_sectors = self._collect_fat_sectors(
            file, header, start_offset, sector_size, entries_per_sector
        )

        max_used_sector = 0
        for sector_index, sect in enumerate(fat_sectors):
            raw_sector = self._read_sector(file, start_offset, sector_size, sect)
            entries = struct.unpack(f"<{entries_per_sector}I", raw_sector)

            base_sector_id = sector_index * entries_per_sector
            for entry_id in range(len(entries) - 1, -1, -1):
                if entries[entry_id] == FREE_SECTOR:
                    continue

                max_id = base_sector_id + entry_id
                max_used_sector = max(max_used_sector, max_id)
                break

        total_size = sector_size + ((max_used_sector + 1) * sector_size)

        return ValidChunk(
            start_offset=start_offset,
            end_offset=start_offset + total_size,
        )
