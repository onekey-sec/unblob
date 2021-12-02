import io
import struct
from typing import List, Optional

from structlog import get_logger

from ...file_utils import Endian, InvalidInputFormat, read_until_past
from ...models import StructHandler, ValidChunk

logger = get_logger()


STRING_ALIGNMENT = 16
MAX_LINUX_PATH_LENGTH = 0xFF
MAX_UINT32 = 0x100000000


def valid_checksum(content: bytes) -> int:
    """Compute the RomFS checksum of content."""
    total = 0
    for i in range(0, len(content), 4):
        total += struct.unpack(">L", content[i : (i + 4)])[0]  # noqa: E203
        total %= MAX_UINT32
    return total == 0


def get_string(file: io.BufferedIOBase) -> bytes:
    filename = b""
    counter = 0
    while b"\x00" not in filename and counter < MAX_LINUX_PATH_LENGTH:
        filename += file.read(STRING_ALIGNMENT)
        counter += STRING_ALIGNMENT
    return filename.rstrip(b"\x00")


class RomFSFSHandler(StructHandler):

    NAME = "romfs"

    YARA_RULE = r"""
        strings:
            // '-rom1fs-'
            $romfs_magic = { 2D 72 6F 6D 31 66 73 2d }
        condition:
            $romfs_magic
    """

    C_DEFINITIONS = r"""
        struct romfs_header {
            char magic[8];
            uint32 full_size;
            uint32 checksum;
        }
    """
    HEADER_STRUCT = "romfs_header"

    def calculate_chunk(
        self, file: io.BufferedIOBase, start_offset: int
    ) -> Optional[ValidChunk]:

        if not valid_checksum(file.read(512)):
            raise InvalidInputFormat("Invalid RomFS checksum.")

        file.seek(-512, io.SEEK_CUR)

        # Every multi byte value must be in big endian order.
        header = self.parse_header(file, Endian.BIG)

        # The zero terminated name of the volume, padded to 16 byte boundary.
        get_string(file)

        # seek filesystem size (number of accessible bytes in this fs)
        # from the actual end of the header
        file.seek(header.full_size, io.SEEK_CUR)

        # Another thing to note is that romfs works on file headers and data
        # aligned to 16 byte boundaries, but most hardware devices and the block
        # device drivers are unable to cope with smaller than block-sized data.
        # To overcome this limitation, the whole size of the file system must be
        # padded to an 1024 byte boundary.
        read_until_past(file, b"\x00")

        return ValidChunk(
            start_offset=start_offset,
            end_offset=file.tell(),
        )

    @staticmethod
    def make_extract_command(inpath: str, outdir: str) -> List[str]:
        return ["unromfs", "-f", "-e", outdir, inpath]
