import binascii
import io
from typing import Optional

from structlog import get_logger

from ...extractors import Command
from ...file_utils import Endian, convert_int32
from ...models import File, HexString, StructHandler, ValidChunk

logger = get_logger()

# CPP/7zip/Archive/ArjHandler.cpp IsArc_Arj()
MIN_BLOCK_SIZE = 30
MAX_BLOCK_SIZE = 2600
BASIC_HEADER_SIZE = 4


class ARJError(Exception):
    pass


class InvalidARJSize(ARJError):
    """Invalid size fields in ARJ header."""


class ARJChecksumError(ARJError):
    """Main ARJ header checksum missmatch."""


class ARJExtendedHeader(ARJError):
    """Main ARJ header contains extended_header, which we don't handle."""


class ARJHandler(StructHandler):
    NAME = "arj"

    PATTERNS = [HexString("60 EA [5] 0? [2] 0?")]

    # https://docs.fileformat.com/compression/arj/
    # https://github.com/tripsin/unarj/blob/master/UNARJ.H#L203
    C_DEFINITIONS = r"""
        typedef struct basic_header {
            uint16 id;
            uint16 size;
        } basic_header_t;

        typedef struct arj_header
        {
            basic_header_t header;
            uint8 first_hdr_size; // size up to "extra data"
            uint8 archive_version;
            uint8 min_version;
            uint8 host_os; // 0-9
            uint8 arj_flags; // 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40
            uint8 security_version; // "2 = current"
            uint8 file_type; // 0-4
            uint8 garble_password;
            uint32 datetime_created;
            uint32 datetime_modified;
            uint32 archive_size;
            uint32 filepos_security_env_data;
            uint16 reserved1;
            uint16 reserved2;
            uint16 security_env_length;
            uint16 host_data;
        } arj_header_t;

        typedef struct file_header {
            basic_header_t header;
            uint8 first_hdr_size; // size up to "extra data"
            uint8 archive_version;
            uint8 min_version;
            uint8 host_os; // 0-9
            uint8 arj_flags; // 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40
            uint8 method; // 0-4
            uint8 file_type;
            uint8 garble_password;
            uint32 datetime_modified;
            uint32 compressed_size;
            uint32 original_size;
            uint32 original_file_crc;
            uint16 entryname_pos_in_filename;
            uint16 file_access_mode;
            uint16 host_data;
        } file_header_t;

        typedef struct metadata {
            char filename[];
            char comment[];
            uint32 crc;
        } metadata_t;

        typedef struct extended_header {
            uint16 size;
            // More would go here if there were an extended header
        } extended_header_t;
    """

    HEADER_STRUCT = "arj_header_t"

    EXTRACTOR = Command("7z", "x", "-y", "{inpath}", "-o{outdir}")

    def _read_arj_main_header(self, file: File, start_offset: int) -> int:
        file.seek(start_offset)
        main_header = self.cparser_le.arj_header(file)
        logger.debug("Main header parsed", header=main_header, _verbosity=3)

        if (
            main_header.header.size < MIN_BLOCK_SIZE
            or main_header.header.size > MAX_BLOCK_SIZE
            or main_header.header.size < main_header.first_hdr_size
        ):
            raise InvalidARJSize

        file.seek(start_offset + BASIC_HEADER_SIZE)
        content = file.read(main_header.header.size)
        calculated_crc = binascii.crc32(content)
        crc = convert_int32(file.read(4), endian=Endian.LITTLE)

        if crc != calculated_crc:
            raise ARJChecksumError

        file.seek(start_offset + main_header.first_hdr_size + BASIC_HEADER_SIZE)
        self._read_headers(file)
        return file.tell()

    def _read_arj_files(self, file: File) -> int:
        while True:
            start = file.tell()
            basic_header = self.cparser_le.basic_header(file)
            logger.debug("Basic header parsed", header=basic_header, _verbosity=3)

            if basic_header.size == 0:
                # We've reached the final empty file header. This is where we want to be.
                return file.tell()

            file.seek(start)
            file_header = self.cparser_le.file_header_t(file)

            file.seek(start + file_header.first_hdr_size + len(basic_header))
            self._read_headers(file)
            # Seek past the file contents
            file.seek(file_header.compressed_size, io.SEEK_CUR)

    def _read_headers(self, file):
        metadata = self.cparser_le.metadata_t(file)
        logger.debug("Metadata header parsed", header=metadata, _verbosity=3)

        # Lack of support for extended header is ok given that no versions of ARJ use the extended header.
        # Source: 'ARJ TECHNICAL INFORMATION', September 2001
        extended_header = self.cparser_le.extended_header_t(file)
        logger.debug("Extended header parsed", header=extended_header, _verbosity=3)
        if extended_header.size != 0:
            raise ARJExtendedHeader

    def calculate_chunk(self, file: File, start_offset: int) -> Optional[ValidChunk]:
        try:
            # Read past the main header.
            self._read_arj_main_header(file, start_offset)
            end_of_arj = self._read_arj_files(file)
        except ARJError as exc:
            logger.debug(
                "Invalid ARJ file",
                start_offset=start_offset,
                reason=exc.__doc__,
                _verbosity=2,
            )
            return None

        return ValidChunk(
            start_offset=start_offset,
            end_offset=end_of_arj,
        )
