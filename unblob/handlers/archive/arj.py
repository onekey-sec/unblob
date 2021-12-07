import io
from typing import List, Optional

from structlog import get_logger

from ...models import StructHandler, ValidChunk

logger = get_logger()


class ARJError(Exception):
    pass


class ARJNullFile(ARJError):
    """Zero-sized ARJ."""


class ARJExtendedHeader(ARJError):
    """Main ARJ header contains extended_header, which we don't handle."""


class ARJHandler(StructHandler):
    NAME = "arj"

    YARA_RULE = r"""
        strings:
            $magic = { 60 EA [5] 0? [2] 0? } //
        condition:
            $magic
    """

    # https://docs.fileformat.com/compression/arj/
    # https://github.com/tripsin/unarj/blob/master/UNARJ.H#L203
    C_DEFINITIONS = r"""
        struct basic_header {
            uint16 id;
            uint16 size;
        };

        struct arj_header
        {
            basic_header header;
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
        };

        struct file_header {
            basic_header header;
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
        };

        struct metadata {
            char filename[];
            char comment[];
            uint32 crc;
        };

        struct extended_header {
            ushort size;
            // More would go here if there were an extended header
        }
    """

    HEADER_STRUCT = "arj_header"

    def _read_arj_main_header(self, file: io.BufferedIOBase, start_offset: int) -> int:
        basic_header = self.cparser_le.basic_header(file)
        logger.debug("Basic header parsed", header=basic_header)

        # It's unlikely and unhelpful if we find a completely zero-sized ARJ on it's own,
        # so we raise here.
        if basic_header.size == 0:
            raise ARJNullFile

        file.seek(start_offset)
        main_header = self.cparser_le.arj_header(file)
        logger.debug("Main header parsed", header=main_header)

        file.seek(start_offset + main_header.first_hdr_size + len(basic_header))
        self._read_headers(file)
        return file.tell()

    def _read_arj_files(self, file: io.BufferedIOBase) -> int:
        while True:
            start = file.tell()
            basic_header = self.cparser_le.basic_header(file)
            logger.debug("Basic header parsed", header=basic_header)

            if basic_header.size == 0:
                # We've reached the final empty file header. This is where we want to be.
                return file.tell()

            file.seek(start)
            file_header = self.cparser_le.file_header(file)

            file.seek(start + file_header.first_hdr_size + len(basic_header))
            self._read_headers(file)
            # Read past the file contents
            file.read(file_header.compressed_size)

    def _read_headers(self, file):
        metadata = self.cparser_le.metadata(file)
        logger.debug("Metadata header parsed", header=metadata)

        # Lack of support for extended header is ok given that no versions of ARJ use the extended header.
        # Source: 'ARJ TECHNICAL INFORMATION', September 2001
        extended_header = self.cparser_le.extended_header(file)
        logger.debug("Extended header parsed", header=extended_header)
        if extended_header.size != 0:
            raise ARJExtendedHeader

    def calculate_chunk(
        self, file: io.BufferedIOBase, start_offset: int
    ) -> Optional[ValidChunk]:
        try:
            # Read past the main header.
            self._read_arj_main_header(file, start_offset)
            end_of_arj = self._read_arj_files(file)
        except ARJError as exc:
            logger.warning("Invalid ARJ file", reason=exc.__doc__)
            return
        except EOFError:
            logger.warning(
                "Invalid ARJ file", reason="File ends before ARJ file resolves."
            )
            return

        return ValidChunk(
            start_offset=start_offset,
            end_offset=end_of_arj,
        )

    @staticmethod
    def make_extract_command(inpath: str, outdir: str) -> List[str]:
        return ["7z", "x", "-y", inpath, f"-o{outdir}"]
