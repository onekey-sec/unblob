import io
import zipfile
from typing import List, Optional

from structlog import get_logger

from ...file_utils import find_first
from ...models import StructHandler, ValidChunk

logger = get_logger()


MAXIMUM_VERSION = 0xFF
EOCD_RECORD_HEADER = b"\x50\x4b\x05\x06"
ENCRYPTED_FLAG = 0b0001


class MissingEOCDHeader(Exception):
    """Raised when the EOCD record header is missing from the ZIP."""


class ZIPHandler(StructHandler):
    NAME = "zip"

    YARA_RULE = r"""
        strings:
            $zip_header = { 50 4B 03 04 } // Local file header only
        condition:
            $zip_header
    """

    C_DEFINITIONS = r"""
        struct pk_generic
        {
            uint32 magic;
            uint16 version;
        }

        struct local_file_header
        {
            uint32 local_file_header_signature;
            uint16 version_needed_to_extract;
            uint16 gp_bitflag;
            uint16 compression_method;
            uint16 last_mod_file_time;
            uint16 last_mod_file_date;
            uint32 crc32;
            uint32 compressed_size;
            uint32 uncompressed_size;
            uint16 file_name_length;
            uint16 extra_field_length;
            char file_name[file_name_length];
            char extra_field[extra_field_length];
        }

        struct central_directory_header
        {
            uint32 cd_header_signature; //
            uint16 version_made_by;
            uint16 min_version_to_extract;
            uint16 gp_bitflag;
            uint16 compression_method;
            uint16 last_mod_file_time;
            uint16 last_mod_file_date;
            uint32 crc32;
            uint32 compressed_size;
            uint32 uncompressed_size;
            uint16 file_name_length;
            uint16 extra_field_length;
            uint16 file_comment_length;
            uint16 disk_number_start;
            uint16 internal_file_attributes;
            uint32 external_file_attributes;
            uint32 offset_local_header;
            char file_name[file_name_length];
            char extra_field[extra_field_length];
            char file_comment[file_comment_length];
        }

        struct end_of_central_directory
        {
            uint32 end_of_central_signature;
            uint16 disk_number;
            uint16 disk_number_with_cd;
            uint16 disk_entries;
            uint16 total_entries;
            uint32 central_directory_size;
            uint32 offset_of_cd;
            uint16 comment_len;
            char zip_file_comment[comment_len];
        }

        struct streaming_data
        {
            uint32 magic;
            uint32 unk1;
            uint32 unk2;
            uint32 unk3;
        }
    """
    HEADER_STRUCT = "local_file_header"

    def _calculate_zipfile_end(self, file: io.BufferedIOBase, start_offset: int) -> int:
        # If we just pass a file with multiple ZIP files in it to zipfile.ZipFile, it seems
        # that it will basically scan for the final EOCD record header, and assume
        # that's where the file ends.
        # E.g. in the case our file looks like this:
        # | ZIPFILE | SOMETHING ELSE | ZIPFILE |
        # zipfile.ZipFile() will assume:
        # |    THIS IS ALL THE SAME ZIPFILE    |
        # For obvious reasons, this is not helpful in our case. We need to try to guess the length of
        # the ZIP file chunk within our file independently, and then carve that chunk out.

        file.seek(start_offset)

        zip_end = find_first(file, EOCD_RECORD_HEADER)

        if zip_end == -1:
            raise MissingEOCDHeader

        file.seek(zip_end)
        self.cparser_le.end_of_central_directory(file)
        return file.tell()

    def calculate_chunk(
        self, file: io.BufferedIOBase, start_offset: int
    ) -> Optional[ValidChunk]:

        header = self.parse_header(file)
        if header.version_needed_to_extract > MAXIMUM_VERSION:
            return

        try:
            end_of_zip = self._calculate_zipfile_end(file, start_offset)
        except MissingEOCDHeader:
            return

        file.seek(start_offset)

        has_encrypted_files = False

        zip_content = file.read(end_of_zip - start_offset)
        this_zip_chunk = io.BytesIO(zip_content)
        with zipfile.ZipFile(this_zip_chunk) as zip:
            for zipinfo in zip.infolist():
                if zipinfo.flag_bits & ENCRYPTED_FLAG:
                    has_encrypted_files = True

        if has_encrypted_files:
            logger.warning("There are encrypted files in the ZIP")

        return ValidChunk(start_offset=start_offset, end_offset=end_of_zip)

    @staticmethod
    def make_extract_command(inpath: str, outdir: str) -> List[str]:
        # empty password with -p will make sure the command will not hang
        return ["7z", "x", "-p", "", "-y", inpath, f"-o{outdir}"]
