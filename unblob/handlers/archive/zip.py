import io
import zipfile
from typing import List, Optional, Tuple

from structlog import get_logger

from ...file_utils import InvalidInputFormat, find_first, iterate_patterns
from ...models import StructHandler, ValidChunk

logger = get_logger()


MAXIMUM_VERSION = 0xFF
EOCD_RECORD_HEADER = b"\x50\x4b\x05\x06"
ENCRYPTED_FLAG = 0b0001


class ZIPHandler(StructHandler):
    NAME = "zip"

    YARA_RULE = r"""
        strings:
            $zip_header = { 50 4B 03 04 } // Local file header only
        condition:
            $zip_header
    """

    C_DEFINITIONS = r"""
        typedef struct local_file_header
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
        } local_file_header_t;

        typedef struct end_of_central_directory
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
        } end_of_central_directory_t;
    """
    HEADER_STRUCT = "local_file_header_t"

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

        for zip_end in iterate_patterns(file, EOCD_RECORD_HEADER):
            if zip_end == -1:
                break

            file.seek(zip_end)
            eocd = self.cparser_le.end_of_central_directory_t(file)

            # Check if the EOCD header is valid, we might be just picking up something that looks like an EOCD header
            if zip_end == (eocd.offset_of_cd + eocd.central_directory_size):
                return file.tell()

        raise InvalidInputFormat("Missing EOCD record header in ZIP chunk.")

        # file.seek(start_offset)
        #
        # zip_end = find_first(file, EOCD_RECORD_HEADER)
        # print('ZIP_END', zip_end)
        #
        # if zip_end == -1:
        #     raise InvalidInputFormat("Missing EOCD record header in ZIP chunk.")
        #
        # file.seek(zip_end)
        # eocd = self.cparser_le.end_of_central_directory_t(file)
        # print('EOCD', eocd)
        # print(f"zip_end={zip_end} cd_size={eocd.central_directory_size} cd_offset={eocd.offset_of_cd} cd_end={eocd.offset_of_cd + eocd.central_directory_size}")
        # return file.tell()

    def check_file(self, file: io.BufferedIOBase) -> Tuple[bool, bool]:
        has_encrypted_files = False
        try:
            with zipfile.ZipFile(file) as zip:  # type: ignore
                for zipinfo in zip.infolist():
                    if zipinfo.flag_bits & ENCRYPTED_FLAG:
                        has_encrypted_files = True
            return True, has_encrypted_files
        except (zipfile.BadZipFile, UnicodeDecodeError, ValueError):
            return False, has_encrypted_files

    def calculate_chunk(
        self, file: io.BufferedIOBase, start_offset: int
    ) -> Optional[ValidChunk]:

        header = self.parse_header(file)
        if header.version_needed_to_extract > MAXIMUM_VERSION:
            return

        end_of_zip = self._calculate_zipfile_end(file, start_offset)
        file.seek(start_offset)

        is_valid, has_encrypted_files = self.check_file(file)

        if not is_valid:
            raise InvalidInputFormat("Invalid ZIP header.")

        return ValidChunk(
            start_offset=start_offset,
            end_offset=end_of_zip,
            is_encrypted=has_encrypted_files,
        )

    @staticmethod
    def make_extract_command(inpath: str, outdir: str) -> List[str]:
        # empty password with -p will make sure the command will not hang
        return ["7z", "x", "-p", "-y", inpath, f"-o{outdir}"]
