import io
import struct
from typing import List, Optional

from dissect.cstruct import Instance
from structlog import get_logger

from ...file_utils import InvalidInputFormat, iterate_patterns
from ...models import StructHandler, ValidChunk

logger = get_logger()

ENCRYPTED_FLAG = 0b0001
EOCD_RECORD_HEADER = 0x6054B50


class ZIPHandler(StructHandler):
    NAME = "zip"

    YARA_RULE = r"""
        strings:
            $zip_header = { 50 4B 03 04 } // Local file header only
        condition:
            $zip_header
    """

    C_DEFINITIONS = r"""

        typedef struct cd_file_header {
            uint32 magic;
            uint16 version_made_by;
            uint16 version_needed;
            uint16 flags;
            uint16 compression_method;
            uint16 dostime;
            uint16 dosdate;
            uint32 crc32_cs;
            uint32 compress_size;
            uint32 file_size;
            uint16 file_name_length;
            uint16 extra_field_length;
            uint16 file_comment_length;
            uint16 disk_number_start;
            uint16 internal_file_attr;
            uint32 external_file_attr;
            uint32 relative_offset_local_header;
            char file_name[file_name_length];
            char extra_field[extra_field_length];
        } cd_file_header_t;

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
    HEADER_STRUCT = "end_of_central_directory_t"

    def has_encrypted_files(
        self,
        file: io.BufferedIOBase,
        start_offset: int,
        end_of_central_directory: Instance,
    ) -> bool:
        file.seek(start_offset + end_of_central_directory.offset_of_cd, io.SEEK_SET)
        for _ in range(0, end_of_central_directory.total_entries):
            cd_header = self.cparser_le.cd_file_header_t(file)
            if cd_header.flags & ENCRYPTED_FLAG:
                return True
        return False

    def calculate_chunk(
        self, file: io.BufferedIOBase, start_offset: int
    ) -> Optional[ValidChunk]:

        has_encrypted_files = False
        file.seek(start_offset, io.SEEK_SET)

        for offset in iterate_patterns(file, struct.pack("<I", EOCD_RECORD_HEADER)):
            file.seek(offset, io.SEEK_SET)
            end_of_central_directory = self.parse_header(file)

            # the EOCD offset is equal to the offset of CD + size of CD
            end_of_central_directory_offset = (
                start_offset
                + end_of_central_directory.offset_of_cd
                + end_of_central_directory.central_directory_size
            )

            if offset == end_of_central_directory_offset:
                break
        else:
            raise InvalidInputFormat("Missing EOCD record header in ZIP chunk.")

        has_encrypted_files = self.has_encrypted_files(
            file, start_offset, end_of_central_directory
        )

        file.seek(offset, io.SEEK_SET)
        self.cparser_le.end_of_central_directory_t(file)

        return ValidChunk(
            start_offset=start_offset,
            end_offset=file.tell(),
            is_encrypted=has_encrypted_files,
        )

    @staticmethod
    def make_extract_command(inpath: str, outdir: str) -> List[str]:
        # empty password with -p will make sure the command will not hang
        return ["7z", "x", "-p", "-y", inpath, f"-o{outdir}"]
