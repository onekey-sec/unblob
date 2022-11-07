import io
from typing import Optional, Tuple

from dissect.cstruct import Instance
from structlog import get_logger

from ...extractors import Command
from ...file_utils import InvalidInputFormat
from ...models import File, HexString, StructHandler, ValidChunk

logger = get_logger()


def signature(hex: str) -> bytes:
    return bytes.fromhex(hex)


class ZIPHandler(StructHandler):
    NAME = "zip"

    # b'PK' = 50 4B
    ENCRYPTED_FLAG = 0b0001
    LOCAL_FILE_HEADER_SIGNATURE = signature("50 4B 03 04")
    EOCD_SIGNATURE = signature("50 4B 05 06")
    ZIP64_EOCD_SIGNATURE = signature("50 4B 06 06")
    ZIP64_EOCD_LOCATOR_SIGNATURE = signature("50 4B 06 07")

    PATTERNS = [HexString("50 4B 05 06 // EOCD")]

    C_DEFINITIONS = r"""
        // every zip structure starts with a signature of 4 bytes, the first 2 being
        // 'PK' after Phil Katz, the next 2 bytes is structure specific

        typedef struct cd_file_header {
            char signature[4];
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
            char signature[4];
            uint16 disk_number;
            uint16 disk_number_with_cd;
            uint16 disk_entries;
            uint16 total_entries;
            uint32 size_of_cd;
            uint32 offset_of_cd;
            uint16 comment_len;
            char zip_file_comment[comment_len];
        } end_of_central_directory_t;

        typedef struct zip64_end_of_central_directory_locator
        {
            char signature[4];
            uint32 disk_number;
            uint64 offset_of_cd;
            uint32 total_disk;
        } zip64_end_of_central_directory_locator_t;

        typedef struct zip64_end_of_central_directory
        {
            char signature[4];
            uint64 size_of_eocd_record;
            uint16 version_made_by;
            uint16 version_needed;
            uint32 disk_number;
            uint32 disk_number_with_cd;
            uint64 total_entries_disk;
            uint64 total_entries;
            uint64 size_of_cd;
            uint64 offset_of_cd;
        } zip64_end_of_central_directory_t;
    """

    HEADER_STRUCT = "end_of_central_directory_t"

    # empty password with -p will make sure the command will not hang
    EXTRACTOR = Command("7z", "x", "-p", "-y", "{inpath}", "-o{outdir}")

    def has_encrypted_files(
        self,
        file: File,
        start_offset: int,
        end_of_central_directory: Instance,
    ) -> bool:
        # https://pkware.cachefly.net/webdocs/APPNOTE/APPNOTE-6.3.10.TXT
        # 4.4.4 general purpose bit flag: (2 bytes)
        # Bit 0: If set, indicates that the file is encrypted.
        file.seek(start_offset + end_of_central_directory.offset_of_cd, io.SEEK_SET)
        for _ in range(0, end_of_central_directory.total_entries):
            cd_header = self.cparser_le.cd_file_header_t(file)
            if cd_header.flags & self.ENCRYPTED_FLAG:
                return True
        return False

    @staticmethod
    def is_zip64_eocd(end_of_central_directory: Instance):
        # see https://pkware.cachefly.net/webdocs/APPNOTE/APPNOTE-6.3.1.TXT section J
        return (
            end_of_central_directory.disk_number == 0xFFFF
            or end_of_central_directory.disk_number_with_cd == 0xFFFF
            or end_of_central_directory.disk_entries == 0xFFFF
            or end_of_central_directory.total_entries == 0xFFFF
            or end_of_central_directory.size_of_cd == 0xFFFFFFFF
            or end_of_central_directory.offset_of_cd == 0xFFFFFFFF
        )

    def _parse_zip64(self, file: File, eocd_offset: int) -> Tuple[int, Instance]:
        # ZIP64 EOCD locator is right before the EOCD record
        eocd_locator_offset = eocd_offset - len(
            self.cparser_le.zip64_end_of_central_directory_locator_t
        )
        if eocd_locator_offset < 0:
            raise InvalidInputFormat("Zip64 offset negative")
        file.seek(eocd_locator_offset, io.SEEK_SET)
        eocd_locator = self.cparser_le.zip64_end_of_central_directory_locator_t(file)
        logger.debug("eocd_locator", eocd_locator=eocd_locator, _verbosity=3)
        if eocd_locator.signature != self.ZIP64_EOCD_LOCATOR_SIGNATURE:
            raise InvalidInputFormat("Zip64 EOCD Locator not found")

        zip64_eocd_offset = eocd_locator_offset - len(
            self.cparser_le.zip64_end_of_central_directory_t
        )
        if zip64_eocd_offset < 0:
            raise InvalidInputFormat("Zip64 offset negative")
        file.seek(zip64_eocd_offset, io.SEEK_SET)
        zip64_eocd = self.cparser_le.zip64_end_of_central_directory_t(file)
        if zip64_eocd.signature != self.ZIP64_EOCD_SIGNATURE:
            raise InvalidInputFormat("Zip64 EOCD not found")
        return zip64_eocd_offset, zip64_eocd

    def calculate_chunk(self, file: File, start_offset: int) -> Optional[ValidChunk]:
        # start_offset = start of EOCD record
        # EOCD = end of central directory
        eocd_offset = start_offset
        # from here calculate the beginning of the zip file (needs to interpret the CD offsets)
        # REASON: EOCD SIGNATURE is much rarer when there are many embedded zip files in a blob
        # while there are a lot of LOCAL FILE HEADER SIGNATUREs

        end_of_central_directory = self.parse_header(file)
        assert end_of_central_directory.signature == self.EOCD_SIGNATURE
        end_offset = eocd_offset + len(end_of_central_directory)

        if self.is_zip64_eocd(end_of_central_directory):
            logger.debug("Hit Zip64 EOCD")
            eocd_offset, end_of_central_directory = self._parse_zip64(file, eocd_offset)

        # the EOCD offset is equal to the offset of CD + size of CD
        start_offset = (
            eocd_offset
            - end_of_central_directory.size_of_cd
            - end_of_central_directory.offset_of_cd
        )

        logger.debug(
            "Zip chunk candidate",
            start_offset=start_offset,
            end_offset=end_offset,
            header=end_of_central_directory,
        )
        if start_offset < 0:
            raise InvalidInputFormat("Bad EOCD record header in ZIP chunk candidate.")

        file.seek(start_offset, io.SEEK_SET)
        signature = self.cparser_le.char[4](file)
        if signature != self.LOCAL_FILE_HEADER_SIGNATURE:
            logger.debug(
                "Bad local file header signature", signature=signature.hex(" ")
            )
            raise InvalidInputFormat("Bad EOCD record header in ZIP chunk candidate.")

        has_encrypted_files = self.has_encrypted_files(
            file, start_offset, end_of_central_directory
        )

        return ValidChunk(
            start_offset=start_offset,
            end_offset=end_offset,
            is_encrypted=has_encrypted_files,
        )
