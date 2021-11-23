import io
import zipfile
from typing import List, Union

from dissect.cstruct import cstruct
from structlog import get_logger

from ...file_utils import find_first
from ...models import UnknownChunk, ValidChunk

logger = get_logger()


NAME = "zip"

YARA_RULE = """
strings:
    $zip_header = { 50 4B 03 04 } // Local file header only
condition:
    $zip_header
"""

cparser = cstruct()
cparser.load(
    """
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
)


MAXIMUM_VERSION = 0xFF


def _calculate_zipfile_end(file: io.BufferedReader, start_offset: int) -> int:
    # If we just pass a firmware blob with multiple ZIP files in it to zipfile.ZipFile, it seems
    # that it will basically scan for the final EOCD record header, and assume that that's where
    # the file ends.
    # E.g. in the case our firmware image looks like this:
    # | ZIPFILE | SOMETHING ELSE | ZIPFILE |
    # zipfile.ZipFile() will assume:
    # |    THIS IS ALL THE SAME ZIPFILE    |
    # For obvious reasons, this is not helpful in our case. We need to try to guess the length of
    # the ZIP file chunk within our firmware image, independently, and then carve that chunk out.

    file.seek(start_offset)

    # In our case, we want to find the first instance of the EOCD record header, not the last!
    zip_end = find_first(file, b"\x50\x4b\x05\x06") + start_offset
    file.seek(zip_end)
    _ = cparser.end_of_central_directory(file)
    return file.tell()


def calculate_chunk(
    file: io.BufferedReader, start_offset: int
) -> Union[ValidChunk, UnknownChunk]:

    header = cparser.local_file_header(file)
    if header.version_needed_to_extract > MAXIMUM_VERSION:
        return UnknownChunk(
            start_offset=start_offset,
            reason=f"ZIP (0x{start_offset:x}): Version too high!",
        )

    end_of_zip = _calculate_zipfile_end(file, start_offset)

    file.seek(start_offset)

    encrypted_files = set()
    all_files = set()

    this_zip_chunk = io.BytesIO(file.read(end_of_zip - start_offset))
    with zipfile.ZipFile(this_zip_chunk) as zip:
        for zipinfo in zip.infolist():
            if zipinfo.flag_bits & 0b0001:
                encrypted_files.add(zipinfo.filename)
            all_files.add(zipinfo.filename)

    if len(encrypted_files) > 0:
        # TODO: We can't handle encrypted ZIP files yet, so we fall back to the UnknownChunk in the
        # cases where there are encrypted files in the ZIP.
        return UnknownChunk(
            start_offset=start_offset,
            end_offset=end_of_zip,
            reason="ZIP contains encrypted files.",
        )

    return ValidChunk(
        start_offset=start_offset,
        end_offset=end_of_zip,
    )


def make_extract_command(inpath: str, outdir: str) -> List[str]:
    # TODO: This will just hang waiting for user input if any the ZIP is encrypted.
    return ["unzip", inpath, "-d", outdir]
