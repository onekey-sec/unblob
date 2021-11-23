import io
import logging
from typing import List, Union
from zipfile import ZipFile

from dissect.cstruct import cstruct
from structlog import get_logger

from ...file_utils import LimitedStartReader
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


def _find_end_of_zip(file: io.BufferedReader, start_offset: int) -> int:
    """Find the end of the zip file
    by looking for the end of central directory header bytes, verifying, then
    returning the end of the end of central directory header structure.
    """
    file.seek(start_offset)
    content = file.read()
    end_marker = content.find(b"\x50\x4b\x05\x06")
    if end_marker == -1:
        logging.debug(
            f"ZIP (0x{start_offset:x}): No End of Central Directory headers in the rest of the stream."
        )
        return 0

    file.seek(start_offset + end_marker)
    header = cparser.end_of_central_directory(file)

    try:
        header.zip_file_comment.decode("utf-8")
    except UnicodeDecodeError:
        return _find_end_of_zip(file, start_offset + end_marker + 22)

    return start_offset + end_marker + len(header)


def _guess_zip_size(file: LimitedStartReader, start_offset: int):
    # If we just pass a full firmware blob to zipfile.ZipFile, somehow,
    # the way that it is parsed means that only the final zipfile in the
    # blob is recognised, if at all. Sometimes, if the firmware is just
    # a big blob of lots of other things, then ZipFile will just throw an
    # error. Basically, ZipFile is really bad at dealing with anything
    # which isn't actually a ZIP.

    # For this reason, we need to try to guess the length of the ZIP file
    # chunk within our firmware image, and then carve that chunk out.
    # Then, we make this is a BytesIO stream, so we can just pass this
    # stream to ZipFile.

    file_names = set()
    encrypted_files = set()
    zip_end = _find_end_of_zip(file, start_offset)

    file.seek(start_offset)
    content = io.BytesIO(file.read(zip_end - start_offset))

    with ZipFile(content) as z:
        logger.info("Found ZIP filenames", filenames=[x.filename for x in z.infolist()])
        for g in z.infolist():
            if g.flag_bits & 0b0001:
                encrypted_files.add(g.filename)
            file_names.add(g.filename)

    size = zip_end - start_offset
    return size


def calculate_chunk(
    file: LimitedStartReader, start_offset: int
) -> Union[ValidChunk, UnknownChunk]:
    header = cparser.local_file_header(file)
    if header.version_needed_to_extract > MAXIMUM_VERSION:
        return UnknownChunk(
            start_offset=start_offset,
            reason=f"ZIP (0x{start_offset:x}): Version too high!",
        )

    size = _guess_zip_size(file, start_offset)
    return ValidChunk(
        start_offset=start_offset,
        end_offset=start_offset + size,
    )


def make_extract_command(inpath: str, outdir: str) -> List[str]:
    return ["unzip", inpath, "-d", outdir]
