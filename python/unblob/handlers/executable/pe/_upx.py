"""PE images compressed by UPX."""

import io
from enum import IntEnum

from unblob.extractors import Command
from unblob.file_utils import Endian, File, StructParser
from unblob.models import Reference

from ._headers import Machine, PEHeaders
from ._payload import PEPayload

# The UPX packheader follows src/packhead.cpp of UPX 4.2.2, checked against files packed
# by upx 4.2.2 (packheader version 13):
#   https://github.com/upx/upx/blob/v4.2.2/src/packhead.cpp
C_DEFINITIONS = r"""
    typedef struct upx_packheader {
        char   magic[4];          // "UPX!"
        uint8  version;
        uint8  format;            // UPX_F_*
        uint8  method;            // compression method
        uint8  level;             // compression level
        uint32 u_adler;           // Adler-32 of the uncompressed data
        uint32 c_adler;           // Adler-32 of the compressed data
        uint32 u_len;
        uint32 c_len;
        uint32 u_file_size;       // size of the original file
        uint8  filter;
        uint8  filter_cto;
        uint8  n_mru;
        uint8  header_checksum;   // sum of the bytes after the magic, modulo 251
    } upx_packheader_t;
"""

UPX_MAGIC = b"UPX!"
# the 32 byte packheader layout above starts with packheader version 10
UPX_MIN_VERSION = 10
UPX_HEADER_CHECKSUM_MODULUS = 251
# resource limit: upx writes the packheader into the few hundred bytes of header padding
MAX_UPX_HEADER_WINDOW = 0x1000

_parser = StructParser(C_DEFINITIONS)


class UPXFormat(IntEnum):
    # UPX_F_W32PE_I386 and UPX_F_W64PE_AMD64 in src/conf.h
    W32PE_I386 = 9
    W64PE_AMD64 = 36


# the PE machine a UPX format packs
UPX_FORMAT_MACHINES = {
    UPXFormat.W32PE_I386: Machine.I386,
    UPXFormat.W64PE_AMD64: Machine.AMD64,
}


class UPXPayload(PEPayload):
    """PE image compressed by UPX, restored by ``upx -d``."""

    name = "UPX"
    extractor = Command(
        "upx", "-d", "{inpath}", "-o{outdir}/{inpath.stem}.unpacked{inpath.suffix}"
    )
    description = (
        "UPX packed PE32 (i386) and PE32+ (amd64) files are unpacked with upx."
    )
    references = [
        Reference(
            title="UPX packheader definition (packhead.cpp, v4.2.2)",
            url="https://github.com/upx/upx/blob/v4.2.2/src/packhead.cpp",
        ),
    ]
    limitations = [
        "UPX is only recognised in i386 and amd64 PE files.",
        "UPX packed files whose packheader was modified or removed, as done to hinder "
        "unpacking, are processed as plain data.",
        "Only packheaders of version 10 and later are recognised; the layout was "
        "checked against files packed by upx 4.2.2 (packheader version 13).",
    ]

    def get_end(self, file: File, headers: PEHeaders, image_end: int) -> int | None:
        # upx writes the packheader into the header padding: after the section table,
        # starting before the raw data of the first section (it may run into it)
        first_raw_data = min(
            (
                section.pointer_to_raw_data
                for section in headers.sections
                if section.size_of_raw_data
            ),
            default=image_end,
        )
        window_end = min(
            first_raw_data, headers.section_table_end + MAX_UPX_HEADER_WINDOW
        )
        # the window bounds where the magic starts, the magic itself may cross its end
        magic_offset = file.find(
            UPX_MAGIC,
            headers.start_offset + headers.section_table_end,
            headers.start_offset + window_end + len(UPX_MAGIC) - 1,
        )
        if magic_offset == -1:
            return None

        file.seek(magic_offset, io.SEEK_SET)
        try:
            packheader = _parser.parse("upx_packheader_t", file, Endian.LITTLE)
        except EOFError:
            # probing: a packheader cut by the end of the file
            return None
        if not self._is_valid(packheader, headers, image_end):
            return None
        # the compressed data is inside the sections: the image is the whole payload
        return image_end

    @staticmethod
    def _is_valid(packheader, headers: PEHeaders, image_end: int) -> bool:
        # the header checksum gates any PE with a "UPX!" string in its header padding;
        # the Adler-32 checksums of the data are verified by upx on extraction. The stub
        # decompresses into the image: u_len fits in SizeOfImage, which also bounds what
        # upx allocates by what the PE maps.
        checksummed = packheader.dumps()[len(UPX_MAGIC) : -1]
        return (
            packheader.version >= UPX_MIN_VERSION
            and sum(checksummed) % UPX_HEADER_CHECKSUM_MODULUS
            == packheader.header_checksum
            and UPX_FORMAT_MACHINES.get(packheader.format)
            == headers.file_header.machine
            and packheader.c_len <= image_end
            and packheader.u_len <= headers.optional_header.size_of_image
        )
