import binascii
import io
from typing import Optional

from dissect.cstruct import Instance
from structlog import get_logger

from unblob.file_utils import (
    Endian,
    InvalidInputFormat,
    convert_int16,
    read_until_past,
    round_up,
)

from ...extractors import Command
from ...models import File, HexString, StructHandler, ValidChunk

logger = get_logger()


BLOCK_ALIGNMENT = 4
JFFS2_MAGICS = [0x1985, 0x8519, 0x1984, 0x8419]

# Compatibility flags.
JFFS2_NODE_ACCURATE = 0x2000
JFFS2_FEATURE_INCOMPAT = 0xC000
JFFS2_FEATURE_RWCOMPAT_DELETE = 0x0000

DIRENT = JFFS2_FEATURE_INCOMPAT | JFFS2_NODE_ACCURATE | 1
INODE = JFFS2_FEATURE_INCOMPAT | JFFS2_NODE_ACCURATE | 2
CLEANMARKER = JFFS2_FEATURE_RWCOMPAT_DELETE | JFFS2_NODE_ACCURATE | 3
PADDING = JFFS2_FEATURE_RWCOMPAT_DELETE | JFFS2_NODE_ACCURATE | 4
SUMMARY = JFFS2_FEATURE_RWCOMPAT_DELETE | JFFS2_NODE_ACCURATE | 6
XATTR = JFFS2_FEATURE_INCOMPAT | JFFS2_NODE_ACCURATE | 8
XREF = JFFS2_FEATURE_INCOMPAT | JFFS2_NODE_ACCURATE | 9

JFFS2_NODETYPES = {DIRENT, INODE, CLEANMARKER, PADDING, SUMMARY, XATTR, XREF}


class _JFFS2Base(StructHandler):
    C_DEFINITIONS = r"""
        typedef struct jffs2_unknown_node
        {
            uint16 magic;
            uint16 nodetype;
            uint32 totlen;
            uint32 hdr_crc;
        } jffs2_unknown_node_t;
    """

    HEADER_STRUCT = "jffs2_unknown_node_t"

    BIG_ENDIAN_MAGIC = 0x19_85

    EXTRACTOR = Command("jefferson", "-v", "-f", "-d", "{outdir}", "{inpath}")

    def guess_endian(self, file: File) -> Endian:
        magic = convert_int16(file.read(2), Endian.BIG)
        endian = Endian.BIG if magic == self.BIG_ENDIAN_MAGIC else Endian.LITTLE
        file.seek(-2, io.SEEK_CUR)
        return endian

    def valid_header(self, header: Instance, node_start_offset: int, eof: int) -> bool:
        header_crc = (binascii.crc32(header.dumps()[:-4], -1) ^ -1) & 0xFFFFFFFF
        check_crc = True

        if header.nodetype not in JFFS2_NODETYPES:
            if header.nodetype | JFFS2_NODE_ACCURATE not in JFFS2_NODETYPES:
                logger.debug(
                    "Invalid JFFS2 node type", node_type=header.nodetype, _verbosity=2
                )
                return False
            logger.debug(
                "Not accurate JFFS2 node type, ignore CRC",
                node_type=header.nodetype,
                _verbosity=2,
            )
            check_crc = False

        if check_crc and header_crc != header.hdr_crc:
            logger.debug("node header CRC missmatch", _verbosity=2)
            return False

        if node_start_offset + header.totlen > eof:
            logger.debug(
                "node length greater than total file size",
                node_len=header.totlen,
                file_size=eof,
                _verbosity=2,
            )
            return False

        if header.totlen < len(header):
            logger.debug(
                "node length greater than header size",
                node_len=header.totlen,
                _verbosity=2,
            )
            return False
        return True

    def calculate_chunk(self, file: File, start_offset: int) -> Optional[ValidChunk]:
        file.seek(0, io.SEEK_END)
        eof = file.tell()
        file.seek(start_offset)

        endian = self.guess_endian(file)
        current_offset = start_offset

        while current_offset < eof:
            node_start_offset = current_offset
            file.seek(current_offset)
            try:
                header = self.parse_header(file, endian=endian)
            except EOFError:
                break

            if header.magic not in JFFS2_MAGICS:
                # JFFS2 allows padding at the end with 0xFF or 0x00, usually
                # to the size of an erase block.
                if header.magic in [0x0000, 0xFFFF]:
                    file.seek(-len(header), io.SEEK_CUR)
                    current_offset = read_until_past(file, b"\x00\xFF")
                    continue

                logger.debug(
                    "unexpected header magic",
                    header_magic=header.magic,
                    _verbosity=2,
                )
                break

            if not self.valid_header(header, node_start_offset, eof):
                return None

            node_len = round_up(header.totlen, BLOCK_ALIGNMENT)
            current_offset += node_len

        if current_offset > eof:
            raise InvalidInputFormat("Corrupt file or last chunk isn't really JFFS2")

        return ValidChunk(
            start_offset=start_offset,
            end_offset=current_offset,
        )


class JFFS2OldHandler(_JFFS2Base):
    NAME = "jffs2_old"

    PATTERNS = [
        HexString("84 19 ( 01 | 02 | 03 | 04 | 06 | 08 | 09 ) ( e0 | 20 )"),  # LE
        HexString("19 84 ( e0 | 20 ) ( 01 | 02 | 03 | 04 | 06 | 08 | 09 )"),  # BE
    ]

    BIG_ENDIAN_MAGIC = 0x19_84


class JFFS2NewHandler(_JFFS2Base):
    NAME = "jffs2_new"

    PATTERNS = [
        HexString("85 19 ( 01 | 02 | 03 | 04 | 06 | 08 | 09 ) ( e0 | 20 )"),  # LE
        HexString("19 85 ( e0 | 20 ) ( 01 | 02 | 03 | 04 | 06 | 08 | 09 )"),  # BE
    ]

    BIG_ENDIAN_MAGIC = 0x19_85
