import io
from typing import List, Optional

from structlog import get_logger

from unblob.file_utils import Endian, convert_int16, read_until_past, round_up

from ...models import StructHandler, ValidChunk

logger = get_logger()


BLOCK_ALIGNMENT = 4
JFFS2_MAGICS = [0x1985, 0x8519, 0x1984, 0x8419]

# Compatibility flags.
JFFS2_COMPAT_MASK = 0xC000
JFFS2_NODE_ACCURATE = 0x2000
JFFS2_FEATURE_INCOMPAT = 0xC000
JFFS2_FEATURE_ROCOMPAT = 0x8000
JFFS2_FEATURE_RWCOMPAT_COPY = 0x4000
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

    def guess_endian(self, file: io.BufferedIOBase) -> Endian:
        magic = convert_int16(file.read(2), Endian.BIG)
        if magic == self.BIG_ENDIAN_MAGIC:
            endian = Endian.BIG
        else:
            endian = Endian.LITTLE
        file.seek(-2, io.SEEK_CUR)
        return endian

    def calculate_chunk(
        self, file: io.BufferedIOBase, start_offset: int
    ) -> Optional[ValidChunk]:

        file.seek(0, io.SEEK_END)
        eof = file.tell()
        file.seek(start_offset)

        endian = self.guess_endian(file)
        current_offset = start_offset

        while current_offset < eof:
            node_start_offset = current_offset
            file.seek(current_offset)
            header = self.parse_header(file, endian=endian)

            if header.magic not in JFFS2_MAGICS:
                # JFFS2 allows padding at the end with 0xFF or 0x00, usually
                # to the size of an erase block.
                if header.magic in [0x0000, 0xFFFF]:
                    file.seek(-len(header), io.SEEK_CUR)
                    current_offset = read_until_past(file, b"\x00\xFF")
                    continue
                else:
                    logger.debug("unexpected header magic", header_magic=header.magic)
                    break

            if header.nodetype not in JFFS2_NODETYPES:
                logger.debug("Invalid JFFS2 node type", node_type=header.nodetype)
                return

            if node_start_offset + header.totlen > eof:
                logger.debug(
                    "node length greater than total file size",
                    node_len=header.totlen,
                    file_size=eof,
                )
                return

            if header.totlen < len(header):
                logger.debug(
                    "node length greater than header size", node_len=header.totlen
                )
                return

            node_len = round_up(header.totlen, BLOCK_ALIGNMENT)
            file.seek(node_len, io.SEEK_CUR)
            current_offset += node_len

        if current_offset > eof:
            # corrupt file or last chunk isn't really jffs2
            return

        return ValidChunk(
            start_offset=start_offset,
            end_offset=current_offset,
        )

    @staticmethod
    def make_extract_command(inpath: str, outdir: str) -> List[str]:
        return ["jefferson", "-v", "-f", "-d", outdir, inpath]


class JFFS2OldHandler(_JFFS2Base):

    NAME = "jffs2_old"

    YARA_RULE = r"""
        strings:
            $jffs2_old_le = { 84 19 ( 01 | 02 | 03 | 04 | 06 | 08 | 09 ) ( e0 | 20 ) }
            $jffs2_old_be = { 19 84 ( e0 | 20 ) ( 01 | 02 | 03 | 04 | 06 | 08 | 09 ) }
        condition:
            $jffs2_old_le or $jffs2_old_be
    """

    BIG_ENDIAN_MAGIC = 0x19_84


class JFFS2NewHandler(_JFFS2Base):

    NAME = "jffs2_new"

    YARA_RULE = r"""
        strings:
            $jffs2_new_le = { 85 19 ( 01 | 02 | 03 | 04 | 06 | 08 | 09 ) ( e0 | 20 ) }
            $jffs2_new_be = { 19 85 ( e0 | 20 ) ( 01 | 02 | 03 | 04 | 06 | 08 | 09 ) }
        condition:
            $jffs2_new_le or $jffs2_new_be
    """

    BIG_ENDIAN_MAGIC = 0x19_85
