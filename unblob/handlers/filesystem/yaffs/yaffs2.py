import io
from pathlib import Path
from typing import Optional

from structlog import get_logger

from unblob.file_utils import File, read_until_past, snull
from unblob.handlers.filesystem.yaffs.utils import (
    C_DEFINITIONS,
    YAFFS2Chunk,
    YAFFS2Entry,
    YAFFSConfig,
    YAFFSFileVar,
    YAFFSParser,
    decode_file_size,
    is_valid_header,
    iterate_over_file,
)
from unblob.models import Extractor, HexString, StructHandler, ValidChunk

logger = get_logger()


class YAFFS2Parser(YAFFSParser):
    def build_chunk(self, spare: bytes, config: YAFFSConfig) -> YAFFS2Chunk:
        # images built without ECC have two superfluous bytes before the chunk ID.
        if not config.ecc:
            # adding two null bytes at the end only works if it's LE
            spare = spare[2:] + b"\x00\x00"

        yaffs2_packed_tags = self._struct_parser.parse(
            "yaffs2_packed_tags_t", spare, self.config.endianness
        )
        logger.debug(
            "yaffs2_packed_tags_t",
            yaffs2_packed_tags=yaffs2_packed_tags,
            config=config,
            _verbosity=3,
        )

        return YAFFS2Chunk(
            id=yaffs2_packed_tags.chunk_id,
            seq_number=yaffs2_packed_tags.seq_number,
            byte_count=yaffs2_packed_tags.byte_count,
            object_id=yaffs2_packed_tags.object_id,
        )

    def parse(self):  # noqa: C901
        count = 0
        for offset, page, spare in iterate_over_file(self.file, self.config):
            try:
                chunk = self.build_chunk(spare, self.config)
            except EOFError:
                break

            yaffs_obj_hdr = self._struct_parser.parse(
                "yaffs2_obj_hdr_t", page, self.config.endianness
            )
            logger.debug("yaffs2_obj_hdr_t", yaffs_obj_hdr=yaffs_obj_hdr, _verbosity=3)

            if chunk.id == 0:
                try:
                    yaffs_obj_hdr = self._struct_parser.parse(
                        "yaffs2_obj_hdr_t", page, self.config.endianness
                    )
                    logger.debug(
                        "yaffs2_obj_hdr_t", yaffs_obj_hdr=yaffs_obj_hdr, _verbosity=3
                    )
                except EOFError:
                    break

                if not is_valid_header(yaffs_obj_hdr):
                    break

                entry = YAFFS2Entry(
                    object_id=chunk.object_id,
                    chunks=[],
                    type=yaffs_obj_hdr.type,
                    parent_obj_id=yaffs_obj_hdr.parent_obj_id,
                    sum_no_longer_used=yaffs_obj_hdr.sum_no_longer_used,
                    name=snull(yaffs_obj_hdr.name[:-1]).decode("utf-8"),
                    chksum=yaffs_obj_hdr.chksum,
                    yst_mode=yaffs_obj_hdr.yst_mode,
                    yst_uid=yaffs_obj_hdr.yst_uid,
                    yst_gid=yaffs_obj_hdr.yst_gid,
                    yst_atime=yaffs_obj_hdr.yst_atime,
                    yst_mtime=yaffs_obj_hdr.yst_mtime,
                    yst_ctime=yaffs_obj_hdr.yst_ctime,
                    equiv_id=yaffs_obj_hdr.equiv_id,
                    alias=snull(yaffs_obj_hdr.alias.replace(b"\xFF", b"")).decode(
                        "utf-8"
                    ),
                    yst_rdev=yaffs_obj_hdr.yst_rdev,
                    win_ctime=yaffs_obj_hdr.win_ctime,
                    win_mtime=yaffs_obj_hdr.win_mtime,
                    inband_shadowed_obj_id=yaffs_obj_hdr.inband_shadowed_obj_id,
                    inband_is_shrink=yaffs_obj_hdr.inband_is_shrink,
                    reserved=yaffs_obj_hdr.reserved,
                    shadows_obj=yaffs_obj_hdr.shadows_obj,
                    is_shrink=yaffs_obj_hdr.is_shrink,
                    filehead=YAFFSFileVar(
                        file_size=yaffs_obj_hdr.filehead.file_size,
                        stored_size=yaffs_obj_hdr.filehead.stored_size,
                        shrink_size=yaffs_obj_hdr.filehead.shrink_size,
                        top_level=yaffs_obj_hdr.filehead.top_level,
                    ),
                    file_size=decode_file_size(
                        yaffs_obj_hdr.file_size_high, yaffs_obj_hdr.file_size_low
                    ),
                    start_offset=offset,
                )
                self.insert_entry(entry)
                count += 1
            else:
                # this is a data chunk, so we add it to our object
                entry = self.get_entry(chunk.object_id)
                # can happen during bruteforcing
                if entry is not None:
                    entry.chunks.append(chunk)
                else:
                    break

        self.end_offset = self.file.tell()
        return count


class YAFFS2Extractor(Extractor):
    def __init__(self, config: YAFFSConfig):
        self.config = config

    def extract(self, inpath: Path, outdir: Path):
        infile = File.from_path(inpath)
        parser = YAFFS2Parser(infile, self.config)
        parser.parse()
        parser.extract(outdir)


class YAFFS2Handler(StructHandler):
    NAME = "yaffs2"

    C_DEFINITIONS = C_DEFINITIONS

    HEADER_STRUCT = "yaffs_obj_hdr_t"

    PATTERNS = [
        HexString(
            "03 00 00 00 01 00 00 00 ff ff // YAFFS_OBJECT_TYPE_DIRECTORY in little endian"
        ),
        HexString(
            "01 00 00 00 01 00 00 00 ff ff // YAFFS_OBJECT_TYPE_FILE in little endian"
        ),
        HexString(
            "00 00 00 03 00 00 00 01 ff ff // YAFFS_OBJECT_TYPE_DIRECTORY in big endian"
        ),
        HexString(
            "00 00 00 01 00 00 00 01 ff ff // YAFFS_OBJECT_TYPE_FILE in big endian"
        ),
    ]

    BIG_ENDIAN_MAGIC = 0x00_00_00_01

    EXTRACTOR = None

    def calculate_chunk(self, file: File, start_offset: int) -> Optional[ValidChunk]:
        parser = YAFFS2Parser(file)
        parser.parse()
        self.EXTRACTOR = YAFFS2Extractor(parser.config)

        # skip 0xFF padding
        file.seek(parser.end_offset, io.SEEK_SET)
        read_until_past(file, b"\xff")
        return ValidChunk(start_offset=start_offset, end_offset=file.tell())
