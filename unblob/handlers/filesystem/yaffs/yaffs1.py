import io
from pathlib import Path
from typing import Optional

from structlog import get_logger

from unblob.file_utils import get_endian, read_until_past, snull
from unblob.handlers.filesystem.yaffs.utils import (
    C_DEFINITIONS,
    YAFFS1Chunk,
    YAFFS1Entry,
    YAFFSChunk,
    YAFFSConfig,
    YAFFSParser,
    is_valid_header,
    iterate_over_file,
)

from ....models import Extractor, File, HexString, StructHandler, ValidChunk

logger = get_logger()

BIG_ENDIAN_MAGIC = 0x00_00_00_03


class YAFFS1Parser(YAFFSParser):
    def build_chunk(self, spare: bytes) -> YAFFSChunk:
        yaffs_sparse = self._struct_parser.parse(
            "yaffs_spare_t", spare, self.config.endianness
        )

        yaffs_packed_tags = self._struct_parser.parse(
            "yaffs1_packed_tags_t",
            bytes(
                [
                    yaffs_sparse.tag_b0,
                    yaffs_sparse.tag_b1,
                    yaffs_sparse.tag_b2,
                    yaffs_sparse.tag_b3,
                    yaffs_sparse.tag_b4,
                    yaffs_sparse.tag_b5,
                    yaffs_sparse.tag_b6,
                    yaffs_sparse.tag_b7,
                ]
            ),
            self.config.endianness,
        )

        return YAFFS1Chunk(
            id=yaffs_packed_tags.chunk_id,
            serial=yaffs_packed_tags.serial,
            byte_count=yaffs_packed_tags.byte_count,
            object_id=yaffs_packed_tags.object_id,
            ecc=yaffs_packed_tags.ecc,
            page_status=yaffs_sparse.page_status,
            block_status=yaffs_sparse.block_status,
        )

    def parse(self):
        for offset, page, spare in iterate_over_file(self.file, self.config):
            chunk = self.build_chunk(spare)

            # A chunkId of zero indicates that this chunk holds a yaffs_ObjectHeader.
            if chunk.id == 0:
                yaffs_obj_hdr = self._struct_parser.parse(
                    "yaffs1_obj_hdr_t", page, self.config.endianness
                )
                logger.debug(
                    "yaffs1_obj_hdr_t", yaffs_obj_hdr=yaffs_obj_hdr, _verbosity=3
                )

                if not is_valid_header(yaffs_obj_hdr):
                    break

                if b"\xFF" not in yaffs_obj_hdr.alias:
                    alias = (snull(yaffs_obj_hdr.alias).decode("utf-8"),)
                else:
                    alias = ""

                entry = YAFFS1Entry(
                    type=yaffs_obj_hdr.type,
                    object_id=chunk.object_id,
                    parent_obj_id=yaffs_obj_hdr.parent_obj_id,
                    sum_no_longer_used=yaffs_obj_hdr.sum_no_longer_used,
                    name=snull(yaffs_obj_hdr.name[0:128]).decode("utf-8"),
                    alias=alias,
                    file_size=yaffs_obj_hdr.file_size,
                    start_offset=offset,
                    chunks=[],
                )
                self.insert_entry(entry)
            else:
                # this is a data chunk, so we add it to our object
                self.get_entry(chunk.object_id).chunks.append(chunk)
        self.end_offset = self.file.tell()


class YAFFS1Extractor(Extractor):
    def extract(self, inpath: Path, outdir: Path):
        infile = File.from_path(inpath)
        config = YAFFSConfig(
            page_size=512,
            spare_size=16,
            endianness=get_endian(infile, BIG_ENDIAN_MAGIC),
            ecc=False,
        )
        parser = YAFFS1Parser(infile, config)
        parser.parse()
        parser.extract(outdir)


class YAFFS1Handler(StructHandler):
    NAME = "yaffs1"

    # YAFFS1 images always have a first entry as a directory entry with an empty name
    # this is how it's done in mkyaffsimage:
    # write_object_header(1, YAFFS_OBJECT_TYPE_DIRECTORY, &stats, 1,"", -1, NULL);
    PATTERNS = [
        HexString(
            "03 00 00 00 01 00 00 00 ff ff 00 00 00 00 00 00 // LE, Look for YAFFS_OBJECT_TYPE_DIRECTORY with a null name"
        ),
        HexString("00 00 00 03 00 00 00 01 ff ff 00 00 00 00 00 00 // BE"),
    ]

    C_DEFINITIONS = C_DEFINITIONS
    EXTRACTOR = YAFFS1Extractor()

    def calculate_chunk(self, file: File, start_offset: int) -> Optional[ValidChunk]:
        # from https://yaffs.net/archives/yaffs-development-notes: currently each chunk
        # is the same size as a NAND flash page (ie. 512 bytes + 16 byte spare).
        # In the future we might decide to allow for different chunk sizes.
        config = YAFFSConfig(
            page_size=512,
            spare_size=16,
            endianness=get_endian(file, BIG_ENDIAN_MAGIC),
            ecc=False,
        )
        parser = YAFFS1Parser(file, config)
        parser.parse()
        # skip 0xFF padding
        file.seek(parser.end_offset, io.SEEK_SET)
        read_until_past(file, b"\xff")
        return ValidChunk(start_offset=start_offset, end_offset=file.tell())
