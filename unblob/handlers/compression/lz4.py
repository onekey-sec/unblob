"""LZ4 handler.

Frame format definition: https://github.com/lz4/lz4/blob/dev/doc/lz4_Frame_format.md.
"""
import io
from typing import Optional

from lz4.block import LZ4BlockError, decompress
from structlog import get_logger

from unblob.extractors import Command

from ...file_utils import Endian, InvalidInputFormat, convert_int8, convert_int32
from ...models import File, Handler, HexString, ValidChunk

logger = get_logger()

SKIPPABLE_FRAMES_MAGIC = [0x184D2A50 + i for i in range(16)]
FRAME_MAGIC = 0x184D2204
LEGACY_FRAME_MAGIC = 0x184C2102
FRAME_MAGICS = [*SKIPPABLE_FRAMES_MAGIC, FRAME_MAGIC, LEGACY_FRAME_MAGIC]

_1BIT = 0x01
_2BITS = 0x03

END_MARK = 0x00000000

CONTENT_SIZE_LEN = 8
BLOCK_SIZE_LEN = (
    FRAME_SIZE_LEN
) = BLOCK_CHECKSUM_LEN = CONTENT_CHECKSUM_LEN = MAGIC_LEN = DICTID_LEN = 4
FLG_LEN = BD_LEN = HC_LEN = 1
MAX_LEGACY_BLOCK_SIZE = 8 * 1024 * 1024  # 8 MB


class FLG:
    """Represents the FLG field."""

    version: int = 0
    block_independence: int = 0
    block_checksum: int = 0
    content_size: int = 0
    content_checksum: int = 0
    dictid: int = 0

    def __init__(self, raw_flg: int):
        self.version = (raw_flg >> 6) & _2BITS
        self.block_independence = (raw_flg >> 5) & _1BIT
        self.block_checksum = (raw_flg >> 4) & _1BIT
        self.content_size = (raw_flg >> 3) & _1BIT
        self.content_checksum = (raw_flg >> 2) & _1BIT
        self.dictid = raw_flg & _1BIT

    def as_dict(self) -> dict:
        return {
            "version": self.version,
            "block_independence": self.block_independence,
            "block_checksum": self.block_checksum,
            "content_size": self.content_size,
            "content_checksum": self.content_checksum,
            "dictid": self.dictid,
        }


class _LZ4HandlerBase(Handler):
    """A common base for all LZ4 formats."""

    def _skip_magic_bytes(self, file: File):
        file.seek(MAGIC_LEN, io.SEEK_CUR)

    EXTRACTOR = Command("lz4", "--decompress", "{inpath}", "{outdir}/lz4.uncompressed")


class LegacyFrameHandler(_LZ4HandlerBase):
    NAME = "lz4_legacy"
    PATTERNS = [HexString("02 21 4C 18")]

    def calculate_chunk(self, file: File, start_offset: int) -> Optional[ValidChunk]:
        self._skip_magic_bytes(file)

        while True:
            # The last block is detected either because it is followed by the “EOF” (End of File) mark,
            # or because it is followed by a known Frame Magic Number.
            raw_bsize = file.read(BLOCK_SIZE_LEN)
            if raw_bsize == b"":  # EOF
                break

            block_compressed_size = convert_int32(raw_bsize, Endian.LITTLE)
            if block_compressed_size in FRAME_MAGICS:
                # next magic, read too far
                file.seek(-4, io.SEEK_CUR)
                break

            compressed_block = file.read(block_compressed_size)
            try:
                uncompressed_block = decompress(compressed_block, MAX_LEGACY_BLOCK_SIZE)
            except LZ4BlockError:
                raise InvalidInputFormat("Invalid LZ4 legacy frame.") from None

            # See 'fixed block size' in https://android.googlesource.com/platform/external/lz4/+/HEAD/doc/lz4_Frame_format.md#legacy-frame
            if len(uncompressed_block) < MAX_LEGACY_BLOCK_SIZE:
                break

        end_offset = file.tell()
        return ValidChunk(start_offset=start_offset, end_offset=end_offset)


class SkippableFrameHandler(_LZ4HandlerBase):
    """Can be anything, basically uncompressed data."""

    NAME = "lz4_skippable"
    PATTERNS = [HexString("5? 2A 4D 18")]

    def calculate_chunk(self, file: File, start_offset: int) -> Optional[ValidChunk]:
        self._skip_magic_bytes(file)
        frame_size = convert_int32(file.read(FRAME_SIZE_LEN), Endian.LITTLE)
        file.seek(frame_size, io.SEEK_CUR)
        end_offset = file.tell()
        return ValidChunk(start_offset=start_offset, end_offset=end_offset)


class DefaultFrameHandler(_LZ4HandlerBase):
    """Modern version, most frequently used."""

    NAME = "lz4_default"

    PATTERNS = [HexString("04 22 4D 18")]

    def calculate_chunk(self, file: File, start_offset: int) -> Optional[ValidChunk]:
        self._skip_magic_bytes(file)

        # 2. we parse the frame descriptor of dynamic size
        flg_bytes = file.read(FLG_LEN)
        raw_flg = convert_int8(flg_bytes, Endian.LITTLE)
        flg = FLG(raw_flg)
        logger.debug("Parsed FLG", **flg.as_dict())

        # skip BD (max blocksize), only useful for decoders that needs to allocate memory
        file.seek(BD_LEN, io.SEEK_CUR)

        if flg.content_size:
            file.seek(CONTENT_SIZE_LEN, io.SEEK_CUR)
        if flg.dictid:
            file.seek(DICTID_LEN, io.SEEK_CUR)

        header_checksum = convert_int8(file.read(HC_LEN), Endian.LITTLE)
        logger.debug("Header checksum (HC) read", header_checksum=header_checksum)

        # 3. we read block by block until we hit the endmarker
        while True:
            block_size = convert_int32(file.read(BLOCK_SIZE_LEN), Endian.LITTLE)
            logger.debug("block_size", block_size=block_size)
            if block_size == END_MARK:
                break
            file.seek(block_size, io.SEEK_CUR)
            if flg.block_checksum:
                file.seek(BLOCK_CHECKSUM_LEN, io.SEEK_CUR)

        # 4. we reached the endmark (0x00000000)

        # 5. if frame descriptor mentions CRC, we add CRC
        if flg.content_checksum:
            file.seek(CONTENT_CHECKSUM_LEN, io.SEEK_CUR)

        end_offset = file.tell()

        return ValidChunk(start_offset=start_offset, end_offset=end_offset)
