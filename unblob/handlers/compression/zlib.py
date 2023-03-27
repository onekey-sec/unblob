import re
import zlib
from pathlib import Path
from typing import Optional

from structlog import get_logger

from unblob.handlers.archive.dmg import DMGHandler

from ...file_utils import DEFAULT_BUFSIZE, InvalidInputFormat
from ...models import Extractor, File, Handler, HexString, ValidChunk

logger = get_logger()


class ZlibExtractor(Extractor):
    def extract(self, inpath: Path, outdir: Path):
        decompressor = zlib.decompressobj()
        outpath = outdir / "zlib.uncompressed"
        with File.from_path(inpath) as f, outpath.open("wb") as outfile:
            content = f.read(DEFAULT_BUFSIZE)
            while content and not decompressor.eof:
                outfile.write(decompressor.decompress(content))
                content = f.read(DEFAULT_BUFSIZE)


class ZlibHandler(Handler):
    NAME = "zlib"

    PATTERNS = [
        HexString("78 01"),  # low compression
        HexString("78 9c"),  # default compression
        HexString("78 da"),  # best compression
        HexString("78 5e"),  # compressed
    ]

    EXTRACTOR = ZlibExtractor()

    def calculate_chunk(self, file: File, start_offset: int) -> Optional[ValidChunk]:
        for pattern in DMGHandler.PATTERNS:
            if re.search(pattern.as_regex(), file[-512:]):
                raise InvalidInputFormat(
                    "File is a DMG archive made of zlib streams. Aborting."
                )

        decompressor = zlib.decompressobj()

        try:
            content = file.read(DEFAULT_BUFSIZE)
            while content and not decompressor.eof:
                decompressor.decompress(content)
                content = file.read(DEFAULT_BUFSIZE)

        except zlib.error:
            raise InvalidInputFormat("invalid zlib stream") from None

        end_offset = file.tell() - len(decompressor.unused_data)

        return ValidChunk(
            start_offset=start_offset,
            end_offset=end_offset,
        )
