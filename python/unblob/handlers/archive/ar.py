import os
from pathlib import Path
from typing import Optional

import arpy
from structlog import get_logger

from ...file_utils import FileSystem, OffsetFile, iterate_file
from ...models import (
    Extractor,
    ExtractResult,
    File,
    Handler,
    HandlerDoc,
    HandlerType,
    HexString,
    Reference,
    ValidChunk,
)
from ...report import ExtractionProblem

logger = get_logger()


HEADER_LENGTH = 0x44
SIGNATURE_LENGTH = 0x8


class ArExtractor(Extractor):
    def extract(self, inpath: Path, outdir: Path) -> Optional[ExtractResult]:
        fs = FileSystem(outdir)

        with arpy.Archive(inpath.as_posix()) as archive:
            archive.read_all_headers()

            for name in sorted(archive.archived_files):
                archived_file = archive.archived_files[name]

                try:
                    path = Path(name.decode())
                except UnicodeDecodeError:
                    path = Path(name.decode(errors="replace"))
                    fs.record_problem(
                        ExtractionProblem(
                            path=repr(name),
                            problem="Path is not a valid UTF/8 string",
                            resolution=f"Converted to {path}",
                        )
                    )

                fs.write_chunks(
                    path,
                    chunks=iterate_file(
                        archived_file,
                        0,
                        archived_file.header.size,
                    ),
                )

        return ExtractResult(reports=fs.problems)


class ARHandler(Handler):
    NAME = "ar"

    PATTERNS = [
        HexString(
            """
            // "!<arch>\\n", 58 chars of whatever, then the ARFMAG
            21 3C 61 72 63 68 3E 0A [58] 60 0A
            """
        )
    ]

    EXTRACTOR = ArExtractor()

    DOC = HandlerDoc(
        name="AR",
        description="Unix AR (archive) files are used to store multiple files in a single archive with a simple header format.",
        handler_type=HandlerType.ARCHIVE,
        vendor=None,
        references=[
            Reference(
                title="Unix AR File Format Documentation",
                url="https://en.wikipedia.org/wiki/Ar_(Unix)",
            )
        ],
        limitations=[],
    )

    def calculate_chunk(self, file: File, start_offset: int) -> Optional[ValidChunk]:
        offset_file = OffsetFile(file, start_offset)
        ar = arpy.Archive(fileobj=offset_file)  # type: ignore

        try:
            ar.read_all_headers()
        except arpy.ArchiveFormatError as exc:
            logger.debug(
                "Hit an ArchiveFormatError, we've probably hit some other kind of data",
                exc_info=exc,
            )

            # wind the cursor back the whole header length to check if we failed on
            # the first match, which means malformed AR archive
            ar.file.seek(-HEADER_LENGTH, os.SEEK_CUR)
            # we check if we failed on the first match
            if start_offset == file.tell():
                return None
            # otherwise we seek past the signature (failure on malformed AR archive
            # within the whole file, not at the start)
            ar.file.seek(SIGNATURE_LENGTH, os.SEEK_CUR)

        return ValidChunk(
            start_offset=start_offset,
            end_offset=file.tell(),
        )
