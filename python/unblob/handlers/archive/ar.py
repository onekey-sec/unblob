from pathlib import Path

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


class ArExtractor(Extractor):
    def extract(self, inpath: Path, outdir: Path) -> ExtractResult | None:
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

    def calculate_chunk(self, file: File, start_offset: int) -> ValidChunk | None:
        offset_file = OffsetFile(file, start_offset)
        ar = arpy.Archive(fileobj=offset_file)  # type: ignore

        try:
            ar.read_all_headers()
        except arpy.ArchiveFormatError as exc:
            logger.debug(
                "Hit an ArchiveFormatError, we've probably hit some other kind of data",
                exc_info=exc,
            )
            # failing on the very first member header means this is not an AR archive
            if not ar.headers:
                return None

        # arpy tracks where the next member header would start, which is the end
        # of the last member it parsed (padded to an even offset). Unlike the file
        # position, it does not depend on how many bytes follow the archive.
        return ValidChunk(
            start_offset=start_offset,
            end_offset=start_offset + ar.next_header_offset,
        )
