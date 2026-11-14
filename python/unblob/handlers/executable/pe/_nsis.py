"""Nullsoft (NSIS) installers: the exehead stub followed by the installer data."""

import binascii
import io
from pathlib import Path

from unblob.extractors import Command
from unblob.file_utils import (
    Endian,
    File,
    SeekError,
    StructParser,
    iterate_file,
    round_up,
)
from unblob.models import ExtractError, Extractor, ExtractResult, Reference
from unblob.report import ExtractionProblem

from ._headers import PEHeaders
from ._payload import PEPayload

# The NSIS firstheader follows Source/exehead/fileform.h of NSIS 3.11:
#   https://github.com/kichik/nsis/blob/v311/Source/exehead/fileform.h
C_DEFINITIONS = r"""
    typedef struct nsis_firstheader {
        uint32 flags;             // FH_FLAGS_*
        uint32 siginfo;           // FH_SIG
        char   nsinst[12];        // FH_INT1, FH_INT2, FH_INT3
        uint32 length_of_header;
        // length of all the data, including the firstheader and CRC
        uint32 length_of_all_following_data;
    } nsis_firstheader_t;
"""

NSIS_SIGINFO = 0xDEADBEEF
NSIS_MAGIC = b"NullsoftInst"
# The NSIS stub looks for the firstheader at 512 byte boundaries of the installer
NSIS_ALIGNMENT = 512
# FH_FLAGS_MASK: uninstall, silent, no CRC, force CRC
NSIS_FLAGS_MASK = 0xF
# FH_FLAGS_NO_CRC: built with "CRCCheck off" or /NCRC
NSIS_FLAG_NO_CRC = 4
# The CRC-32 covers the installer from its 512th byte up to the CRC itself, the last 4
# bytes of the installer data: the stub (but its first 512 bytes), the firstheader and
# the compressed data. Checked against NSIS 3.11 installers.
NSIS_CRC_START = 512
NSIS_CRC_SIZE = 4

_parser = StructParser(C_DEFINITIONS)


def _find_firstheader(file: File, headers: PEHeaders, image_end: int):
    """Return the offset (relative to the PE start) and the parsed firstheader, if any.

    makensis appends the firstheader and the compressed data right after the stub, whose
    FileAlignment of 512 puts them at the next 512 byte boundary.
    """
    firstheader_offset = round_up(image_end, NSIS_ALIGNMENT)
    try:
        file.seek(headers.start_offset + firstheader_offset, io.SEEK_SET)
        firstheader = _parser.parse("nsis_firstheader_t", file, Endian.LITTLE)
    except (EOFError, SeekError):
        # probing: a PE at the end of the file has no installer data
        return None
    if (
        firstheader.siginfo != NSIS_SIGINFO
        or firstheader.nsinst != NSIS_MAGIC
        or firstheader.flags & ~NSIS_FLAGS_MASK
        or firstheader.length_of_all_following_data < len(firstheader)
    ):
        return None
    return firstheader_offset, firstheader


class NSISExtractor(Extractor):
    """Verify the installer CRC, then extract the installer with 7-Zip.

    7-Zip does not verify the CRC. A mismatch (e.g. an installer modified after it was
    built) is reported, and the installer is extracted anyway.
    """

    def __init__(self):
        self.command = Command("7z", "x", "-y", "{inpath}", "-o{outdir}")

    def get_dependencies(self) -> list[str]:
        return self.command.get_dependencies()

    def extract(self, inpath: Path, outdir: Path) -> ExtractResult | None:
        with File.from_path(inpath) as file:
            # the carved chunk starts with the PE
            headers = PEHeaders.parse(file, 0)
            found = _find_firstheader(file, headers, headers.get_image_end(file))
            if found is None:
                raise ExtractError(
                    ExtractionProblem(
                        problem="NSIS installer data not found in the chunk",
                        resolution="Skipped",
                    )
                )
            firstheader_offset, firstheader = found
            problems = []
            if not firstheader.flags & NSIS_FLAG_NO_CRC:
                problem = self._check_crc(
                    file,
                    firstheader_offset + firstheader.length_of_all_following_data,
                )
                if problem is not None:
                    problems.append(problem)

        try:
            self.command.extract(inpath, outdir)
        except ExtractError as exc:
            raise ExtractError(*problems, *exc.reports) from exc
        return ExtractResult(reports=problems)

    @staticmethod
    def _check_crc(file: File, end: int) -> ExtractionProblem | None:
        crc_offset = end - NSIS_CRC_SIZE
        computed = 0
        for data in iterate_file(file, NSIS_CRC_START, crc_offset - NSIS_CRC_START):
            computed = binascii.crc32(data, computed)
        file.seek(crc_offset, io.SEEK_SET)
        stored = _parser.parse("uint32", file, Endian.LITTLE)
        if computed == stored:
            return None
        return ExtractionProblem(
            problem=f"NSIS installer CRC mismatch: stored {stored:#010x}, "
            f"computed {computed:#010x}",
            resolution="Extracted anyway",
        )


class NSISPayload(PEPayload):
    """Nullsoft (NSIS) installer data appended to the exehead stub."""

    name = "NSIS"
    extractor = NSISExtractor()
    description = (
        "Nullsoft (NSIS) installers are carved with their appended installer data and "
        "extracted with 7-Zip, after their CRC is verified (a mismatch is reported)."
    )
    references = [
        Reference(
            title="NSIS firstheader definition (fileform.h, v3.11)",
            url="https://github.com/kichik/nsis/blob/v311/Source/exehead/fileform.h",
        ),
    ]
    limitations = [
        "NSIS data is only looked for at the first 512 byte boundary after the PE "
        "image, where makensis writes it.",
        "The CRC of NSIS installers built without CRC check (CRCCheck off) is not "
        "verified.",
    ]

    def get_end(self, file: File, headers: PEHeaders, image_end: int) -> int | None:
        found = _find_firstheader(file, headers, image_end)
        if found is None:
            return None
        firstheader_offset, firstheader = found
        # the CRC is verified on extraction, see NSISExtractor
        return firstheader_offset + firstheader.length_of_all_following_data
