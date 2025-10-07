from pathlib import Path
from typing import Optional

import io
import lief

from structlog import get_logger

from unblob.extractors.command import Command

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

lief.logging.disable()

logger = get_logger()


class PEExtractor(Extractor):
    """
    PEExtractor extracts files embedded within PEs such as installers.
    """

    def extract(self, inpath: Path, outdir: Path) -> Optional[ExtractResult]:
        binary = lief.PE.parse(inpath)
        if not binary:
            return None

        if not self.is_nsis(binary):
            return None

        return Command("7z", "x", "-y", "{inpath}", "-o{outdir}").extract(inpath, outdir)


    def is_nsis(self, binary: lief.PE.Binary) -> bool:
        """
        Test if binary appears to be a Nullsoft Installer self-extracting archive

        TODO: this series of tests is possibly too strict
        """

        return binary.has_resources and \
            binary.resources_manager.has_manifest and \
            "Nullsoft" in binary.resources_manager.manifest



class PEHandler(Handler):
    NAME = "pe"

    PATTERNS = [
        HexString(
            """
            // MZ header
            4d 5a
            """
        ),
        HexString(
            """
            // PE header
            50 45 00 00
            """
        )
    ]


    EXTRACTOR = PEExtractor()


    DOC = HandlerDoc(
        name="pe",
        description="The PE (Portable Executable) is a binary file format used for executable code on 32-bit and 64-bit Windows operating systems as well as in UEFI environments.",
        handler_type=HandlerType.EXECUTABLE,
        vendor=None,
        references=[
            Reference(
                title="PE Format",
                url="https://learn.microsoft.com/en-us/windows/win32/debug/pe-format",
            ),
            Reference(
                title="Portable Executable Wikipedia",
                url="https://en.wikipedia.org/wiki/Portable_Executable",
            ),
        ],
        limitations=[],
    )


    def calculate_chunk(self, file: File, start_offset: int) -> Optional[ValidChunk]:
        file.seek(start_offset, io.SEEK_SET)

        binary = lief.PE.parse(file)
        if not binary:
            return None

        return ValidChunk(
            start_offset = start_offset,
            end_offset = start_offset + binary.original_size,
        )
