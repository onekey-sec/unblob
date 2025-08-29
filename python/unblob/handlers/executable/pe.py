import io
import struct
from pathlib import Path
from typing import Optional

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
    def extract(self, inpath: Path, outdir: Path) -> Optional[ExtractResult]:
        binary = lief.PE.parse(inpath)
        if binary and self.is_nsis(binary):
            return Command("7z", "x", "-y", "{inpath}", "-o{outdir}").extract(
                inpath, outdir
            )
        return None

    def is_nsis(self, binary: lief.PE.Binary) -> bool:
        # Test if binary appears to be a Nullsoft Installer self-extracting archive
        # see https://github.com/file/file/blob/7ed3febfcd616804a2ec6495b3e5f9ccb6fc5f8f/magic/Magdir/msdos#L383

        if binary.has_resources:
            resource_manager = binary.resources_manager
            if (
                isinstance(resource_manager, lief.PE.ResourcesManager)
                and resource_manager.has_manifest
            ):
                manifest = (
                    resource_manager.manifest
                    if isinstance(resource_manager.manifest, str)
                    else resource_manager.manifest.decode(errors="ignore")
                )
                if "Nullsoft.NSIS.exehead" in manifest:
                    return True
        return False


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
        ),
    ]

    EXTRACTOR = PEExtractor()

    DOC = HandlerDoc(
        name="pe",
        description="The PE (Portable Executable) is a binary file format used for executable code on 32-bit and 64-bit Windows operating systems as well as in UEFI environments.",
        handler_type=HandlerType.EXECUTABLE,
        vendor="Microsoft",
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

        binary = lief.PE.parse(file[start_offset:])
        if not binary:
            return None

        # Check to see if we can extract the size of the full NSIS Installer by
        # including the archive size from the NSIS header.
        if binary.overlay:
            overlay = bytes(binary.overlay)

            magic_offset = overlay.find(b"NullsoftInst")
            if magic_offset != -1:
                header_start = magic_offset - 8
                if header_start < 0:
                    # Malformed NSIS header?
                    return None

                _, _, _, _, archive_size = struct.unpack(
                    "II12sII", overlay[header_start : header_start + 28]
                )

                return ValidChunk(
                    start_offset=start_offset,
                    end_offset=start_offset + binary.overlay_offset + archive_size,
                )

        return ValidChunk(
            start_offset=start_offset,
            end_offset=start_offset + binary.original_size,
        )
