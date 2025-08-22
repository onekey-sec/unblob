"""MSI Handler

Extracts uses 7z for now. Could migrate to fully implementation:

    https://github.com/nightlark/pymsi
"""

from typing import Optional
import io

import pymsi
from structlog import get_logger

from unblob.extractors import Command

from ...models import (
    File,
    Handler,
    HandlerDoc,
    HandlerType,
    HexString,
    Reference,
    ValidChunk,
)

logger = get_logger()


class MsiHandler(Handler):
    NAME = "msi"

    PATTERNS = [
        HexString("D0 CF 11 E0 A1 B1 1A E1")
    ]
    EXTRACTOR = Command("7z", "x", "-p", "-y", "{inpath}", "-o{outdir}")

    DOC = HandlerDoc(
        name="MSI",
        description="Microsoft Installer (MSI) files are used for the installation, maintenance, and removal of software.",
        handler_type=HandlerType.ARCHIVE,
        vendor="Microsoft",
        references=[
            Reference(
                title="MSI File Format Documentation",
                url="https://docs.microsoft.com/en-us/windows/win32/msi/overview-of-windows-installer",
            )
        ],
        limitations=[],
    )

    def calculate_chunk(self, file: File, start_offset: int) -> Optional[ValidChunk]:
        file.seek(start_offset, io.SEEK_SET)

        try:
            # TODO: pymsi wants a path or BytesIO
            buf = io.BytesIO()
            buf.write(file[:])
            buf.seek(0)

            package = pymsi.Package(buf)
            msi = pymsi.Msi(package, True)
        except Exception:
            return None

        # MSI moves the file pointer
        msi_end_offset = buf.tell()

        return ValidChunk(
                start_offset = start_offset,
                end_offset = msi_end_offset,
        )
