from pathlib import Path

import attrs

from unblob.file_utils import File, round_up
from unblob.models import (
    ExtractResult,
    Handler,
    HandlerDoc,
    HandlerType,
    HexString,
    ValidChunk,
)

from ._headers import (
    CERTIFICATE_TABLE_ALIGNMENT,
    PE_REFERENCE,
    DataDirectory,
    PEHeaders,
)
from ._nsis import NSISPayload
from ._payload import PEPayload
from ._upx import UPXPayload

# Probed in order, the first payload found is extracted. NSIS comes first: makensis can
# compress its stub with UPX (!packhdr), and the installer data is what matters then.
PAYLOADS: tuple[PEPayload, ...] = (NSISPayload(), UPXPayload())


def _join_names(payloads: tuple[PEPayload, ...]) -> str:
    names = [payload.name for payload in payloads]
    return " and ".join([", ".join(names[:-1]), names[-1]] if len(names) > 1 else names)


@attrs.define(repr=False)
class PEChunk(ValidChunk):
    """A PE file with a payload, extracted with the payload's extractor."""

    payload: PEPayload = attrs.field(kw_only=True)

    def extract(self, inpath: Path, outdir: Path) -> ExtractResult | None:
        outdir.mkdir(parents=True, exist_ok=False)
        return self.payload.extractor.extract(inpath, outdir)


class PEHandler(Handler):
    NAME = "pe"

    PATTERNS = [
        # "MZ" followed by the DOS header up to e_lfanew, whose two upper bytes must be
        # zero: the PE signature sits within the first 64 KiB in practice.
        HexString("4d 5a [58] ?? ?? 00 00"),
    ]

    # each payload brings its own extractor, see PEChunk
    EXTRACTOR = None

    DOC = HandlerDoc(
        name="PE",
        description=" ".join(
            [
                "PE (Portable Executable) is the executable file format of Windows and "
                + "UEFI. The handler carves PE files with a known payload and extracts "
                + "it.",
                *(payload.description for payload in PAYLOADS),
                "The chunk covers the PE image, whose size is computed from the headers, "
                + "the section table, debug data and COFF symbol table stored outside of "
                + "sections, then the data a payload appends (NSIS installer data), and "
                + "an Authenticode certificate table right after them. Other PE files are "
                + "not claimed: their contents are searched like any other data.",
            ]
        ),
        handler_type=HandlerType.EXECUTABLE,
        vendor="Microsoft",
        references=[
            PE_REFERENCE,
            *(reference for payload in PAYLOADS for reference in payload.references),
        ],
        limitations=[
            f"Only {_join_names(PAYLOADS)} are recognised. PE files of other packers "
            + "and installers (Inno Setup, WiX Burn, ...) are processed as plain data.",
            *(limitation for payload in PAYLOADS for limitation in payload.limitations),
        ],
    )

    @staticmethod
    def _find_payload(
        file: File, headers: PEHeaders, image_end: int
    ) -> tuple[PEPayload, int] | None:
        """Return the first payload found in ``PAYLOADS`` order, with its end."""
        for payload in PAYLOADS:
            end = payload.get_end(file, headers, image_end)
            if end is not None:
                return payload, end
        return None

    @classmethod
    def get_dependencies(cls) -> list[str]:
        return [
            dependency
            for payload in PAYLOADS
            for dependency in payload.extractor.get_dependencies()
        ]

    def calculate_chunk(self, file: File, start_offset: int) -> ValidChunk | None:
        headers = PEHeaders.parse(file, start_offset)

        # offsets below are relative to start_offset
        found = self._find_payload(file, headers, headers.get_image_end(file))
        if found is None:
            # A PE without a known payload is not claimed: unblob has nothing to unpack,
            # and a chunk would hide its contents (e.g. data in resources) from the
            # pattern search, which keeps scanning the PE like any other data.
            return None
        payload, end = found

        # only a certificate table right after the image (or payload) belongs to this
        # PE, a table after other overlay data would pull that data into the chunk
        security = headers.get_data_directory(DataDirectory.SECURITY)
        if security is not None and security.virtual_address == round_up(
            end, CERTIFICATE_TABLE_ALIGNMENT
        ):
            end = security.virtual_address + security.dir_size

        return PEChunk(
            start_offset=start_offset, end_offset=start_offset + end, payload=payload
        )
