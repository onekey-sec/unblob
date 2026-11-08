"""iRobot Otps firmware container.

Otps is the signed OTA package format used by the Qualcomm-based iRobot
generations (sapphire, soho, stingray, lewis, sanmarino, wichita), produced by
iRobot's ``otagen`` tool.

The whole file is a little-endian TLV stream where every element is a
4-byte tag, a uint32 length and a value:

    | Otps | total_len | cmnt* | Sdat | Sign |

Inside ``Sdat``:

    | cnid | salg | Auth{cert} | Otpc |

``Otpc`` holds one ``Otim`` group per flashed component. Each ``Otim`` wraps
an ``Otis`` (a signed ``Sdat`` metadata block followed by the item's
signature) and an ``Otie`` (the item entry: ``indx`` + ``data`` payload).
The item metadata carries the component's ``keyt`` letter (A..N, mapped to
TZ, RPM, ABL, SYSTEM, KERNEL, ...), a ``size`` and a SHA-256 ``hash`` of the
payload, which is verified during extraction.

The chunk ends at the declared ``total_len``; a small ``__PACKET_INFO__``
text footer can follow the package (wichita) and is left to the generic
handling.

Format reference: https://github.com/BookCatKid/irobot-firmware-archive
"""

import hashlib
import io
from dataclasses import dataclass
from pathlib import Path

from structlog import get_logger

from unblob.file_utils import (
    Endian,
    File,
    FileSystem,
    InvalidInputFormat,
    StructParser,
)
from unblob.models import (
    Extractor,
    ExtractResult,
    HandlerDoc,
    HandlerType,
    HexString,
    Reference,
    StructHandler,
    ValidChunk,
)
from unblob.report import ExtractionProblem

logger = get_logger()

C_DEFINITIONS = r"""
    typedef struct otps_header {
        char magic[4];     /* "Otps" */
        uint32 total_len;  /* length of everything after this field */
    } otps_header_t;
"""

HEADER_LEN = 8
MAX_TLV_ELEMENTS = 512

# top-level tags observed across the preserved package catalog
TOP_LEVEL_TAGS = {b"cmnt", b"Sdat", b"Sign"}

# "key type X" letters found in Otis metadata, mapped to component names.
KEY_TYPE_NAMES = {
    "A": "TZ",
    "B": "RPM",
    "C": "ABL",
    "D": "SYSTEM",
    "E": "KERNEL",
    "F": "STUBL",
    "G": "CMNLIB",
    "H": "CMNLIB64",
    "J": "DEVCFG",
    "K": "KM",
    "L": "PMIC",
    "M": "STORSEC",
    "N": "UEFI_SEC",
}


def _iter_tlvs(file: File, start: int, end: int):
    """Yield (tag, value_offset, next_offset) for each TLV in [start, end)."""
    offset = start
    count = 0
    while offset < end:
        count += 1
        if count > MAX_TLV_ELEMENTS or offset + 8 > end:
            raise InvalidInputFormat("Malformed Otps TLV stream.")
        file.seek(offset, io.SEEK_SET)
        raw = file.read(8)
        tag, length = raw[:4], int.from_bytes(raw[4:], "little")
        value_end = offset + 8 + length
        if value_end > end:
            raise InvalidInputFormat("Otps TLV element exceeds its container.")
        yield tag, offset + 8, value_end
        offset = value_end


def _read_u32(file: File, offset: int) -> int:
    file.seek(offset, io.SEEK_SET)
    return int.from_bytes(file.read(4), "little")


def _parse_otis_iexh(file: File, start: int, end: int) -> dict:
    """Collect the fields we care about from an Otis item extended header."""
    fields = {}
    for tag, value, next_offset in _iter_tlvs(file, start, end):
        if tag == b"hash":
            file.seek(value, io.SEEK_SET)
            fields["hash"] = file.read(next_offset - value).hex()
        elif tag == b"size":
            fields["size"] = _read_u32(file, value)
        elif tag == b"cmnt":
            file.seek(value, io.SEEK_SET)
            fields["cmnt"] = (
                file.read(next_offset - value)
                .split(b"\0", 1)[0]
                .decode("ascii", "replace")
            )
    return fields


def _parse_otis(file: File, start: int, end: int) -> dict:
    """Extract keyt/Iexh fields from an item's signed metadata block."""
    meta = {}
    for tag, value, next_offset in _iter_tlvs(file, start, end):
        if tag != b"Sdat":
            continue
        # the Sdat element is followed by the item's raw signature bytes,
        # which are not a TLV stream, so stop after the first Sdat
        for tag2, value2, next2 in _iter_tlvs(file, value, next_offset):
            if tag2 == b"keyt":
                file.seek(value2, io.SEEK_SET)
                keyt = (
                    file.read(next2 - value2)
                    .split(b"\0", 1)[0]
                    .decode("ascii", "replace")
                )
                # observed values look like "key type J"
                letter = keyt.rsplit(" ", 1)[-1]
                meta["name"] = KEY_TYPE_NAMES.get(letter, letter)
            elif tag2 == b"Iexh":
                meta.update(_parse_otis_iexh(file, value2, next2))
        break
    return meta


@dataclass(frozen=True)
class OtpsItem:
    index: int
    name: str
    payload_offset: int
    payload_size: int
    expected_sha256: str | None
    declared_size: int | None


def _parse_otie(file: File, start: int, end: int):
    """Return (index, payload_offset, payload_size) of an Otim's Otie element."""
    index = payload_offset = payload_size = None
    for tag, value, next_offset in _iter_tlvs(file, start, end):
        if tag == b"indx":
            if next_offset - value > 4:
                raise InvalidInputFormat("Invalid Otie index size.")
            file.seek(value, io.SEEK_SET)
            index = int.from_bytes(file.read(next_offset - value), "little")
        elif tag == b"data":
            payload_offset = value
            payload_size = next_offset - value
    return index, payload_offset, payload_size


def _parse_otim(file: File, otim_start: int, otim_end: int, seen: set) -> OtpsItem:
    meta: dict = {}
    index = payload_offset = payload_size = None
    for tag, value, next_offset in _iter_tlvs(file, otim_start, otim_end):
        if tag == b"Otis":
            meta = _parse_otis(file, value, next_offset)
        elif tag == b"Otie":
            index, payload_offset, payload_size = _parse_otie(file, value, next_offset)
    if index is None or payload_offset is None or payload_size is None:
        raise InvalidInputFormat("Otim item lacks index or payload.")
    declared = meta.get("size")
    if declared is not None and declared != payload_size:
        raise InvalidInputFormat(
            "Otim payload size does not match its signed metadata."
        )
    name = meta.get("name") or f"item-{index}"
    if name in seen:
        name = f"{name}-{index}"
    seen.add(name)
    return OtpsItem(
        index=index,
        name=name,
        payload_offset=payload_offset,
        payload_size=payload_size,
        expected_sha256=meta.get("hash"),
        declared_size=declared,
    )


def _parse_items(file: File, otpc_start: int, otpc_end: int):
    items = []
    seen = set()
    for tag, otim_start, otim_end in _iter_tlvs(file, otpc_start, otpc_end):
        if tag != b"Otim":
            raise InvalidInputFormat("Unexpected element inside Otps Otpc.")
        items.append(_parse_otim(file, otim_start, otim_end, seen))
    if not items:
        raise InvalidInputFormat("Otps Otpc holds no items.")
    return items


def _find_otpc(file: File, start: int, end: int):
    """Return the (start, end) of the Otpc element inside the Sdat block."""
    sdat = None
    for tag, value, next_offset in _iter_tlvs(file, start, end):
        if tag not in TOP_LEVEL_TAGS:
            raise InvalidInputFormat(f"Unexpected Otps element: {tag!r}.")
        if tag != b"Sdat":
            continue
        if sdat is not None:
            raise InvalidInputFormat("Multiple Sdat blocks in Otps package.")
        sdat = (value, next_offset)
    if sdat is None:
        raise InvalidInputFormat("Otps package lacks the Sdat block.")
    for tag, value, next_offset in _iter_tlvs(file, *sdat):
        if tag == b"Otpc":
            return value, next_offset
    raise InvalidInputFormat("Otps Sdat block lacks the Otpc content.")


class IRobotOtpsExtractor(Extractor):
    def __init__(self):
        self._struct_parser = StructParser(C_DEFINITIONS)

    def extract(self, inpath: Path, outdir: Path):
        fs = FileSystem(outdir)
        with File.from_path(inpath) as file:
            header = self._struct_parser.parse("otps_header_t", file, Endian.LITTLE)
            otpc_start, otpc_end = _find_otpc(
                file, HEADER_LEN, HEADER_LEN + header.total_len
            )
            items = _parse_items(file, otpc_start, otpc_end)
            for item in items:
                fs.carve(
                    Path(item.name),
                    file,
                    item.payload_offset,
                    item.payload_size,
                )
                if item.expected_sha256:
                    file.seek(item.payload_offset, io.SEEK_SET)
                    hasher = hashlib.sha256()
                    remaining = item.payload_size
                    while remaining:
                        block = file.read(min(remaining, 1024 * 1024))
                        if not block:
                            break
                        hasher.update(block)
                        remaining -= len(block)
                    if hasher.hexdigest() != item.expected_sha256:
                        fs.record_problem(
                            ExtractionProblem(
                                problem=(f"SHA-256 mismatch for Otps item {item.name}"),
                                resolution="payload extracted anyway",
                                path=item.name,
                            )
                        )
        return ExtractResult(reports=fs.problems)


class IRobotOtpsHandler(StructHandler):
    NAME = "irobot_otps"

    PATTERNS = [
        HexString(
            """
            4f 74 70 73 // "Otps"
        """
        ),
    ]
    C_DEFINITIONS = C_DEFINITIONS
    HEADER_STRUCT = "otps_header_t"
    EXTRACTOR = IRobotOtpsExtractor()

    DOC = HandlerDoc(
        name="iRobot Otps",
        description=(
            "iRobot Otps signed OTA packages are used by Qualcomm-based "
            "robots (sapphire, soho, stingray, lewis, sanmarino, wichita). "
            "The package is a TLV stream holding a signed data block whose "
            "Otpc content lists one Otim group per component. Each item's "
            "payload is carved under its component name (TZ, RPM, ABL, "
            "SYSTEM, KERNEL, ...) and verified against the SHA-256 declared "
            "in its signed metadata."
        ),
        handler_type=HandlerType.ARCHIVE,
        vendor="iRobot",
        references=[
            Reference(
                title="iRobot firmware archive Otie/Otim analysis",
                url="https://github.com/BookCatKid/irobot-firmware-archive/blob/6dee59f86f5991d18b9bd06c089277128ca8aa22/src/irobot_firmware/analyze.py",
            ),
        ],
        limitations=[
            "Package and item signatures are not verified; payloads are "
            "checked against the SHA-256 in the signed item metadata."
        ],
    )

    def calculate_chunk(self, file: File, start_offset: int) -> ValidChunk | None:
        header = self.parse_header(file, endian=Endian.LITTLE)
        if header.total_len < HEADER_LEN:
            raise InvalidInputFormat(f"Invalid Otps length: {header.total_len}.")

        otpc_start, otpc_end = _find_otpc(
            file,
            start_offset + HEADER_LEN,
            start_offset + HEADER_LEN + header.total_len,
        )
        _parse_items(file, otpc_start, otpc_end)

        return ValidChunk(
            start_offset=start_offset,
            end_offset=start_offset + HEADER_LEN + header.total_len,
        )
