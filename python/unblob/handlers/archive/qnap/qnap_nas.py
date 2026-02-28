import io
from pathlib import Path

import attrs
from pyperscan import Flag, Pattern, Scan, StreamDatabase
from structlog import get_logger

from unblob.file_utils import File, stream_scan
from unblob.models import (
    Endian,
    Handler,
    HandlerDoc,
    HandlerType,
    HexString,
    StructParser,
    ValidChunk,
)

from ._qnap import C_DEFINITIONS, FOOTER_LEN, QnapExtractor

logger = get_logger()

SECRET = "QNAPNASVERSION"  # noqa: S105

FOOTER_PATTERN = [
    HexString("69 63 70 6e 61 73"),  # encrypted gzip stream start bytes
]


@attrs.define
class QTSSearchContext:
    start_offset: int
    file: File
    end_offset: int


def is_valid_header(header) -> bool:
    try:
        header.device_id.decode("utf-8")
        header.file_version.decode("utf-8")
        header.firmware_date.decode("utf-8")
        header.revision.decode("utf-8")
    except UnicodeDecodeError:
        return False
    return True


def _hyperscan_match(
    context: QTSSearchContext, pattern_id: int, offset: int, end: int
) -> Scan:
    del pattern_id, end  # unused arguments
    if offset < context.start_offset:
        return Scan.Continue
    context.file.seek(offset, io.SEEK_SET)
    struct_parser = StructParser(C_DEFINITIONS)
    header = struct_parser.parse("qnap_header_t", context.file, Endian.LITTLE)
    logger.debug("qnap_header_t", header=header)

    if is_valid_header(header):
        context.end_offset = context.file.tell()
        return Scan.Terminate
    return Scan.Continue


def build_stream_end_scan_db(pattern_list):
    return StreamDatabase(
        *(Pattern(p.as_regex(), Flag.SOM_LEFTMOST, Flag.DOTALL) for p in pattern_list)
    )


hyperscan_stream_end_magic_db = build_stream_end_scan_db(FOOTER_PATTERN)


class QnapNasExtractor(QnapExtractor):
    def _get_secret(self, header) -> str:
        return SECRET + header.file_version.decode("utf-8")[0]


class QnapHandler(Handler):
    NAME = "qnap_nas"

    PATTERNS = [
        HexString("F5 7B 47 03"),
    ]
    EXTRACTOR = QnapNasExtractor()

    DOC = HandlerDoc(
        name="QNAP NAS",
        description="QNAP NAS firmware files consist of a custom header, encrypted data sections, and a footer marking the end of the encrypted stream. The header contains metadata such as device ID, firmware version, and encryption details.",
        handler_type=HandlerType.ARCHIVE,
        vendor="QNAP",
        references=[],
        limitations=[],
    )

    def calculate_chunk(self, file: File, start_offset: int) -> ValidChunk | None:
        context = QTSSearchContext(start_offset=start_offset, file=file, end_offset=-1)

        try:
            scanner = hyperscan_stream_end_magic_db.build(context, _hyperscan_match)  # type: ignore
            stream_scan(scanner, file)
        except Exception as e:
            logger.debug(
                "Error scanning for QNAP patterns",
                error=e,
            )
        if context.end_offset > 0:
            return ValidChunk(start_offset=start_offset, end_offset=context.end_offset)
        return None
