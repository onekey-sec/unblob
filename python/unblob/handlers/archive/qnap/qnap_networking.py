from pathlib import Path

from unblob.file_utils import File
from unblob.models import (
    Endian,
    Handler,
    HandlerDoc,
    HandlerType,
    HexString,
    Reference,
    StructParser,
    ValidChunk,
)

from ._qnap import C_DEFINITIONS, FOOTER_LEN, NAS_DEVICE_ID_PREFIX, QnapExtractor


class QnapNetworkingExtractor(QnapExtractor):
    def _get_secret(self, header) -> str:
        return header.device_id.rstrip(b"\x00").decode("ascii")


class QnapNetworkingHandler(Handler):
    NAME = "qnap_networking"

    PATTERNS = [
        HexString("69 63 70 6e 61 73"),  # "icpnas" footer signature
    ]

    EXTRACTOR = QnapNetworkingExtractor()

    DOC = HandlerDoc(
        name="QNAP Networking",
        description=(
            "QNAP networking device firmware encrypted with the PC1 cipher. "
            "The encryption key is self-describing: it is stored as the "
            "device_id in the 74-byte 'icpnas' footer appended to the image, "
            "unlike NAS firmware which uses a shared secret prefix."
        ),
        handler_type=HandlerType.ARCHIVE,
        vendor="QNAP",
        references=[
            Reference(
                title="Pwn2Own Ireland 2024: QNAP Qhora-322",
                url="https://neodyme.io/en/blog/pwn2own-2024_qhora/",
            ),
            Reference(
                title="QNAP firmware encryption/decryption (PC1)",
                url="https://gist.github.com/galaxy4public/0420c7c9a8e3ff860c8d5dce430b2669",
            ),
        ],
        limitations=[],
    )

    def calculate_chunk(self, file: File, start_offset: int) -> ValidChunk | None:
        if start_offset != file.size() - FOOTER_LEN:
            return None

        header = StructParser(C_DEFINITIONS).parse("qnap_header_t", file, Endian.LITTLE)

        if header.encrypted_len == 0 or header.encrypted_len > start_offset:
            return None

        device_id = header.device_id.rstrip(b"\x00").decode("ascii", errors="replace")
        if device_id.upper().startswith(NAS_DEVICE_ID_PREFIX):
            return None

        return ValidChunk(start_offset=0, end_offset=start_offset + FOOTER_LEN)
