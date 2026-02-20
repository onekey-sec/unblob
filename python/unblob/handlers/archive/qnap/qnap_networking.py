import io
from pathlib import Path

from structlog import get_logger

from unblob.file_utils import File, iterate_file
from unblob.models import (
    Endian,
    Extractor,
    Handler,
    HandlerDoc,
    HandlerType,
    HexString,
    StructParser,
    ValidChunk,
)

from ._qnap import C_DEFINITIONS, FOOTER_LEN, Cryptor

logger = get_logger()


class QnapNetworkingExtractor(Extractor):
    """Extractor for encrypted QNAP networking device firmware.

    Unlike NAS firmware, the encryption key is self-describing: it is stored
    as the device_id field in the 74-byte footer appended to the image.

    Known examples:
        Qhora-322  -> key "QHora-322"
        Qhora-301W -> key "HORA_301W"
    """

    def __init__(self):
        self._struct_parser = StructParser(C_DEFINITIONS)

    def extract(self, inpath: Path, outdir: Path):
        outpath = outdir.joinpath(f"{inpath.name}.decrypted")
        with File.from_path(inpath) as file:
            file.seek(-FOOTER_LEN, io.SEEK_END)
            header = self._struct_parser.parse("qnap_header_t", file, Endian.LITTLE)
            eof = file.tell()
            secret = header.device_id.rstrip(b"\x00").decode("ascii")
            cryptor = Cryptor(secret)
            with outpath.open("wb") as outfile:
                for chunk in iterate_file(file, 0, header.encrypted_len, 1024):
                    outfile.write(cryptor.decrypt_chunk(chunk))
                for chunk in iterate_file(
                    file,
                    header.encrypted_len,
                    eof - FOOTER_LEN - header.encrypted_len,
                    1024,
                ):
                    outfile.write(chunk)


class QnapNetworkingHandler(Handler):
    NAME = "qnap_networking"

    # Networking device firmware has no plaintext magic at the start — the
    # entire payload is encrypted. We match on the "icpnas" footer signature
    # and anchor the chunk to the start of the file.
    PATTERNS = [
        HexString("69 63 70 6e 61 73"),  # "icpnas" footer signature
    ]

    EXTRACTOR = QnapNetworkingExtractor()

    DOC = HandlerDoc(
        name="QNAP Networking",
        description=(
            "QNAP networking device firmware encrypted with the PC1 cipher."
            "The encryption key is self-describing: it is stored as the"
            "device_id in the 74-byte 'icpnas' footer appended to the image,"
            "unlike NAS firmware which uses a shared secret prefix."
        ),
        handler_type=HandlerType.ARCHIVE,
        vendor="QNAP",
        references=[
            "https://neodyme.io/en/blog/pwn2own-2024_qhora/",
            "https://gist.github.com/galaxy4public/0420c7c9a8e3ff860c8d5dce430b2669",
        ],
        limitations=[],
    )

    def calculate_chunk(self, file: File, start_offset: int) -> ValidChunk | None:
        # start_offset points at the "icpnas" magic inside the footer.
        # Validate it sits exactly at file_size - FOOTER_LEN to reject stray matches.
        file.seek(0, io.SEEK_END)
        file_size = file.tell()
        if start_offset != file_size - FOOTER_LEN:
            return None

        struct_parser = StructParser(C_DEFINITIONS)
        file.seek(start_offset)
        header = struct_parser.parse("qnap_header_t", file, Endian.LITTLE)

        if header.encrypted_len == 0 or header.encrypted_len > start_offset:
            return None

        # NAS firmware device_id begins with "QNAPNAS" — let QnapHandler own those.
        device_id = header.device_id.rstrip(b"\x00").decode("ascii", errors="replace")
        if device_id.upper().startswith("QNAPNAS"):
            return None

        return ValidChunk(start_offset=0, end_offset=file_size)
