import base64
import io
import json
from pathlib import Path

import requests
from pyhpke import AEADId, CipherSuite, KDFId, KEMId, KEMKey
from structlog import get_logger

from unblob.file_utils import File, InvalidInputFormat
from unblob.models import (
    Extractor,
    ExtractResult,
    Handler,
    HandlerDoc,
    HandlerType,
    HexString,
    Reference,
    ValidChunk,
)

logger = get_logger()

# python-aea uses enum.StrEnum, which only exists from 3.11 on, so it is declared
# as a Python 3.11+ dependency and imported lazily: importing it at module level
# would take the whole CLI down on 3.10.
_UNSUPPORTED_PYTHON = "AEA decryption needs Python 3.11 or newer"

# HPKE suite as used by Apple AEA Profile 1
_HPKE_SUITE = CipherSuite.new(
    KEMId.DHKEM_P256_HKDF_SHA256, KDFId.HKDF_SHA256, AEADId.AES256_GCM
)


# AEA auth data (WKMS key fields) is a few KB; cap generously to reject false-positive
# "AEA1" matches without reading a bogus multi-GB size into memory.
_MAX_AUTH_DATA_SIZE = 1 << 20


def _parse_auth_data_fields(auth_data_blob: bytes) -> dict[str, bytes]:
    fields = {}
    while auth_data_blob:
        if len(auth_data_blob) < 4:
            raise InvalidInputFormat("AEA auth data: truncated field header")
        field_size = int.from_bytes(auth_data_blob[:4], "little")
        # field_size covers the 4-byte size prefix + "key\x00value"; must fit and advance.
        if not 4 < field_size <= len(auth_data_blob):
            raise InvalidInputFormat(f"AEA auth data: invalid field size {field_size}")
        key, sep, value = auth_data_blob[4:field_size].partition(b"\x00")
        if not sep:
            raise InvalidInputFormat("AEA auth data: field missing NUL separator")
        fields[key.decode("latin-1")] = value
        auth_data_blob = auth_data_blob[field_size:]
    return fields


def _unwrap_session_key(fields: dict[str, bytes]) -> bytes:
    if (
        "com.apple.wkms.fcs-response" not in fields
        or "com.apple.wkms.fcs-key-url" not in fields
    ):
        raise ValueError(
            "AEA file does not contain WKMS key fields — cannot decrypt without a pre-shared key"
        )
    fcs_response = json.loads(fields["com.apple.wkms.fcs-response"])
    enc_request = base64.b64decode(fcs_response["enc-request"])
    wrapped_key = base64.b64decode(fcs_response["wrapped-key"])
    url = fields["com.apple.wkms.fcs-key-url"].decode()

    r = requests.get(url, timeout=10)
    r.raise_for_status()
    privkey = KEMKey.from_pem(r.text)

    recipient = _HPKE_SUITE.create_recipient_context(enc_request, privkey)
    return recipient.open(wrapped_key)


class AEAExtractor(Extractor):
    def extract(self, inpath: Path, outdir: Path) -> ExtractResult:
        try:
            # python-aea is a 3.11+ only dependency, so it is absent on 3.10
            from aea import aea as aeaformat  # noqa: PLC0415 # pyright: ignore
        except ImportError:
            logger.warning(
                "AEA: cannot decrypt — skipping extraction", reason=_UNSUPPORTED_PYTHON
            )
            return ExtractResult(reports=[])

        with inpath.open("rb") as f:
            header = f.read(12)
            auth_data_size = int.from_bytes(header[8:12], "little")
            auth_data_blob = f.read(auth_data_size)

        fields = _parse_auth_data_fields(auth_data_blob)
        try:
            symmetric_key = _unwrap_session_key(fields)
        except ValueError as e:
            logger.warning("AEA: cannot decrypt — skipping extraction", reason=str(e))
            return ExtractResult(reports=[])
        logger.debug("AEA session key obtained", length=len(symmetric_key))

        decrypted_path = outdir / "decrypted.bin"
        with inpath.open("rb") as infile, decrypted_path.open("wb") as outfile:
            try:
                aeaformat.decode_stream(infile, outfile, symmetric_key=symmetric_key)
            except aeaformat.MACValidationError as e:
                logger.error(
                    "AEA MAC validation failed — symmetric_key is likely wrong",
                    error=str(e),
                )
                raise
            except aeaformat.ParseError as e:
                logger.error("AEA parse error", error=str(e))
                raise
        logger.debug(
            "AEA decryption complete", output_size=decrypted_path.stat().st_size
        )

        return ExtractResult(reports=[])


class AEAHandler(Handler):
    NAME = "aea"
    PATTERNS = [HexString("41 45 41 31")]  # AEA1
    EXTRACTOR = AEAExtractor()

    DOC = HandlerDoc(
        name="Apple Encrypted Archive (AEA)",
        description="Apple Encrypted Archive (AEA) is Apple's encrypted container format used for secure firmware and OTA update distribution. Profile 1 archives use Hybrid Public Key Encryption (HPKE) with Apple's WKMS key management service to wrap a per-archive symmetric key.",
        handler_type=HandlerType.ARCHIVE,
        vendor="Apple",
        references=[
            Reference(
                title="Apple Archive - Apple Developer Documentation",
                url="https://developer.apple.com/documentation/applearchive",
            ),
        ],
        limitations=[
            "Decryption requires access to Apple's WKMS key management service",
            "Archives without WKMS fields cannot be decrypted",
        ],
    )

    def calculate_chunk(self, file: File, start_offset: int) -> ValidChunk | None:
        # Validate the auth-data header so false-positive "AEA1" matches (common inside
        # large filesystems) are rejected here instead of crashing the extractor.
        file.seek(start_offset, io.SEEK_SET)
        header = file.read(12)
        if len(header) < 12:
            raise InvalidInputFormat("AEA header truncated")
        auth_data_size = int.from_bytes(header[8:12], "little")
        if auth_data_size > _MAX_AUTH_DATA_SIZE:
            raise InvalidInputFormat(f"AEA auth data size too large: {auth_data_size}")
        auth_data_blob = file.read(auth_data_size)
        if len(auth_data_blob) < auth_data_size:
            raise InvalidInputFormat("AEA auth data truncated")
        _parse_auth_data_fields(auth_data_blob)

        file.seek(0, io.SEEK_END)
        return ValidChunk(start_offset=start_offset, end_offset=file.tell())
