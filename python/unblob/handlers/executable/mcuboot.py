"""MCUboot image: header, image and TLV area.

Format: MCUboot design documentation, "Image Format"; type codes as imgtool
defines them. Little-endian images only.
"""

import struct
from dataclasses import dataclass
from pathlib import Path

from unblob.file_utils import InvalidInputFormat
from unblob.models import (
    ExtractError,
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
from unblob.report import MetadataReport, UnknownError, register_report_type

IMAGE_MAGIC = 0x96F3B83D
HEADER = struct.Struct(
    "<IIHHIIBBHII"
)  # magic, load, hdr, prot, img, flags, version, pad
TLV_INFO = struct.Struct("<HH")  # magic, total length including this header
TLV = struct.Struct("<HH")  # type, length
TLV_INFO_MAGIC = 0x6907
TLV_PROT_INFO_MAGIC = 0x6908
SIGNATURE_TLVS = {0x20, 0x22, 0x23, 0x24}  # RSA2048, ECDSASIG, RSA3072, ED25519
ENCRYPTED_FLAGS = 0x4 | 0x8  # ENCRYPTED_AES128, ENCRYPTED_AES256


@register_report_type
class MCUbootMetadataReport(MetadataReport):
    """MCUboot image metadata; `signed` means a signature TLV is present, not verified.

    `encrypted` mirrors the header flags only: the image is still split, with
    the ciphertext in image.bin, so this is not an EncryptionMetadataReport.
    """

    version: str
    load_address: int
    flags: int
    signed: bool
    encrypted: bool
    tlv_types: list[int]


@dataclass(frozen=True)
class ImageInfo:
    header_size: int
    image_size: int
    protected_size: int
    end: int  # of the TLV area, relative to the image start
    version: str
    load_address: int
    flags: int
    tlv_types: list[int]

    @property
    def signed(self) -> bool:
        return bool(SIGNATURE_TLVS & set(self.tlv_types))

    @property
    def encrypted(self) -> bool:
        return bool(self.flags & ENCRYPTED_FLAGS)


def _unpack(layout: struct.Struct, buf, offset: int) -> tuple:
    if offset < 0 or offset + layout.size > len(buf):
        raise InvalidInputFormat("MCUboot structure runs past the end of the data")
    return layout.unpack_from(buf, offset)


def _tlv_area(buf, offset: int, magic: int) -> tuple[int, list[int]]:
    """(end offset, TLV types) of the TLV area whose info header is at offset."""
    found, total = _unpack(TLV_INFO, buf, offset)
    if found != magic or total < TLV_INFO.size:
        raise InvalidInputFormat(f"missing TLV info magic 0x{magic:04x}")
    end = offset + total
    if end > len(buf):
        raise InvalidInputFormat("TLV area runs past the end of the data")
    types = []
    pos = offset + TLV_INFO.size
    while pos < end:
        tlv_type, length = _unpack(TLV, buf, pos)
        types.append(tlv_type)
        pos += TLV.size + length
    if pos != end:
        raise InvalidInputFormat("TLV entries do not fill the TLV area")
    return end, types


def image_info(buf, start: int = 0) -> ImageInfo:
    """Parse the MCUboot image at start; InvalidInputFormat if it is not one."""
    (
        magic,
        load,
        hdr_size,
        prot_size,
        img_size,
        flags,
        major,
        minor,
        revision,
        build,
        _pad,
    ) = _unpack(HEADER, buf, start)
    if magic != IMAGE_MAGIC or hdr_size < HEADER.size:
        raise InvalidInputFormat("not an MCUboot image header")
    pos = start + hdr_size + img_size
    types: list[int] = []
    if prot_size:
        prot_end, prot_types = _tlv_area(buf, pos, TLV_PROT_INFO_MAGIC)
        if prot_end != pos + prot_size:
            raise InvalidInputFormat("protected TLV area size mismatch")
        types += prot_types
        pos = prot_end
    end, tlv_types = _tlv_area(buf, pos, TLV_INFO_MAGIC)
    return ImageInfo(
        header_size=hdr_size,
        image_size=img_size,
        protected_size=prot_size,
        end=end - start,
        version=f"{major}.{minor}.{revision}+{build}",
        load_address=load,
        flags=flags,
        tlv_types=types + tlv_types,
    )


class MCUbootExtractor(Extractor):
    def extract(self, inpath: Path, outdir: Path) -> ExtractResult | None:
        data = inpath.read_bytes()
        try:
            info = image_info(data)
        except InvalidInputFormat as exc:
            raise ExtractError(UnknownError(exception=exc)) from None
        if info.end != len(data):
            problem = f"the input is not one whole MCUboot image ({len(data)} bytes)"
            raise ExtractError(UnknownError(exception=InvalidInputFormat(problem)))
        image_end = info.header_size + info.image_size
        (outdir / "header.bin").write_bytes(data[: info.header_size])
        (outdir / "image.bin").write_bytes(data[info.header_size : image_end])
        (outdir / "tlv.bin").write_bytes(data[image_end : info.end])
        return ExtractResult(reports=[])


class MCUbootHandler(Handler):
    NAME = "mcuboot"
    PATTERNS = [HexString("3D B8 F3 96")]  # IMAGE_MAGIC, little-endian
    EXTRACTOR = MCUbootExtractor()
    DOC = HandlerDoc(
        name="MCUboot image",
        description="MCUboot application image: header, image and TLV area (hashes, keys, signatures), used by Zephyr, nRF Connect SDK and ESP32 builds.",
        handler_type=HandlerType.EXECUTABLE,
        vendor="MCUboot project",
        references=[
            Reference(
                title="MCUboot design: image format",
                url="https://docs.mcuboot.com/design.html#image-format",
            ),
            Reference(
                title="imgtool",
                url="https://docs.mcuboot.com/imgtool.html",
            ),
        ],
        limitations=[
            "Big-endian images are not handled",
            "Signatures are not verified; 'signed' means a signature TLV is present",
            "Encrypted payloads are written as ciphertext",
        ],
    )

    def calculate_chunk(self, file: File, start_offset: int) -> ValidChunk | None:
        info = image_info(file, start_offset)
        return ValidChunk(
            start_offset=start_offset,
            end_offset=start_offset + info.end,
            metadata_reports=[
                MCUbootMetadataReport(
                    version=info.version,
                    load_address=info.load_address,
                    flags=info.flags,
                    signed=info.signed,
                    encrypted=info.encrypted,
                    tlv_types=info.tlv_types,
                )
            ],
        )
