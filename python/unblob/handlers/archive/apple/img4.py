from pathlib import Path

from unblob.file_utils import File, FileSystem, InvalidInputFormat, iterate_patterns
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

# IM4P (Image4 Payload) DER structure inside an IMG4 container:
#   SEQUENCE
#     IA5String "IM4P"       (image type tag)
#     IA5String <name>       (component name, e.g. "illb")
#     OCTET STRING <payload> (compressed or raw binary)
_IM4P_MAGIC = b"IM4P"
_IM4P_PAYLOAD_SKIP = 12  # bytes past "IM4P" to the start of the payload OCTET STRING


class IM4PExtractor(Extractor):
    def extract(self, inpath: Path, outdir: Path) -> ExtractResult:
        fs = FileSystem(outdir)

        with File.from_path(inpath) as file:
            for pos in iterate_patterns(file, _IM4P_MAGIC):
                payload_start = pos + _IM4P_PAYLOAD_SKIP
                fs.carve(
                    Path(f"{inpath.stem}.bin"),
                    file,
                    payload_start,
                    file.size() - payload_start,
                )
                break

        return ExtractResult(reports=fs.problems)


class IMG4Handler(StructHandler):
    NAME = "img4"

    PATTERNS = [
        # 30          — DER SEQUENCE tag
        # 82          — long-form length: next 2 bytes encode the length
        # ?? ??       — 2-byte big-endian container length (variable)
        # 16 04       — IA5String tag + length 4
        # 49 4D 34 50 — "IM4P" (image type identifier)
        HexString("30 82 ?? ?? 16 04 49 4D 34 50"),
        # 30             — DER SEQUENCE tag
        # 83             — long-form length: next 3 bytes encode the length
        # ?? ?? ??       — 3-byte big-endian container length (variable)
        # 16 04          — IA5String tag + length 4
        # 49 4D 34 50    — "IM4P" (image type identifier)
        HexString("30 83 ?? ?? ?? 16 04 49 4D 34 50"),
    ]

    # DER header covering the worst case (3-byte length form)
    C_DEFINITIONS = r"""
        typedef struct img4_header {
            uint8  tag;           // 0x30 (SEQUENCE)
            uint8  length_type;   // 0x82 or 0x83
            uint8  b2;            // high byte of length (or high byte for 0x83)
            uint8  b3;            // low byte of length (or middle byte for 0x83)
            uint8  b4;            // only valid for 0x83
        } img4_header_t;
    """
    HEADER_STRUCT = "img4_header_t"

    EXTRACTOR = IM4PExtractor()

    DOC = HandlerDoc(
        name="Apple IMG4/IM4P",
        description="IMG4 is Apple's DER-encoded firmware image container used for signed payloads in the iOS and macOS secure boot chain. An IM4P (Image4 Payload) embeds a compressed or raw binary (typically LZFSE or LZSS) together with metadata used for cryptographic verification.",
        handler_type=HandlerType.ARCHIVE,
        vendor="Apple",
        references=[
            Reference(
                title="libimg4 - Apple open-source IMG4 implementation",
                url="https://github.com/apple-oss-distributions/libimg4",
            ),
        ],
        limitations=[
            "Only IM4P payload extraction is supported; full IMG4 manifests are not verified"
        ],
    )

    def calculate_chunk(self, file: File, start_offset: int) -> ValidChunk | None:
        header = self.parse_header(file)

        if header.length_type == 0x82:
            length = int.from_bytes([header.b2, header.b3], "big")
            total_size = 4 + length
        elif header.length_type == 0x83:
            length = int.from_bytes([header.b2, header.b3, header.b4], "big")
            total_size = 5 + length
        else:
            raise InvalidInputFormat(
                f"IMG4: unexpected DER length type {header.length_type:#x}"
            )

        return ValidChunk(
            start_offset=start_offset, end_offset=start_offset + total_size
        )
