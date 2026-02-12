from __future__ import annotations

import io
import os
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import (
    Cipher,
    algorithms,
    modes,
)

from unblob._rust import math_tools
from unblob.file_utils import Endian, File, FileSystem, InvalidInputFormat, StructParser
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

if TYPE_CHECKING:
    from collections.abc import Iterable

    from cryptography.hazmat.primitives.ciphers import CipherContext

C_DEFINITIONS = r"""
    typedef struct dlink_alpha_header {
        uint32 magic1;
        uint32 signature_len;
        uint32 padding;
        char   signature[signature_len];    /* "signature=XXXXXX_dlink.YYYY_ZZZZZZ\0" */
        // where XXXXXX seems to be the Alpha Networks model number, YYYY the year
        // and ZZZZZZ the D-Link model number
        uint32 magic2;
        uint32 signature_len2;
        uint32 fsize;                       /* size of the firmware image (without 128 Bytes header) */
    } dlink_alpha_header_t;

    // see https://github.com/openwrt/firmware-utils/blob/master/src/mkwrggimg.c
    typedef struct wrgg03_header {
        char        signature[32];    /* signature without "signature=" */
        uint32      magic1;
        uint32      magic2;
        char        version[16];
        char        model[16];
        uint32      flag[2];
        uint32  	reserve[2];
        char        buildno[16];
        uint32  	fsize;
        uint32  	offset;
        char		devname[32];
        char		digest[16];
    } wrgg03_header_t;
"""
XOR_RANGE = 0xFC
UNENCRYPTED_ENTROPY_THRESHOLD = 3


@dataclass
class EncParams:
    signature: bytes
    key: bytes
    iv: bytes

    @property
    def mangled_key(self):
        return self._mangle(self.signature, self.key)

    @property
    def mangled_iv(self):
        return self._mangle(self.signature, self.iv)

    @staticmethod
    def _mangle(image_sign: bytes, data: bytes) -> bytes:
        sign_len = len(image_sign)
        return bytes(
            data_byte ^ ((i + 1) % XOR_RANGE) ^ image_sign[i % sign_len]
            for i, data_byte in enumerate(data)
        )


@dataclass
class EncParamsV2(EncParams):
    key: bytes = b"oVhq0hvXHdfaGFLdubM4/QvuVHdKee7v"
    iv: bytes = b"0BO5nlYankuVBe4s"


ENC_START_TO_PARAMS = {
    # DAP-1665 B
    bytes.fromhex("35 66 6f 68"): EncParams(
        signature=b"wapac25_dlink.2015_dap1665",
        key=b"EfCHXytwsC6F0zsedwZc+9vDbCjE3ge4",
        iv=b"ggPy917jwESpnfXm",
    ),
    # DAP-1720 A
    bytes.fromhex("68 01 cc fb"): EncParams(
        signature=b"wapac28_dlink.2015_dap1720",
        key=b"qBiz6o/1RVQTtJBd3FS7FDbqogE8yoBm",
        iv=b"EfDMqWWxHCOhEqgY",
    ),
    # DIR-822 C1
    bytes.fromhex("df 8c 39 0d"): EncParams(
        signature=b"wrgac43s_dlink.2015_dir822c1",
        key=b"KNpsEntCcsep1jdFIs3wnXySKRGNCGmf",
        iv=b"uph587JdKHrtAUlr",
    ),
    # DIR-842 C1 / C2
    bytes.fromhex("f5 2a a0 b4"): EncParams(
        signature=b"wrgac65_dlink.2015_dir842",
        key=b"xQYoRZeD726UAbRb846kO7TeNw8eZa6u",
        iv=b"zufEbNF3kUafxFiE",
    ),
    # DIR-842 C3 (same as C1 except for the "EU" at the end of the signature)
    bytes.fromhex("21 dd da 00"): EncParams(
        signature=b"wrgac65_dlink.2015_dir842EU",
        key=b"xQYoRZeD726UAbRb846kO7TeNw8eZa6u",
        iv=b"zufEbNF3kUafxFiE",
    ),
    # DIR-850L A1
    bytes.fromhex("e3 13 00 5b"): EncParams(
        signature=b"wrgac05_dlob.hans_dir850l",
        key=b"BIuS1CVMEQG+0pUeE99jnR+vLlLd9unr",
        iv=b"f3+odwHhmJL1ceW1",
    ),
    # DIR-850L B1
    bytes.fromhex("0a 14 e4 24"): EncParams(
        signature=b"wrgac25_dlink.2013gui_dir850l",
        key=b"qQehHMEmEPQ5izL+cabn8bNHZXHjkp6W",
        iv=b"Mmb+IKQgnO8OuF4b",
    ),
    # DIR-859 A
    bytes.fromhex("4c 1b 95 af"): EncParams(
        signature=b"wrgac37_dlink.2013gui_dir859",
        key=b"KY0H9R2PDL3eu1J4uCVd1CK7BJ7vF1kc",
        iv=b"qbStAzIRvWeQHz5U",
    ),
    # FixMe: add more entries when they are found
}


def decrypt_chunk(encrypted: bytes, enc_params: EncParams) -> bytes:
    decryptor = _get_decryptor(enc_params)
    return decryptor.update(encrypted) + decryptor.finalize()


def decrypt_file(
    file: File, enc_params: EncParams, chunk_size: int = 16
) -> Iterable[bytes]:
    decryptor = _get_decryptor(enc_params)
    while chunk := file.read(chunk_size):
        yield decryptor.update(chunk)
    yield decryptor.finalize()


def _get_decryptor(enc_params: EncParams) -> CipherContext:
    cipher = Cipher(
        algorithms.AES(enc_params.mangled_key),
        modes.CBC(enc_params.mangled_iv),
        backend=default_backend(),
    )
    return cipher.decryptor()


class AlphaEncimgExtractorV1(Extractor):
    def extract(self, inpath: Path, outdir: Path) -> ExtractResult | None:
        fs = FileSystem(outdir)
        with File.from_path(inpath) as file:
            enc_magic = file.read(4)
            enc_params = ENC_START_TO_PARAMS.get(enc_magic)
            if not enc_params:
                raise InvalidInputFormat("Device not supported")
            file.seek(0, io.SEEK_SET)
            out_path = Path(f"{enc_params.signature.decode()}.bin")
            fs.write_chunks(out_path, decrypt_file(file, enc_params))
        return ExtractResult(reports=fs.problems)


class AlphaEncimgExtractorV2(Extractor):
    def extract(self, inpath: Path, outdir: Path) -> ExtractResult | None:
        struct_parser = StructParser(C_DEFINITIONS)
        fs = FileSystem(outdir)
        with File.from_path(inpath) as file:
            header = struct_parser.parse("wrgg03_header_t", file, Endian.BIG)
            enc_params = EncParamsV2(signature=header.signature.rstrip(b"\0"))
            file.seek(AlphaEncimgV2Handler.HEADER_SIZE, io.SEEK_SET)
            out_path = Path(f"{enc_params.signature.decode()}.bin")
            fs.write_chunks(out_path, decrypt_file(file, enc_params))
        return ExtractResult(reports=fs.problems)


class AlphaEncimgHandler(StructHandler):
    NAME = "alpha_encimg_v1"
    PATTERNS = [
        HexString("35 66 6f 68 ef 1a fe 1f 34 ef 4f 11 21 05 4e be"),  # DAP-1665 B
        HexString("68 01 cc fb ad 6b a0 ba 33 04 b0 9c bb 48 b0 27"),  # DAP-1720 A
        HexString("df 8c 39 0d 22 b4 dc 29 fb 4e bf db e8 e1 8b fb"),  # DIR-822 C1
        HexString("f5 2a a0 b4 92 53 bf ef f8 21 a6 2e 28 a7 39 8b"),  # DIR-842 C1 / C2
        HexString("21 dd da 00 99 d8 87 a9 d5 2d 7e ff 3b 58 70 a6"),  # DIR-842 C3
        HexString("e3 13 00 5b 76 df 0b e8 83 24 5a 42 ff 91 2d 3d"),  # DIR-850L A1
        HexString("0a 14 e4 24 ff 0f b4 d7 53 66 a0 b0 72 fe ab df"),  # DIR-850L B1
        HexString("4c 1b 95 af 93 72 5f 81 03 03 96 4d dd 76 01 74"),  # DIR-859 A
        HexString("98 9c 3c 2c 6b 19 1b 25 6e 03 ee 0f 72 5c 6c a0"),  # DIR-865L A
        HexString("3d e6 02 63 3f c1 85 e7 d2 bf 64 af 29 57 3a bd"),  # DIR-868L A
        HexString("8e 69 57 e7 76 09 d7 94 47 75 78 a2 4a 1f c9 b2"),  # DIR-880L A
        HexString("92 61 58 58 14 db bb 3b e5 a5 f3 e7 10 9c a2 0b"),  # DIR-885L A
        HexString("cb c3 a7 4c 50 0f 42 43 a5 d9 7c a5 25 6b cd ba"),  # DIR-890L A
        HexString("91 5a c9 a2 11 ff aa 6d b0 12 e8 8d 2c 3c 23 cb"),  # DIR-895L A
    ]
    EXTRACTOR = AlphaEncimgExtractorV1()
    C_DEFINITIONS = C_DEFINITIONS
    DOC = HandlerDoc(
        name="D-Link Alpha encimg V1 Firmware",
        description=(
            "Encrypted firmware images found in D-Link DIR devices manufactured by Alpha Networks."
            "Uses AES-256-CBC encryption with device-specific keys."
        ),
        handler_type=HandlerType.ARCHIVE,
        vendor="D-Link",
        references=[
            Reference(
                title="OpenWRT forum",
                url="https://forum.openwrt.org/t/adding-openwrt-support-for-d-link-dir-x1860-mt7621-mt7915-ax1800/106500",
            ),
            Reference(
                title="delink tool",
                url="https://github.com/devttys0/delink/blob/main/src/encimg.rs",
            ),
        ],
        limitations=[],
    )
    HEADER_STRUCT = "dlink_alpha_header_t"
    HEADER_SIZE = 0x80
    _SIGNATURE_PREFIX = b"signature="
    MAGIC = {0x5EA3A417}

    def _get_header(self, file: File):
        encrypted_header = file.read(self.HEADER_SIZE)
        enc_params = ENC_START_TO_PARAMS.get(encrypted_header[:4])
        if not enc_params:
            raise InvalidInputFormat("Device not supported")

        decrypted_header = decrypt_chunk(encrypted_header, enc_params)
        header = self._struct_parser.parse(
            self.HEADER_STRUCT, decrypted_header, Endian.BIG
        )
        self._validate(enc_params, file, header)
        return header

    def calculate_chunk(self, file: File, start_offset: int) -> ValidChunk | None:
        header = self._get_header(file)
        end_offset = start_offset + self.HEADER_SIZE + header.fsize
        return ValidChunk(start_offset=start_offset, end_offset=end_offset)

    def _validate(self, enc_params: EncParams, file: File, header):
        if header.magic1 not in self.MAGIC:
            raise InvalidInputFormat(f"Invalid magic: {header.magic1}")

        expected_signature = self._SIGNATURE_PREFIX + enc_params.signature
        if header.signature.rstrip(b"\0") != expected_signature:
            raise InvalidInputFormat(f"Invalid signature {header.signature}")

        remaining = file.size() - file.tell()
        if header.fsize > remaining:
            raise InvalidInputFormat("Invalid file size")

        if header.fsize % 16:
            raise InvalidInputFormat(
                f"Firmware size not aligned to 16 bytes: {header.fsize}"
            )


class AlphaEncimgV2Handler(AlphaEncimgHandler):
    NAME = "alpha_encimg_v2"
    PATTERNS = [
        HexString("77 61 70 [29] 21 03 08 20 21 03 08 20"),  # Alpha Networks DAP-2xxx
    ]
    EXTRACTOR = AlphaEncimgExtractorV2()
    DOC = HandlerDoc(
        name="D-Link Alpha encimg v2 Firmware",
        description=(
            "Encrypted firmware images found in D-Link DIR devices manufactured by Alpha Networks."
            "Uses AES-256-CBC encryption with device-specific keys."
            "Unlike the other variant, this one uses a prepended unencrypted WRGG03 header."
        ),
        handler_type=HandlerType.ARCHIVE,
        vendor="D-Link",
        references=[
            Reference(
                title="OpenWRT Wiki",
                url="https://openwrt.org/toh/d-link/d-link_dap_series_of_business_access_points#old_generation_dap-2xxxdap-3xxx_built_by_alpha_networks",
            ),
            Reference(
                title="delink tool",
                url="https://github.com/devttys0/delink/blob/main/src/encimg.rs",
            ),
        ],
        limitations=[],
    )
    HEADER_SIZE = 0xA0
    HEADER_STRUCT = "wrgg03_header_t"
    _SIGNATURE_PREFIX = b""
    MAGIC = {0x20080321, 0x21030820}
    KNOWN_UNENCRYPTED = (
        bytes.fromhex("5d 00 00 80"),
        bytes.fromhex("d0 0d fe ed"),
        bytes.fromhex("10 ec 7a 0d"),  # DAP X2810/X2850
    )

    def _validate(self, enc_params: EncParams, file: File, header):
        first_block = file.read(16)
        file.seek(-16, os.SEEK_CUR)
        if self._is_not_encrypted(first_block):
            raise InvalidInputFormat("Firmware payload does not seem to be encrypted")
        super()._validate(enc_params, file, header)

    def _is_not_encrypted(self, first_block: bytes) -> bool:
        return (
            any(first_block.startswith(m) for m in self.KNOWN_UNENCRYPTED)
            or math_tools.shannon_entropy(first_block) < UNENCRYPTED_ENTROPY_THRESHOLD
        )

    def _get_header(self, file: File):
        current_offset = file.tell()
        header_le = self.parse_header(file, Endian.LITTLE)
        file.seek(current_offset, io.SEEK_SET)
        header_be = self.parse_header(file, Endian.BIG)
        # there are little and big endian devices that use this format, but there seems to be
        # only one mandatory integer header field: size (sadly we cannot write signatures for that)
        # since the size is an uint32 and the FW image should be smaller than 64 MB, it is safe to assume
        # that the correct endianness is the one with the smaller size field
        header = header_le if header_le.fsize < header_be.fsize else header_be

        device = header.signature.rstrip(b"\0")
        enc_params = EncParamsV2(signature=device)
        self._validate(enc_params, file, header)
        return header
