"""UF2: the USB Flashing Format of RP2040/RP2350, TinyUF2, nRF52 and SAMD bootloaders.

Format: https://github.com/microsoft/uf2 (512-byte blocks, three magics).
Each family's main-flash blocks are written as one file per contiguous
address region, ``<family>/0x<address>.bin``; gaps are never filled.
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
from unblob.report import UnknownError

BLOCK_SIZE = 512
MAX_PAYLOAD = 476
MAGIC_START0 = 0x0A324655
MAGIC_START1 = 0x9E5D5157
MAGIC_END = 0x0AB16F30
FLAG_NOT_MAIN_FLASH = 0x00000001
FLAG_FAMILY_ID = 0x00002000
NO_FAMILY = "no_family"

_HEADER = struct.Struct("<8I")

# Family IDs and short names from microsoft/uf2 utils/uf2families.json at
# 90e9741 (MIT, see NOTICE).
FAMILIES = {
    0x00FF6919: "STM32L4",
    0x04240BDF: "STM32L5",
    0x06D1097B: "STM32F411xC",
    0x11DE784A: "M0SENSE",
    0x16573617: "ATMEGA32",
    0x1851780A: "SAML21",
    0x1B57745F: "NRF52",
    0x1C5F21B0: "ESP32",
    0x1E1F432D: "STM32L1",
    0x202E3A91: "STM32L0",
    0x21460FF0: "STM32WL",
    0x22E0D6FC: "RTL8710B",
    0x2ABC77EC: "LPC55",
    0x2B88D29C: "ESP32C2",
    0x2DC309C5: "STM32F411xE",
    0x300F5633: "STM32G0",
    0x3101F7C1: "ESP32S31",
    0x31D228C6: "GD32F350",
    0x332726F6: "ESP32H2",
    0x3379CFE2: "RTL8720D",
    0x3D308E94: "ESP32P4",
    0x4B684D71: "MaixPlay-U4",
    0x4C71240A: "STM32G4",
    0x4E8F1C5D: "STM32H5",
    0x4F6ACE52: "CSK4",
    0x4FB2D5BD: "MIMXRT10XX",
    0x51E903A8: "XR809",
    0x53B80F00: "STM32F7",
    0x540DDF62: "ESP32C6",
    0x55114460: "SAMD51",
    0x57755A57: "STM32F4",
    0x5A18069B: "FX2",
    0x5D1A0A2E: "STM32F2",
    0x5EE21072: "STM32F1",
    0x621E937A: "NRF52833",
    0x647824B6: "STM32F0",
    0x675A40B0: "BK7231U",
    0x68ED2B88: "SAMD21",
    0x699B62EC: "CH32V",
    0x6A82CC42: "BK7251",
    0x6B846188: "STM32F3",
    0x6D0922FA: "STM32F407",
    0x6DB66082: "STM32H7",
    0x6E7348A8: "CSK6",
    0x6F752678: "NRF52832xxAB",
    0x70D16653: "STM32WB",
    0x72721D4E: "NRF52832xxAA",
    0x7410520A: "MAX32690",
    0x77D850C4: "ESP32C61",
    0x7B3EF230: "BK7231N",
    0x7BE8976D: "RA4M1",
    0x7D7A66EF: "PY32F071-UVK5-V3",
    0x7EAB61ED: "ESP8266",
    0x7F83E793: "KL32L2",
    0x820D9A5F: "NRF52820",
    0x8FB060FE: "STM32F407VG",
    0x91D3FD18: "MAX78002",
    0x9517422F: "RZA1LU",
    0x9AF03E33: "GD32VF103",
    0x9E0BAA8A: "ESP32H4",
    0x9FFFD543: "RTL8710A",
    0xA0C97B8E: "AT32F415",
    0xADA52840: "NRF52840",
    0xB6DD00AF: "ESP32H21",
    0xBFDD4EEE: "ESP32S2",
    0xC47E5767: "ESP32S3",
    0xD42BA06C: "ESP32C3",
    0xD63F8632: "MAX32650",
    0xDE1270B7: "BL602",
    0xE08F7564: "RTL8720C",
    0xE48BFF56: "RP2040",
    0xE48BFF57: "RP2XXX_ABSOLUTE",
    0xE48BFF58: "RP2XXX_DATA",
    0xE48BFF59: "RP2350_ARM_S",
    0xE48BFF5A: "RP2350_RISCV",
    0xE48BFF5B: "RP2350_ARM_NS",
    0xF0C30D71: "MAX32666",
    0xF71C0343: "ESP32C5",
}


@dataclass(frozen=True)
class Block:
    flags: int
    target_addr: int
    payload: bytes
    block_no: int
    family_id: int | None


def parse_block(raw: bytes) -> Block | None:
    """Return the block in a 512-byte buffer, or None if it is not a valid UF2 block."""
    if len(raw) < BLOCK_SIZE:
        return None
    start0, start1, flags, addr, size, block_no, _total, family = _HEADER.unpack_from(
        raw
    )
    (end,) = struct.unpack_from("<I", raw, BLOCK_SIZE - 4)
    if (start0, start1, end) != (MAGIC_START0, MAGIC_START1, MAGIC_END):
        return None
    if size > MAX_PAYLOAD:
        return None
    return Block(
        flags=flags,
        target_addr=addr,
        payload=bytes(raw[32 : 32 + size]),
        block_no=block_no,
        family_id=family if flags & FLAG_FAMILY_ID else None,
    )


def family_dir(family_id: int | None) -> str:
    if family_id is None:
        return NO_FAMILY
    return FAMILIES.get(family_id, f"0x{family_id:08x}")


def blocks(data: bytes) -> list[Block]:
    """Return the run of valid blocks at the start of data."""
    found = []
    for offset in range(0, len(data) - BLOCK_SIZE + 1, BLOCK_SIZE):
        block = parse_block(data[offset : offset + BLOCK_SIZE])
        if block is None:
            break
        found.append(block)
    return found


class OverlapConflictError(ValueError):
    """Two blocks write different bytes at the same address."""

    def __init__(self, address: int, first: int, second: int):
        super().__init__(
            f"UF2 blocks {first} and {second} write different bytes at 0x{address:08x}"
        )


def assemble(writes: list[tuple[int, bytes, int]]) -> list[tuple[int, bytes]]:
    """Merge (address, data, block number) writes into sorted contiguous regions.

    Identical overlapping writes are accepted; differing ones raise
    OverlapConflictError naming both blocks.
    """
    regions: list[tuple[int, bytearray, list[int]]] = []
    for address, data, source in sorted(writes, key=lambda w: (w[0], w[2])):
        if regions:
            start, buf, sources = regions[-1]
            end = start + len(buf)
            if address <= end:
                # The write may end inside the region: compare what both cover.
                overlap = buf[address - start : address - start + len(data)]
                if bytes(overlap) != data[: len(overlap)]:
                    raise OverlapConflictError(
                        address, sources[address - start], source
                    )
                tail = data[len(overlap) :]
                buf += tail
                sources += [source] * len(tail)
                continue
        regions.append((address, bytearray(data), [source] * len(data)))
    return [(start, bytes(buf)) for start, buf, _ in regions]


class UF2Extractor(Extractor):
    def extract(self, inpath: Path, outdir: Path) -> ExtractResult | None:
        data = inpath.read_bytes()
        found = blocks(data)
        if not found or len(found) * BLOCK_SIZE != len(data):
            raise ExtractError(
                UnknownError(
                    exception=InvalidInputFormat(
                        f"the input is not one whole UF2 chunk ({len(data)} bytes)"
                    )
                )
            )
        by_family: dict[int | None, list[tuple[int, bytes, int]]] = {}
        for block in found:
            if block.flags & FLAG_NOT_MAIN_FLASH:
                continue
            by_family.setdefault(block.family_id, []).append(
                (block.target_addr, block.payload, block.block_no)
            )
        # Assemble every family before writing, so a conflict writes nothing.
        families = []
        for family_id, writes in by_family.items():
            try:
                families.append((family_id, assemble(writes)))
            except OverlapConflictError as exc:
                raise ExtractError(UnknownError(exception=exc)) from None
        for family_id, regions in families:
            for address, region in regions:
                target = outdir / family_dir(family_id) / f"0x{address:08x}.bin"
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_bytes(region)
        return ExtractResult(reports=[])


class UF2Handler(Handler):
    NAME = "uf2"
    PATTERNS = [HexString("55 46 32 0A 57 51 5D 9E")]
    EXTRACTOR = UF2Extractor()
    DOC = HandlerDoc(
        name="UF2",
        description="USB Flashing Format: 512-byte blocks, each carrying a payload for a target address, used by RP2040/RP2350, ESP32-S2/S3 (TinyUF2), nRF52 and SAMD bootloaders.",
        handler_type=HandlerType.ARCHIVE,
        vendor="Microsoft",
        references=[
            Reference(
                title="UF2 specification",
                url="https://github.com/microsoft/uf2",
            ),
            Reference(
                title="UF2 family IDs",
                url="https://github.com/microsoft/uf2/blob/master/utils/uf2families.json",
            ),
        ],
        limitations=[
            "One file per contiguous address region; gaps are not padded",
            "File-container blocks (flag 0x1000) are not reassembled into files",
        ],
    )

    def calculate_chunk(self, file: File, start_offset: int) -> ValidChunk | None:
        file.seek(start_offset)
        end = start_offset
        while True:
            raw = file.read(BLOCK_SIZE)
            if parse_block(raw) is None:
                break
            end += BLOCK_SIZE
        if end == start_offset:
            raise InvalidInputFormat("no valid UF2 block at the match")
        return ValidChunk(start_offset=start_offset, end_offset=end)
