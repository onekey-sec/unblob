import io
from pathlib import Path

import lzfse
from structlog import get_logger

from unblob.file_utils import (
    Endian,
    File,
    FileSystem,
    convert_int8,
    convert_int64,
)
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


def _field_patp(
    file: File, _fs: FileSystem, current_path: str | None
) -> tuple[str | None, bool]:
    # PATP: Path Property (1-byte length + string)
    len_bytes = file.read(1)
    if not len_bytes:
        return current_path, False
    length = convert_int8(len_bytes, Endian.LITTLE)
    return file.read(length).decode("utf-8", errors="ignore"), True


def _field_data(
    file: File, fs: FileSystem, current_path: str | None
) -> tuple[str | None, bool]:
    # DATA: Data Property (8-byte size + LZFSE/Raw blob)
    size_bytes = file.read(8)
    if not size_bytes:
        return current_path, False
    blob_size = convert_int64(size_bytes, Endian.LITTLE)
    compressed_data = file.read(blob_size)
    if current_path:
        try:
            fs.write_bytes(Path(current_path), lzfse.decompress(compressed_data))
        except Exception:
            fs.write_bytes(Path(current_path), compressed_data)
    return current_path, True


def _field_lnkp(
    file: File, _fs: FileSystem, current_path: str | None
) -> tuple[str | None, bool]:
    # LNKP: Symbolic Link Property (1-byte length + string)
    len_bytes = file.read(1)
    if not len_bytes:
        return current_path, True
    length = convert_int8(len_bytes, Endian.LITTLE)
    target = file.read(length).decode("utf-8", errors="ignore")
    if current_path:
        logger.debug("atlas symlink found", source=current_path, target=target)
    return current_path, True


def _field_xata(
    file: File, _fs: FileSystem, current_path: str | None
) -> tuple[str | None, bool]:
    # XATA: Extended Attributes (skip or parse CRC)
    len_bytes = file.read(1)
    if not len_bytes:
        return current_path, True
    length = convert_int8(len_bytes, Endian.LITTLE)
    current_pos = file.tell()
    file.seek(0, io.SEEK_END)
    file_size = file.tell()
    file.seek(current_pos)
    skip_bytes = length + 4
    if current_pos + skip_bytes > file_size:
        logger.warning("Invalid XATA field length, stopping parse")
        return current_path, False
    file.seek(skip_bytes, io.SEEK_CUR)
    return current_path, True


def _field_typ1(
    file: File, _fs: FileSystem, current_path: str | None
) -> tuple[str | None, bool]:
    # TYP1: Entry Type (1 byte)
    file.seek(1, io.SEEK_CUR)
    return current_path, True


_FIELD_HANDLERS = {
    "PATP": _field_patp,
    "DATA": _field_data,
    "LNKP": _field_lnkp,
    "XATA": _field_xata,
    "TYP1": _field_typ1,
}


class AppleArchiveExtractor(Extractor):
    def extract(self, inpath: Path, outdir: Path) -> ExtractResult:
        fs = FileSystem(outdir)

        with File.from_path(inpath) as file:
            magic = file.read(4)
            if magic != b"AA01":
                return ExtractResult(reports=[])

            current_path: str | None = None

            while True:
                field_tag = file.read(4)
                if len(field_tag) < 4:
                    break
                tag = field_tag.decode("ascii", errors="ignore")
                handler = _FIELD_HANDLERS.get(tag)
                if handler is None:
                    continue
                current_path, ok = handler(file, fs, current_path)
                if not ok:
                    break

        return ExtractResult(reports=fs.problems)


class AppleArchiveHandler(Handler):
    NAME = "apple_archive"
    PATTERNS = [HexString("41 41 30 31")]  # "AA01"
    EXTRACTOR = AppleArchiveExtractor()

    DOC = HandlerDoc(
        name="Apple Archive",
        description="Apple Archive is Apple's proprietary archive format introduced with macOS Big Sur, used for distributing macOS software updates and installers. Files begin with the AA01 magic and contain field-tagged entries encoding paths, LZFSE-compressed data blobs, symbolic links, and extended attributes.",
        handler_type=HandlerType.ARCHIVE,
        vendor="Apple",
        references=[
            Reference(
                title="Apple Archive - Apple Developer Documentation",
                url="https://developer.apple.com/documentation/applearchive",
            ),
        ],
        limitations=[
            "Only PATP/DATA/LNKP/XATA/TYP1 field tags are handled; other tags are silently skipped",
            "Symlink targets are logged but not created in the output directory",
        ],
    )

    def calculate_chunk(self, file: File, start_offset: int) -> ValidChunk | None:
        file.seek(0, io.SEEK_END)
        end_offset = file.tell()
        return ValidChunk(start_offset=start_offset, end_offset=end_offset)
