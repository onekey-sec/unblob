"""InstallShield single-file installer packages (PackageForTheWeb).

A "PackageForTheWeb" package is appended to the setup.exe stub and holds the
files the stub unpacks at runtime: an MSI with its transforms, InstallShield
cabinets, prerequisites, and the setup bootstrap itself.

Format, as read by ISx (https://github.com/lifenjoiner/ISx):

    header, 46 bytes: signature, file count, layout type
    per file: fixed-size attribute record, then the file data

Two layouts exist. The classic "InstallShield" layout stores a 0x138-byte
record per file with an embedded 260-byte (MAX_PATH) name. The newer
"ISSetupStream" layout (InstallShield 2014+) stores a compact 0x18-byte record
followed by a UTF-16 name (with an extra 0x18-byte block for layout type 4).

Member data is obfuscated: every byte is nibble-swapped and XORed with a key
derived from the file name. The key restarts either every 1024 bytes (flag
0x4, "M1024") or spans the whole file (flag 0x2, "Mfile"); flag 0x4 takes
precedence when both are set. Members flagged as unicode launchers are then
zlib-deflated on top of the obfuscation.
"""

from __future__ import annotations

import io
import zlib
from pathlib import Path
from typing import TYPE_CHECKING

from structlog import get_logger

from unblob.file_utils import (
    Endian,
    File,
    FileSystem,
    InvalidInputFormat,
    StructParser,
    iterate_file,
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
from unblob.report import ExtractionProblem

if TYPE_CHECKING:
    from collections.abc import Iterable

logger = get_logger()

C_DEFINITIONS = r"""
    typedef struct pftw_header {
        char     magic[14];        // "InstallShield" or "ISSetupStream"
        uint16   num_files;
        uint32   type;             // layout version, up to 4
        char     x4[8];
        uint16   x5;
        char     x6[16];
    } pftw_header_t;

    typedef struct pftw_file_attributes {
        char     file_name[260];   // MAX_PATH, NUL padded
        uint32   encoded_flags;
        uint32   x3;
        uint32   file_len;
        char     x5[8];
        uint16   is_unicode_launcher;
        char     x7[30];
    } pftw_file_attributes_t;

    typedef struct pftw_stream_file_attributes {
        uint32   filename_len;     // byte length of the UTF-16 name
        uint32   encoded_flags;
        char     x3[2];
        uint32   file_len;
        char     x5[8];
        uint16   is_unicode_launcher;
    } pftw_stream_file_attributes_t;
"""
PFTW_HEADER = "pftw_header_t"
PFTW_FILE_ATTRIBUTES = "pftw_file_attributes_t"
PFTW_STREAM_FILE_ATTRIBUTES = "pftw_stream_file_attributes_t"

PFTW_HEADER_SIZE = 0x2E
PFTW_FILE_ATTRIBUTES_SIZE = 0x138
PFTW_STREAM_FILE_ATTRIBUTES_SIZE = 0x18
PFTW_MAX_TYPE = 4
PFTW_NAME_SIZE = 260  # MAX_PATH

ENCODED_BLOCK_LEN = 1024
# bounded read/decode slice so members never sit whole in memory
DECODE_CHUNK_SIZE = 0x8000

SIG_PFTW = b"InstallShield\x00"
SIG_STREAM = b"ISSetupStream\x00"

# the member data obfuscation: decode_byte(c, k) = ~(k ^ nibbleswap(c)),
# key = file name xored with this constant, repeated
KEY_MAGIC = (0x13, 0x35, 0x86, 0x07)
# ~(a ^ b) == ~a ^ b, so the decode is nibbleswap(c) ^ ~key
_NIBBLE_SWAP = bytes((i << 4 | i >> 4) & 0xFF for i in range(256))


def _gen_key(seed: bytes) -> bytes:
    return bytes(
        ~(b ^ KEY_MAGIC[i % len(KEY_MAGIC)]) & 0xFF for i, b in enumerate(seed)
    )


def _member_block_size(
    encoded_flags: int, file_len: int, *, is_stream: bool
) -> int | None:
    """Return the key restart period for a member, or None when stored plain.

    encoded_flags 0x4: the key restarts every 1024 bytes ("M1024").
    encoded_flags 0x2 without 0x4: a single keyed pass over the whole file
    ("Mfile"); ISx never sets up the decoder for stream members without flag
    0x4, so those stay obfuscation-free.
    """
    if encoded_flags & 0x4:
        return ENCODED_BLOCK_LEN
    if encoded_flags & 0x2 and not is_stream:
        return file_len
    return None


def _decode_slices(
    file: File, offset: int, size: int, seed: bytes, block_size: int
) -> Iterable[bytes]:
    """Yield de-obfuscated member data in bounded slices.

    The key restarts every block_size bytes, so slices never cross a block
    boundary; the key index inside a block is (position % block_size) %
    key_len.
    """
    key = _gen_key(seed)
    key_len = len(key)
    pos = 0
    while pos < size:
        n = min(block_size - pos % block_size, size - pos, DECODE_CHUNK_SIZE)
        raw = bytes(file[offset + pos : offset + pos + n]).translate(_NIBBLE_SWAP)
        mask_off = pos % block_size % key_len
        mask = (key[mask_off:] + key[:mask_off]) * (n // key_len + 1)
        yield (int.from_bytes(raw) ^ int.from_bytes(mask[:n])).to_bytes(n)
        pos += n


def _decoded_slices(
    file: File, member: _Member, block_size: int | None
) -> Iterable[bytes]:
    if block_size is None:
        return iterate_file(file, member.data_offset, member.file_len)
    return _decode_slices(
        file, member.data_offset, member.file_len, member.seed, block_size
    )


def _inflate_slices(chunks: Iterable[bytes]) -> Iterable[bytes]:
    decompressor = zlib.decompressobj()
    for chunk in chunks:
        data = decompressor.decompress(chunk)
        if data:
            yield data
    if not decompressor.eof:
        raise zlib.error("truncated zlib stream")
    tail = decompressor.flush()
    if tail:
        yield tail


class _Member:
    __slots__ = ("data_offset", "encoded_flags", "file_len", "inflate", "name", "seed")

    def __init__(self, name, seed, encoded_flags, file_len, inflate, data_offset):
        self.name = name
        self.seed = seed
        self.encoded_flags = encoded_flags
        self.file_len = file_len
        self.inflate = inflate
        self.data_offset = data_offset


class PftwParser:
    """Iterate the member records of a PackageForTheWeb package."""

    def __init__(self, file: File, start_offset: int = 0):
        self.file = file
        self.start_offset = start_offset
        self.struct_parser = StructParser(C_DEFINITIONS)
        self.file.seek(start_offset, io.SEEK_SET)
        self.header = self.struct_parser.parse(PFTW_HEADER, file, Endian.LITTLE)
        self._validate_header()
        self.is_stream = self.header.magic == SIG_STREAM
        self.data_offset = start_offset + PFTW_HEADER_SIZE

    def _validate_header(self):
        if self.header.magic not in (SIG_PFTW, SIG_STREAM):
            raise InvalidInputFormat("no InstallShield signature")
        if self.header.num_files == 0:
            raise InvalidInputFormat("no members")
        if self.header.type > PFTW_MAX_TYPE:
            raise InvalidInputFormat(f"unsupported layout type {self.header.type}")

    @staticmethod
    def _read_name(data: bytes) -> bytes:
        return data.split(b"\x00", 1)[0]

    def iter_members(self) -> Iterable[_Member]:
        offset = self.data_offset
        for _ in range(self.header.num_files):
            member = self._read_member(offset)
            yield member
            offset = member.data_offset + member.file_len
            if offset > self.file.size():
                raise InvalidInputFormat("member data lies beyond the package")

    def _read_member(self, offset: int) -> _Member:
        self.file.seek(offset, io.SEEK_SET)
        if self.is_stream:
            return self._read_stream_member(offset)
        attrs = self.struct_parser.parse(PFTW_FILE_ATTRIBUTES, self.file, Endian.LITTLE)
        raw_name = self._read_name(attrs.file_name)
        if not raw_name:
            raise InvalidInputFormat("empty member name")
        return _Member(
            name=raw_name,
            seed=raw_name,
            encoded_flags=attrs.encoded_flags,
            file_len=attrs.file_len,
            inflate=bool(attrs.is_unicode_launcher),
            data_offset=offset + PFTW_FILE_ATTRIBUTES_SIZE,
        )

    def _read_stream_member(self, offset: int) -> _Member:
        attrs = self.struct_parser.parse(
            PFTW_STREAM_FILE_ATTRIBUTES, self.file, Endian.LITTLE
        )
        name_offset = offset + PFTW_STREAM_FILE_ATTRIBUTES_SIZE
        if self.header.type == PFTW_MAX_TYPE:
            name_offset += PFTW_STREAM_FILE_ATTRIBUTES_SIZE
        name_len = attrs.filename_len
        if name_len % 2 or not 0 < name_len < PFTW_NAME_SIZE * 2:
            raise InvalidInputFormat(f"invalid stream member name length {name_len}")
        if name_offset + name_len > self.file.size():
            raise InvalidInputFormat("member name lies beyond the package")
        raw_name = bytes(self.file[name_offset : name_offset + name_len])
        try:
            name = raw_name.decode("utf-16-le")
        except UnicodeDecodeError:
            raise InvalidInputFormat("invalid UTF-16 member name") from None
        name = name.split("\x00", 1)[0]
        if not name:
            raise InvalidInputFormat("empty member name")
        return _Member(
            name=name,
            seed=name.encode("utf-8"),
            encoded_flags=attrs.encoded_flags,
            file_len=attrs.file_len,
            inflate=bool(attrs.is_unicode_launcher),
            data_offset=name_offset + name_len,
        )


def _member_path(name: str | bytes, index: int) -> Path:
    """Member names are Windows paths; normalize them for extraction."""
    if isinstance(name, bytes):
        name = name.decode("utf-8", errors="surrogateescape")
    name = name.replace("\\", "/").strip().lstrip("/")
    if name in ("", "."):
        name = f"member_{index}"
    return Path(name)


class PftwExtractor(Extractor):
    def extract(self, inpath: Path, outdir: Path) -> ExtractResult | None:
        fs = FileSystem(outdir)
        with File.from_path(inpath) as file:
            parser = PftwParser(file)
            for index, member in enumerate(parser.iter_members()):
                self._extract_member(
                    file, fs, member, index, is_stream=parser.is_stream
                )
        return ExtractResult(reports=fs.problems)

    @staticmethod
    def _extract_member(
        file: File, fs: FileSystem, member: _Member, index: int, *, is_stream: bool
    ):
        path = _member_path(member.name, index)
        block_size = _member_block_size(
            member.encoded_flags, member.file_len, is_stream=is_stream
        )
        decoded = _decoded_slices(file, member, block_size)
        if member.inflate:
            try:
                fs.write_chunks(path, _inflate_slices(decoded))
            except zlib.error:
                fs.record_problem(
                    ExtractionProblem(
                        problem="member failed to inflate",
                        resolution="wrote de-obfuscated member data without inflating",
                        path=path.as_posix(),
                    )
                )
                decoded = _decoded_slices(file, member, block_size)
            else:
                return
        fs.write_chunks(path, decoded)


class InstallShieldPftwHandler(Handler):
    NAME = "installshield_pftw"
    PATTERNS = [
        # "InstallShield\0" and "ISSetupStream\0"
        HexString("49 6E 73 74 61 6C 6C 53 68 69 65 6C 64 00"),
        HexString("49 53 53 65 74 75 70 53 74 72 65 61 6D 00"),
    ]
    EXTRACTOR = PftwExtractor()
    DOC = HandlerDoc(
        name="InstallShield PackageForTheWeb",
        description=(
            "Single-file InstallShield setup.exe payload (PackageForTheWeb "
            "and ISSetupStream layouts) holding the files the setup stub "
            "unpacks: MSIs, transforms, cabinets and prerequisites. Member "
            "data is obfuscated with a filename-derived key and often "
            "zlib-deflated."
        ),
        handler_type=HandlerType.ARCHIVE,
        vendor="Flexera (InstallShield)",
        references=[
            Reference(
                title="ISx InstallShield installer extractor",
                url="https://github.com/lifenjoiner/ISx",
            ),
        ],
        limitations=[
            "Packages of layout type 5 or newer are not recognized",
        ],
    )

    def calculate_chunk(self, file: File, start_offset: int) -> ValidChunk | None:
        parser = PftwParser(file, start_offset)
        *_, last = parser.iter_members()
        end_offset = last.data_offset + last.file_len
        return ValidChunk(start_offset=start_offset, end_offset=end_offset)
