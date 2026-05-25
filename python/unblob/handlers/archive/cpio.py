import io
import os
import stat
from pathlib import Path

import attrs
from structlog import get_logger

from ...file_utils import (
    Endian,
    FileSystem,
    InvalidInputFormat,
    StructParser,
    decode_int,
    iterate_file,
    round_up,
    snull,
)
from ...models import (
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
from ...report import ExtractionProblem

logger = get_logger()

CPIO_TRAILER_NAME = "TRAILER!!!"
MAX_LINUX_PATH_LENGTH = 0x1000

C_TRAILER = 0o00000
C_ISBLK = 0o60000
C_ISCHR = 0o20000
C_ISDIR = 0o40000
C_ISFIFO = 0o10000
C_ISSOCK = 0o140000
C_ISLNK = 0o120000
C_ISCTG = 0o110000
C_ISREG = 0o100000

C_FILE_TYPES = (
    C_TRAILER,
    C_ISBLK,
    C_ISCHR,
    C_ISDIR,
    C_ISFIFO,
    C_ISSOCK,
    C_ISLNK,
    C_ISCTG,
    C_ISREG,
)

C_NONE = 0o00000
C_ISUID = 0o04000
C_ISGID = 0o02000
C_ISVTX = 0o01000
C_ISUID_ISGID = 0o06000

C_STICKY_BITS = (C_NONE, C_ISUID, C_ISGID, C_ISVTX, C_ISUID_ISGID)

C_DEFINITIONS = r"""
    typedef struct old_cpio_header
    {
        uint16 c_magic;
        uint16 c_dev;
        uint16 c_ino;
        uint16 c_mode;
        uint16 c_uid;
        uint16 c_gid;
        uint16 c_nlink;
        uint16 c_rdev;
        uint16 c_mtimes[2];
        uint16 c_namesize;
        uint16 c_filesize[2];
    } old_cpio_header_t;

    typedef struct old_ascii_header
    {
        char c_magic[6];
        char c_dev[6];
        char c_ino[6];
        char c_mode[6];
        char c_uid[6];
        char c_gid[6];
        char c_nlink[6];
        char c_rdev[6];
        char c_mtime[11];
        char c_namesize[6];
        char c_filesize[11];
    } old_ascii_header_t;

    typedef struct new_ascii_header
    {
        char c_magic[6];
        char c_ino[8];
        char c_mode[8];
        char c_uid[8];
        char c_gid[8];
        char c_nlink[8];
        char c_mtime[8];
        char c_filesize[8];
        char c_dev_maj[8];
        char c_dev_min[8];
        char c_rdev_maj[8];
        char c_rdev_min[8];
        char c_namesize[8];
        char c_chksum[8];
    } new_ascii_header_t;
"""


@attrs.define
class CPIOEntry:
    header: object
    size: int
    mode: int
    rdev: int
    path: Path
    link: str


class CPIOParserBase:
    _PAD_ALIGN: int
    _FILE_PAD_ALIGN: int = 512
    _STRUCT_PARSER = StructParser(C_DEFINITIONS)
    HEADER_STRUCT: str
    entries: list[CPIOEntry]

    def __init__(self, file: File, start_offset: int, entries: list | None = None):
        self.file = file
        self.start_offset = start_offset
        self.end_offset = -1
        self.entries = entries if entries is not None else []

    def read_entry_header(self) -> CPIOEntry | None:
        """Parse one entry header + name, return None at EOF."""
        try:
            header = self._STRUCT_PARSER.parse(
                self.HEADER_STRUCT, self.file, Endian.LITTLE
            )
        except EOFError:
            return None

        c_filesize = self._calculate_file_size(header)
        c_namesize = self._calculate_name_size(header)

        # heuristics 1: check the filename
        if c_namesize > MAX_LINUX_PATH_LENGTH:
            raise InvalidInputFormat("CPIO entry filename is too long.")
        if c_namesize == 0:
            raise InvalidInputFormat("CPIO entry filename empty.")

        padded_header_size = self._pad_header(header, c_namesize)
        name_padding = padded_header_size - len(header) - c_namesize

        tmp_filename = self.file.read(c_namesize)

        # heuristics 2: check that filename is null-byte terminated
        if not tmp_filename.endswith(b"\x00"):
            raise InvalidInputFormat("CPIO entry filename is not null-byte terminated")

        try:
            filename = snull(tmp_filename).decode("utf-8")
        except UnicodeDecodeError as e:
            raise InvalidInputFormat from e

        if name_padding:
            self.file.read(name_padding)

        c_mode = self._calculate_mode(header)
        file_type = c_mode & 0o770000
        sticky_bit = c_mode & 0o7000

        # heuristics 3: check mode field
        if file_type not in C_FILE_TYPES or sticky_bit not in C_STICKY_BITS:
            raise InvalidInputFormat("CPIO entry mode is invalid.")

        return CPIOEntry(
            header=header,
            path=Path(filename),
            size=c_filesize,
            mode=c_mode,
            rdev=0,
            link="",
        )

    def parse(self, fs: FileSystem | None = None):
        while True:
            entry = self.read_entry_header()
            if entry is None:
                break

            content_padding = self._pad_content(entry.size) - entry.size

            if entry.path.name == CPIO_TRAILER_NAME:
                self.file.seek(content_padding, io.SEEK_CUR)
                break

            if entry.path.name in ("", ".", ".."):
                self.file.seek(entry.size + content_padding, io.SEEK_CUR)
                continue

            if fs is not None:
                self.extract_entry(fs, entry)
            else:
                self.file.seek(entry.size, io.SEEK_CUR)
            self.file.seek(content_padding, io.SEEK_CUR)
        self.end_offset = self._pad_file(self.file.tell())

    def extract_entry(self, fs: FileSystem, entry: CPIOEntry):
        # There are cases where CPIO archives have duplicated entries
        # We then unlink the files to overwrite them and avoid an error.
        if not stat.S_ISDIR(entry.mode):
            fs.unlink(entry.path)

        if stat.S_ISREG(entry.mode):
            fs.write_chunks(
                entry.path, iterate_file(self.file, self.file.tell(), entry.size)
            )
        elif stat.S_ISLNK(entry.mode):
            link_target = snull(self.file.read(entry.size)).decode("utf-8")
            fs.create_symlink(src=Path(link_target), dst=entry.path)
        elif stat.S_ISDIR(entry.mode):
            fs.mkdir(entry.path, mode=entry.mode & 0o777, parents=True, exist_ok=True)
            self.file.seek(entry.size, io.SEEK_CUR)
        elif (
            stat.S_ISCHR(entry.mode)
            or stat.S_ISBLK(entry.mode)
            or stat.S_ISSOCK(entry.mode)
        ):
            rdev = self._calculate_rdev(entry.header)
            fs.mknod(entry.path, mode=entry.mode & 0o777, device=rdev)
            self.file.seek(entry.size, io.SEEK_CUR)
        else:
            logger.warning("unknown file type in CPIO archive")
            self.file.seek(entry.size, io.SEEK_CUR)

    def record_checksum_mismatch(
        self, fs: FileSystem, entry: CPIOEntry, calculated_checksum: int
    ):
        if self.valid_checksum(entry.header, calculated_checksum):
            return

        fs.record_problem(
            ExtractionProblem(
                problem=(
                    f"CPIO CRC mismatch: expected {decode_int(entry.header.c_chksum, 16):08x}, "  # pyright: ignore[reportAttributeAccessIssue]
                    f"got {calculated_checksum:08x}"
                ),
                resolution="Extracted anyway.",
                path=entry.path.as_posix(),
            )
        )

    def _pad_file(self, end_offset: int) -> int:
        """CPIO archives can have a 512 bytes block padding at the end."""
        self.file.seek(end_offset, io.SEEK_SET)
        padded_end_offset = self.start_offset + round_up(
            size=end_offset - self.start_offset, alignment=self._FILE_PAD_ALIGN
        )
        padding_size = padded_end_offset - end_offset

        if self.file.read(padding_size) == bytes([0]) * padding_size:
            return padded_end_offset

        return end_offset

    @classmethod
    def _pad_header(cls, header, c_namesize: int) -> int:
        return round_up(len(header) + c_namesize, cls._PAD_ALIGN)

    @classmethod
    def _pad_content(cls, c_filesize: int) -> int:
        """Pad header and content with _PAD_ALIGN bytes."""
        return round_up(c_filesize, cls._PAD_ALIGN)

    @staticmethod
    def _calculate_file_size(header) -> int:
        raise NotImplementedError

    @staticmethod
    def _calculate_name_size(header) -> int:
        raise NotImplementedError

    @staticmethod
    def _calculate_mode(header) -> int:
        raise NotImplementedError

    @staticmethod
    def _calculate_rdev(header) -> int:
        raise NotImplementedError

    def valid_checksum(self, header, calculated_checksum: int) -> bool:  # noqa: ARG002
        return True


class BinaryCPIOParser(CPIOParserBase):
    _PAD_ALIGN = 2

    HEADER_STRUCT = "old_cpio_header_t"

    @staticmethod
    def _calculate_file_size(header) -> int:
        return header.c_filesize[0] << 16 | header.c_filesize[1]

    @staticmethod
    def _calculate_name_size(header) -> int:
        return header.c_namesize + 1 if header.c_namesize % 2 else header.c_namesize

    @staticmethod
    def _calculate_mode(header) -> int:
        return header.c_mode

    @staticmethod
    def _calculate_rdev(header) -> int:
        return header.c_rdev


class PortableOldASCIIParser(CPIOParserBase):
    _PAD_ALIGN = 1

    HEADER_STRUCT = "old_ascii_header_t"

    @staticmethod
    def _calculate_file_size(header) -> int:
        return decode_int(header.c_filesize, 8)

    @staticmethod
    def _calculate_name_size(header) -> int:
        return decode_int(header.c_namesize, 8)

    @staticmethod
    def _calculate_mode(header) -> int:
        return decode_int(header.c_mode, 8)

    @staticmethod
    def _calculate_rdev(header) -> int:
        return decode_int(header.c_rdev, 8)


class PortableASCIIParser(CPIOParserBase):
    _PAD_ALIGN = 4
    HEADER_STRUCT = "new_ascii_header_t"

    @staticmethod
    def _calculate_file_size(header) -> int:
        return decode_int(header.c_filesize, 16)

    @staticmethod
    def _calculate_name_size(header) -> int:
        return decode_int(header.c_namesize, 16)

    @staticmethod
    def _calculate_mode(header) -> int:
        return decode_int(header.c_mode, 16)

    @staticmethod
    def _calculate_rdev(header) -> int:
        return os.makedev(
            decode_int(header.c_rdev_maj, 16), decode_int(header.c_rdev_min, 16)
        )


class PortableASCIIWithCRCParser(PortableASCIIParser):
    def extract_entry(self, fs: FileSystem, entry: CPIOEntry):
        if not stat.S_ISDIR(entry.mode):
            fs.unlink(entry.path)

        calculated_checksum = 0

        if stat.S_ISREG(entry.mode):
            with fs.open(entry.path, "wb+") as output:
                for chunk in iterate_file(self.file, self.file.tell(), entry.size):
                    calculated_checksum += sum(chunk)
                    output.write(chunk)
        elif stat.S_ISLNK(entry.mode):
            content = bytearray()
            for chunk in iterate_file(self.file, self.file.tell(), entry.size):
                calculated_checksum += sum(chunk)
                content.extend(chunk)
            link_target = snull(bytes(content)).decode("utf-8")
            fs.create_symlink(src=Path(link_target), dst=entry.path)
        elif stat.S_ISDIR(entry.mode):
            fs.mkdir(entry.path, mode=entry.mode & 0o777, parents=True, exist_ok=True)
        elif (
            stat.S_ISCHR(entry.mode)
            or stat.S_ISBLK(entry.mode)
            or stat.S_ISSOCK(entry.mode)
        ):
            rdev = self._calculate_rdev(entry.header)
            fs.mknod(entry.path, mode=entry.mode & 0o777, device=rdev)
        else:
            logger.warning("unknown file type in CPIO archive")

        self.record_checksum_mismatch(fs, entry, calculated_checksum & 0xFF_FF_FF_FF)

    def valid_checksum(self, header, calculated_checksum: int) -> bool:
        header_checksum = decode_int(header.c_chksum, 16)
        return header_checksum == calculated_checksum & 0xFF_FF_FF_FF


class StrippedCPIOParser(CPIOParserBase):
    """Stripped CPIO variant (magic 07070X) used in RPM 4.12+.

    File metadata is supplied at construction from the RPM main header;
    dump_entries walks the stream forward to extract each entry.
    """

    _PAD_ALIGN = 4
    _MAGIC = b"07070X"
    _HEADER_SIZE = 14  # 6 magic + 8 file index

    def parse(self, fs: FileSystem | None = None):
        header_padding = self._pad_content(self._HEADER_SIZE) - self._HEADER_SIZE
        while True:
            magic = self.file.read(6)
            # Stripped archives terminate with a standard newc TRAILER entry.
            if magic in (b"070701", b"070702"):
                break
            if magic != self._MAGIC:
                raise InvalidInputFormat(
                    f"Bad stripped CPIO magic: {magic} should be 07070X"
                )

            file_index = int(self.file.read(8), 16)
            self.file.seek(header_padding, io.SEEK_CUR)

            entry = self.entries[file_index]
            content_padding = self._pad_content(entry.size) - entry.size

            if entry.path.name in ("", ".", ".."):
                self.file.seek(entry.size + content_padding, io.SEEK_CUR)
                continue

            if fs is not None:
                self.extract_entry(fs, entry)
            else:
                self.file.seek(entry.size, io.SEEK_CUR)
            self.file.seek(content_padding, io.SEEK_CUR)
        self.end_offset = self._pad_file(self.file.tell())


class _CPIOExtractorBase(Extractor):
    PARSER: type[CPIOParserBase]

    def extract(self, inpath: Path, outdir: Path) -> ExtractResult | None:
        fs = FileSystem(outdir)

        with File.from_path(inpath) as file:
            parser = self.PARSER(file, 0)
            parser.parse(fs)
        return ExtractResult(reports=fs.problems)


class BinaryCPIOExtractor(_CPIOExtractorBase):
    PARSER = BinaryCPIOParser


class PortableOldASCIIExtractor(_CPIOExtractorBase):
    PARSER = PortableOldASCIIParser


class PortableASCIIExtractor(_CPIOExtractorBase):
    PARSER = PortableASCIIParser


class PortableASCIIWithCRCExtractor(_CPIOExtractorBase):
    PARSER = PortableASCIIWithCRCParser


class _CPIOHandlerBase(Handler):
    """A common base for all CPIO formats.

    The format should be parsed the same, there are small differences how to calculate
    file and filename sizes padding and conversion from octal / hex.
    """

    EXTRACTOR: _CPIOExtractorBase

    def calculate_chunk(self, file: File, start_offset: int) -> ValidChunk | None:
        parser = self.EXTRACTOR.PARSER(file, start_offset)
        parser.parse()
        return ValidChunk(
            start_offset=start_offset,
            end_offset=parser.end_offset,
        )


class BinaryHandler(_CPIOHandlerBase):
    NAME = "cpio_binary"
    PATTERNS = [HexString("c7 71 // (default, bin, hpbin)")]

    EXTRACTOR = BinaryCPIOExtractor()

    DOC = HandlerDoc(
        name="CPIO (binary)",
        description="CPIO (Copy In, Copy Out) is an archive file format used for bundling files and directories along with their metadata. It is commonly used in Unix-like systems for creating backups or transferring files, and supports various encoding formats including binary and ASCII.",
        handler_type=HandlerType.ARCHIVE,
        vendor=None,
        references=[
            Reference(
                title="GNU CPIO Manual",
                url="https://www.gnu.org/software/cpio/manual/cpio.html",
            ),
        ],
        limitations=[],
    )


class PortableOldASCIIHandler(_CPIOHandlerBase):
    NAME = "cpio_portable_old_ascii"

    PATTERNS = [HexString("30 37 30 37 30 37 // 07 07 07")]

    EXTRACTOR = PortableOldASCIIExtractor()

    DOC = HandlerDoc(
        name="CPIO (portable old ASCII)",
        description="CPIO (Copy In, Copy Out) is an archive file format used for bundling files and directories along with their metadata. It is commonly used in Unix-like systems for creating backups or transferring files, and supports various encoding formats including binary and ASCII.",
        handler_type=HandlerType.ARCHIVE,
        vendor=None,
        references=[
            Reference(
                title="GNU CPIO Manual",
                url="https://www.gnu.org/software/cpio/manual/cpio.html",
            ),
        ],
        limitations=[],
    )


class PortableASCIIHandler(_CPIOHandlerBase):
    NAME = "cpio_portable_ascii"
    PATTERNS = [HexString("30 37 30 37 30 31 // 07 07 01 (newc)")]

    EXTRACTOR = PortableASCIIExtractor()

    DOC = HandlerDoc(
        name="CPIO (portable ASCII)",
        description="CPIO (Copy In, Copy Out) is an archive file format used for bundling files and directories along with their metadata. It is commonly used in Unix-like systems for creating backups or transferring files, and supports various encoding formats including binary and ASCII.",
        handler_type=HandlerType.ARCHIVE,
        vendor=None,
        references=[
            Reference(
                title="GNU CPIO Manual",
                url="https://www.gnu.org/software/cpio/manual/cpio.html",
            ),
        ],
        limitations=[],
    )


class PortableASCIIWithCRCHandler(_CPIOHandlerBase):
    NAME = "cpio_portable_ascii_crc"
    PATTERNS = [HexString("30 37 30 37 30 32 // 07 07 02")]

    EXTRACTOR = PortableASCIIWithCRCExtractor()

    DOC = HandlerDoc(
        name="CPIO (portable ASCII CRC)",
        description="CPIO (Copy In, Copy Out) is an archive file format used for bundling files and directories along with their metadata. It is commonly used in Unix-like systems for creating backups or transferring files, and supports various encoding formats including binary and ASCII.",
        handler_type=HandlerType.ARCHIVE,
        vendor=None,
        references=[
            Reference(
                title="GNU CPIO Manual",
                url="https://www.gnu.org/software/cpio/manual/cpio.html",
            ),
        ],
        limitations=[],
    )
