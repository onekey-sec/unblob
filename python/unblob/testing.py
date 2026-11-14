import binascii
import glob
import io
import shlex
import subprocess
from pathlib import Path

import attrs
import pytest
from lark.lark import Lark
from lark.visitors import Discard, Transformer

from unblob.file_utils import File, StructParser, round_up
from unblob.finder import build_hyperscan_database, search_chunks
from unblob.handlers.executable.pe import _headers as _pe_headers
from unblob.handlers.executable.pe import _nsis as _pe_nsis
from unblob.handlers.executable.pe import _upx as _pe_upx
from unblob.logging import configure_logger
from unblob.models import Handler, ProcessResult, Task, TaskResult, ValidChunk
from unblob.processing import ExtractionConfig
from unblob.report import ExtractCommandFailedReport


@pytest.fixture(scope="session", autouse=True)
def configure_logging(tmp_path_factory):
    extract_root = tmp_path_factory.mktemp("extract")
    log_path = tmp_path_factory.mktemp("logs") / "unblob.log"
    configure_logger(verbosity_level=3, extract_root=extract_root, log_path=log_path)


def gather_integration_tests(test_data_path: Path):
    # Path.glob() trips on some invalid files
    test_input_dirs = [
        Path(p)
        for p in glob.iglob(  # noqa: PTH207
            f"{test_data_path}/**/__input__", recursive=True
        )
    ]
    test_case_dirs = [p.parent for p in test_input_dirs]
    test_output_dirs = [p / "__output__" for p in test_case_dirs]
    test_ids = [
        f"{str(p.relative_to(test_data_path)).replace('/', '.')}"
        for p in test_case_dirs
    ]

    for input_dir, output_dir, test_id in zip(
        test_input_dirs, test_output_dirs, test_ids, strict=False
    ):
        assert list(input_dir.iterdir()) != [], (
            f"Integration test input dir should contain at least 1 file: {input_dir}"
        )

        yield pytest.param(input_dir, output_dir, id=test_id)


@pytest.fixture
def extraction_config(tmp_path: Path):
    config = ExtractionConfig(
        extract_root=tmp_path,
        randomness_depth=0,
        keep_extracted_chunks=True,
    )

    # Warmup lru_cache before ``process_file`` forks, so child
    # processes can reuse the prebuilt databases without overhead
    build_hyperscan_database(config.handlers)

    return config


def check_output_is_the_same(reference_dir: Path, extract_dir: Path):
    __tracebackhide__ = True

    diff_command = [
        "diff",
        "--recursive",
        "--unified",
        # fix for potential symlinks
        "--no-dereference",
        # Non-unicode files would produce garbage output
        # showing file names which are different should be helpful
        "--brief",
        "--exclude",
        ".gitkeep",
        # Special files in test samples follows a strict naming convention
        # so that we can have them without triggering errors on diff.
        # Example diff with special files: https://www.mail-archive.com/bug-diffutils@gnu.org/msg00863.html
        "--exclude",
        "*.socket",
        "--exclude",
        "*.symlink",
        "--exclude",
        "*.fifo",
        str(reference_dir),
        str(extract_dir),
    ]

    try:
        subprocess.run(diff_command, capture_output=True, check=True, text=True)
    except subprocess.CalledProcessError as exc:
        runnable_diff_command = shlex.join(diff_command)
        pytest.fail(f"\nDiff command: {runnable_diff_command}\n{exc.stdout}\n")


def check_result(reports: ProcessResult):
    __tracebackhide__ = True
    # filter out error reports about truncated integration test files
    errors = [
        error
        for error in reports.errors
        if not (
            isinstance(error, ExtractCommandFailedReport)
            and (
                error.stderr == b"\nERRORS:\nUnexpected end of archive\n\n"
                or (
                    error.command.startswith("debugfs ")
                    and b"while creating symlink" in error.stderr
                    and error.stderr.endswith(
                        b"*** buffer overflow detected ***: terminated\n"
                    )
                )
            )
        )
    ]
    assert errors == [], "Unexpected error reports"


def calculate_chunk(
    handler: type[Handler], content: bytes, start_offset: int = 0
) -> ValidChunk | None:
    """Run the handler's ``calculate_chunk`` on a pattern match at ``start_offset``."""
    with File.from_bytes(content) as file:
        file.seek(start_offset)
        return handler().calculate_chunk(file, start_offset)


def find_chunks(handler: type[Handler], content: bytes) -> list[tuple[int, int]]:
    """Search the content like unblob does, with this one handler.

    Covers the handler's patterns and ``calculate_chunk`` together, and returns the
    start and end offset of each chunk found. Fails if ``calculate_chunk`` raises
    an exception that unblob does not treat as an invalid chunk.
    """
    task_result = TaskResult(task=Task(path=Path("/nonexistent"), depth=0, blob_id=""))
    with File.from_bytes(content) as file:
        chunks = search_chunks(file, len(content), (handler,), task_result)
    assert task_result.reports == [], "calculate_chunk raised an exception"
    return [(chunk.start_offset, chunk.end_offset) for chunk in chunks]


def unhex(hexdump: str) -> bytes:
    """Unparses hexdump back to binary representation.

    In addition to basic parsing the following extra features are supported:

    * line comments starting with ``#``
    * squeezing (repetition of previous line) indicated via ``*`` (see: man 1 hexdump)

    Relative position of data is kept in the result object. This means
    that the offset indicator at the beginning of each line is
    significant, each line will be stored at the position indicated
    relative to the start position.

    The printable ASCII column is discarded during parsing.

    NOTE: all lines MUST contain exactly 16 bytes, except the last line, which can have less.
    """
    parsed = _hexdump_parser.parse(hexdump)
    return _HexDumpToBin().transform(parsed)


BYTES_PER_LINE = 16


_hexdump_parser = Lark(
    """
    %import common.NEWLINE
    %import common.HEXDIGIT

    start:   line (_NEWLINE line)* _NEWLINE?
    line:    address [_SEPARATOR hex _SEPARATOR "|"? ascii "|"?]  -> canonical
             | SQUEEZE                                            -> squeezed
    address: HEXDIGIT+                                            -> join
    hex:     HEXDIGIT+ (_SPACE* HEXDIGIT)+                        -> join
    ascii:   CHAR+                                                -> join
    CHAR:    /./
    SQUEEZE: "*"

    _SEPARATOR: ": " | "  "
    _SPACE:     " "
    _NEWLINE:   NEWLINE
"""
)


@attrs.define
class _HexdumpLine:
    offset: int
    data: bytes

    @classmethod
    def from_bytes(cls, offset, data):
        offset = int.from_bytes(binascii.unhexlify(offset), byteorder="big")
        data = binascii.unhexlify(data) if data else b""
        return cls(offset, data)

    def __len__(self):
        return len(self.data)


class _HexDumpToBin(Transformer):
    def __init__(self):
        super().__init__(visit_tokens=False)
        self._last_line = None
        self._squeezing = False

    def join(self, s):
        return "".join(s.strip() for s in s)

    def canonical(self, s):
        line = _HexdumpLine.from_bytes(s[0], s[1])
        if self._squeezing:
            self._squeezing = False
            line = self._squeeze_in_data(line)
        self._last_line = line
        return self._last_line

    def _squeeze_in_data(self, line: _HexdumpLine) -> _HexdumpLine:
        if not self._last_line:
            raise ValueError("Squeezed line cannot be the first line in a hexdump")

        assert len(self._last_line) % BYTES_PER_LINE == 0

        delta = line.offset - (self._last_line.offset + len(self._last_line))
        count = delta // BYTES_PER_LINE

        return _HexdumpLine(
            self._last_line.offset + len(self._last_line),
            self._last_line.data[-BYTES_PER_LINE:] * count + line.data,
        )

    def squeezed(self, _s):
        self._squeezing = True
        return Discard

    def start(self, s):
        rv = io.BytesIO()
        for line in s:
            rv.write(line.data)

        return rv.getvalue()


# PE builders, shared by the PE handler tests (tests/handlers/executable/pe/)

PE_STRUCTS = StructParser(
    _pe_headers.C_DEFINITIONS + _pe_nsis.C_DEFINITIONS + _pe_upx.C_DEFINITIONS
).cparser_le

# surround a PE in the test content, to check that offsets are relative to its start
PE_PREFIX = b"\xff" * 0x20
PE_SUFFIX = b"\xee" * 0x20

PE_E_LFANEW = 0x40
PE_SIZE_OF_HEADERS = 0x200
PE_SECTION_SIZE = 0x200
PE_SECTION_VA = 0x1000
PE_END = PE_SIZE_OF_HEADERS + PE_SECTION_SIZE
# file header, PE32 optional header with all data directories, one section
PE_SECTION_TABLE_END = (
    PE_E_LFANEW
    + PE_STRUCTS.pe_file_header_t.size
    + PE_STRUCTS.optional_header_32_t.size
    + _pe_headers.MAX_DATA_DIRECTORIES * PE_STRUCTS.data_directory_t.size
    + PE_STRUCTS.section_header_t.size
)


def build_pe(
    *,
    plus: bool = False,
    section_size: int = PE_SECTION_SIZE,
    section_data: bytes = b"",
    data_directories: dict[int, tuple[int, int]] | None = None,
    debug_entries: list[tuple[int, int]] | None = None,
    dos: dict | None = None,
    file_header: dict | None = None,
    optional_header: dict | None = None,
    section: dict | None = None,
    extra_sections: list[dict] | None = None,
) -> bytes:
    """Build a PE with one section at PE_SIZE_OF_HEADERS.

    ``debug_entries`` places a debug directory at the start of the section, pointing
    at (pointer_to_raw_data, size_of_data) records.
    """
    directories = dict(data_directories or {})

    section_body = bytearray(section_data)
    if debug_entries is not None:
        entries = b"".join(
            PE_STRUCTS.debug_directory_t(
                debug_type=2, size_of_data=size, pointer_to_raw_data=pointer
            ).dumps()
            for pointer, size in debug_entries
        )
        section_body[: len(entries)] = entries
        directories[_pe_headers.DataDirectory.DEBUG] = (PE_SECTION_VA, len(entries))
    section_body = bytes(section_body).ljust(section_size, b"\x00")

    optional_struct = (
        PE_STRUCTS.optional_header_64_t if plus else PE_STRUCTS.optional_header_32_t
    )
    optional = {
        "magic": _pe_headers.OptionalHeaderMagic.PE32_PLUS
        if plus
        else _pe_headers.OptionalHeaderMagic.PE32,
        "section_alignment": 0x1000,
        "file_alignment": 0x200,
        "size_of_image": 0x2000,
        "size_of_headers": PE_SIZE_OF_HEADERS,
        "number_of_rva_and_sizes": _pe_headers.MAX_DATA_DIRECTORIES,
    }
    optional.update(optional_header or {})
    optional_bytes = optional_struct(**optional).dumps() + b"".join(
        PE_STRUCTS.data_directory_t(
            virtual_address=directories.get(i, (0, 0))[0],
            dir_size=directories.get(i, (0, 0))[1],
        ).dumps()
        for i in range(
            min(optional["number_of_rva_and_sizes"], _pe_headers.MAX_DATA_DIRECTORIES)
        )
    )

    header = {
        "signature": _pe_headers.PE_SIGNATURE,
        "machine": _pe_headers.Machine.AMD64 if plus else _pe_headers.Machine.I386,
        "number_of_sections": 1 + len(extra_sections or []),
        "size_of_optional_header": len(optional_bytes),
    }
    header.update(file_header or {})
    # the section table starts after the declared optional header size
    optional_bytes = optional_bytes.ljust(header["size_of_optional_header"], b"\x00")

    section_header = {
        "name": b".text",
        "virtual_size": section_size,
        "virtual_address": PE_SECTION_VA,
        "size_of_raw_data": section_size,
        "pointer_to_raw_data": PE_SIZE_OF_HEADERS,
    }
    section_header.update(section or {})

    dos_header = {"e_magic": b"MZ", "e_lfanew": PE_E_LFANEW}
    dos_header.update(dos or {})

    headers = (
        PE_STRUCTS.dos_header_t(**dos_header).dumps()
        + PE_STRUCTS.pe_file_header_t(**header).dumps()
        + optional_bytes
        + PE_STRUCTS.section_header_t(**section_header).dumps()
        + b"".join(
            PE_STRUCTS.section_header_t(**extra).dumps()
            for extra in extra_sections or []
        )
    )
    assert len(headers) <= PE_SIZE_OF_HEADERS
    return headers.ljust(PE_SIZE_OF_HEADERS, b"\x00") + section_body


def build_nsis_data(payload_size: int = 0x100, **overrides) -> bytes:
    fields = {
        "flags": 0,
        "siginfo": _pe_nsis.NSIS_SIGINFO,
        "nsinst": _pe_nsis.NSIS_MAGIC,
        "length_of_header": 0x40,
        "length_of_all_following_data": PE_STRUCTS.nsis_firstheader_t.size
        + payload_size,
    }
    fields.update(overrides)
    return PE_STRUCTS.nsis_firstheader_t(**fields).dumps() + b"\xaa" * payload_size


def get_pe_image_end(content: bytes, start_offset: int = 0) -> int:
    """Return the end of the PE image parsed at ``start_offset``, relative to it."""
    with File.from_bytes(content) as file:
        return _pe_headers.PEHeaders.parse(file, start_offset).get_image_end(file)


def nsis_crc(installer: bytes) -> bytes:
    """Return the CRC of an NSIS installer that starts with the PE and ends with the CRC."""
    covered = installer[_pe_nsis.NSIS_CRC_START : -_pe_nsis.NSIS_CRC_SIZE]
    return binascii.crc32(covered).to_bytes(_pe_nsis.NSIS_CRC_SIZE, "little")


def with_nsis(pe: bytes, payload_size: int = 0x100, flags: int = 0) -> bytes:
    """Append NSIS installer data where makensis writes it: after the image, aligned.

    The last 4 bytes of the installer data are its CRC.
    """
    firstheader_offset = round_up(get_pe_image_end(pe), _pe_nsis.NSIS_ALIGNMENT)
    assert len(pe) <= firstheader_offset, "data after the image"
    assert payload_size >= _pe_nsis.NSIS_CRC_SIZE
    installer = pe.ljust(firstheader_offset, b"\x00") + build_nsis_data(
        payload_size, flags=flags
    )
    return installer[: -_pe_nsis.NSIS_CRC_SIZE] + nsis_crc(installer)


PE_CERTIFICATE_SIZE = 0x80


UPX_SECTION_SIZE = 0x400
# large enough for the u_len of build_upx_packheader
UPX_SIZE_OF_IMAGE = 0x10000
UPX_PE_END = PE_SIZE_OF_HEADERS + UPX_SECTION_SIZE
# the section table of build_upx_pe has two entries
UPX_SECTION_TABLE_END = PE_SECTION_TABLE_END + PE_STRUCTS.section_header_t.size
# where upx 4.2.2 puts it in zip2exe.upx.exe: in the padding at the end of the headers
UPX_PACKHEADER_OFFSET = PE_SIZE_OF_HEADERS - 0x20


def build_upx_packheader(**overrides) -> bytes:
    fields = {
        "magic": _pe_upx.UPX_MAGIC,
        "version": 13,
        "format": _pe_upx.UPXFormat.W32PE_I386,
        "method": 2,
        "level": 8,
        "u_adler": 0x9ECE4F41,
        "c_adler": 0x7CA921FB,
        "u_len": 0x876C,
        "c_len": 0x200,
        "u_file_size": 0x5A00,
        "filter": 0x26,
        "filter_cto": 1,
        "n_mru": 0,
    }
    fields.update(overrides)
    checksum = fields.pop("header_checksum", None)
    header = bytearray(PE_STRUCTS.upx_packheader_t(**fields, header_checksum=0).dumps())
    if checksum is None:
        checksum = sum(header[4:-1]) % _pe_upx.UPX_HEADER_CHECKSUM_MODULUS
    header[-1] = checksum
    return bytes(header)


def build_upx_pe(
    *,
    plus: bool = False,
    packheader: bytes | None = None,
    packheader_offset: int = UPX_PACKHEADER_OFFSET,
    **kwargs,
) -> bytes:
    """Build a PE laid out as upx does: UPX0 without raw data, then UPX1."""
    optional_header = {
        "size_of_image": UPX_SIZE_OF_IMAGE,
        **kwargs.pop("optional_header", {}),
    }
    if packheader is None:
        packheader = build_upx_packheader(
            format=_pe_upx.UPXFormat.W64PE_AMD64
            if plus
            else _pe_upx.UPXFormat.W32PE_I386
        )
    pe = bytearray(
        build_pe(
            plus=plus,
            section_size=UPX_SECTION_SIZE,
            section={
                "name": b"UPX0",
                "virtual_size": 0x2000,
                "size_of_raw_data": 0,
                "pointer_to_raw_data": PE_SIZE_OF_HEADERS,
            },
            extra_sections=[
                {
                    "name": b"UPX1",
                    "virtual_size": UPX_SECTION_SIZE,
                    "virtual_address": PE_SECTION_VA + 0x2000,
                    "size_of_raw_data": UPX_SECTION_SIZE,
                    "pointer_to_raw_data": PE_SIZE_OF_HEADERS,
                }
            ],
            optional_header=optional_header,
            **kwargs,
        )
    )
    pe[packheader_offset : packheader_offset + len(packheader)] = packheader
    return bytes(pe)
