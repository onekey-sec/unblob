import abc
import itertools
from pathlib import Path
from typing import List, Optional, Tuple, Type

import attr
from structlog import get_logger

from .file_utils import Endian, File, InvalidInputFormat, StructParser
from .parser import hexstring2regex
from .report import ErrorReport, Report

logger = get_logger()

# The state transitions are:
#
# file ──► pattern match ──► ValidChunk
#


@attr.define(frozen=True)
class Task:
    path: Path
    depth: int


@attr.define
class Chunk:
    """
    Chunk of a Blob, have start and end offset, but still can be invalid.

    For an array ``b``, a chunk ``c`` represents the slice:
    ::

        b[c.start_offset:c.end_offset]
    """

    start_offset: int
    """The index of the first byte of the chunk"""

    end_offset: int
    """The index of the first byte after the end of the chunk"""

    def __attrs_post_init__(self):
        if self.start_offset < 0 or self.end_offset < 0:
            raise InvalidInputFormat(f"Chunk has negative offset: {self}")
        if self.start_offset >= self.end_offset:
            raise InvalidInputFormat(
                f"Chunk has higher start_offset than end_offset: {self}"
            )

    @property
    def size(self) -> int:
        return self.end_offset - self.start_offset

    @property
    def range_hex(self) -> str:
        return f"0x{self.start_offset:x}-0x{self.end_offset:x}"

    def contains(self, other: "Chunk") -> bool:
        return (
            self.start_offset < other.start_offset
            and self.end_offset >= other.end_offset
        )

    def contains_offset(self, offset: int) -> bool:
        return self.start_offset <= offset < self.end_offset

    def __repr__(self) -> str:
        return self.range_hex


@attr.define(repr=False)
class ValidChunk(Chunk):
    """Known to be valid chunk of a Blob, can be extracted with an external program."""

    handler: "Handler" = attr.ib(init=False, eq=False)
    is_encrypted: bool = attr.ib(default=False)

    def extract(self, inpath: Path, outdir: Path):
        if self.is_encrypted:
            logger.warning(
                "Encrypted file is not extracted",
                path=inpath,
                chunk=self,
            )
            raise ExtractError()

        self.handler.extract(inpath, outdir)


@attr.define(repr=False)
class UnknownChunk(Chunk):
    """Gaps between valid chunks or otherwise unknown chunks.

    Important for manual analysis, and analytical certanity: for example
    entropy, other chunks inside it, metadata, etc.

    These are not extracted, just logged for information purposes and further analysis,
    like most common bytest (like \x00 and \xFF), ASCII strings, high entropy, etc.
    """


@attr.define
class TaskResult:
    task: Task
    reports: List[Report] = attr.field(factory=list)
    subtasks: List[Task] = attr.field(factory=list)

    def add_report(self, report: Report):
        self.reports.append(report)

    def add_subtask(self, task: Task):
        self.subtasks.append(task)


@attr.define
class ProcessResult:
    results: List[TaskResult] = attr.field(factory=list)

    @property
    def errors(self) -> List[ErrorReport]:
        reports = itertools.chain.from_iterable(
            r.reports for r in self.results
        )
        return [r for r in reports if isinstance(r, ErrorReport)]

    def register(self, result: TaskResult):
        self.results.append(result)


class ExtractError(Exception):
    """There was an error during extraction"""

    def __init__(self, *reports: Report):
        super().__init__()
        self.reports: Tuple[Report, ...] = reports


class Extractor(abc.ABC):
    def get_dependencies(self) -> List[str]:
        """Returns the external command dependencies."""
        return []

    @abc.abstractmethod
    def extract(self, inpath: Path, outdir: Path):
        """Extract the carved out chunk.

        Raises ExtractError on failure.
        """


class Pattern(str):
    def as_regex(self) -> bytes:
        raise NotImplementedError


class HexString(Pattern):
    """
    Hex string can be a YARA rule like hexadecimal strings to simplify defining
    binary strings using hex encoding, wild-cards, jumps and alternatives.
    Hexstrings are convereted to hyperscan compatible PCRE regex.

    See YARA & Hyperscan documentation for more details:
    - https://yara.readthedocs.io/en/stable/writingrules.html#hexadecimal-strings
    - https://intel.github.io/hyperscan/dev-reference/compilation.html#pattern-support

    You can specify the following:
    - normal bytes using hexadecimals: 01 de ad co de ff
    - wild-cards can match single bytes and can be mixed with normal hex: 01 ?? 02
    - wild-cards can also match first and second nibles: 0? ?0
    - jumps can be specified for multiple wildcard bytes: [3] [2-5]
    - alternatives can be specified as well: ( 01 02 | 03 04 )
    The above can be combined and alternatives nested:
     01 02 ( 03 04 | (0? | 03 | ?0) | 05 ?? ) 06

    Single line comments can be specified using //

    We do NOT support the following YARA syntax:
    - comments using /* */ notation
    - infinite jumps: [-]
    - unbounded jumps: [3-] or [-4] (use [0-4] instead)
    """

    def as_regex(self) -> bytes:
        return hexstring2regex(self)


class Regex(Pattern):
    """
    Byte PCRE regex, see hyperscan documentation for more details:
    https://intel.github.io/hyperscan/dev-reference/compilation.html#pattern-support
    """

    def as_regex(self) -> bytes:
        return self.encode()


class Handler(abc.ABC):
    """A file type handler is responsible for searching, validating and "unblobbing" files from Blobs."""

    NAME: str
    PATTERNS: List[Pattern]
    # We need this, because not every match reflects the actual start
    # (e.g. tar magic is in the middle of the header)
    PATTERN_MATCH_OFFSET: int = 0

    EXTRACTOR: Optional[Extractor]

    @classmethod
    def get_dependencies(cls):
        """Returns external command dependencies needed for this handler to work."""
        if cls.EXTRACTOR:
            return cls.EXTRACTOR.get_dependencies()
        return []

    @abc.abstractmethod
    def calculate_chunk(self, file: File, start_offset: int) -> Optional[ValidChunk]:
        """Calculate the Chunk offsets from the Blob and the file type headers."""

    def extract(self, inpath: Path, outdir: Path):
        if self.EXTRACTOR is None:
            logger.debug("Skipping file: no extractor.", path=inpath)
            raise ExtractError()

        # We only extract every blob once, it's a mistake to extract the same blob again
        outdir.mkdir(parents=True, exist_ok=False)

        self.EXTRACTOR.extract(inpath, outdir)


class StructHandler(Handler):
    C_DEFINITIONS: str
    # A struct from the C_DEFINITIONS used to parse the file's header
    HEADER_STRUCT: str

    def __init__(self):
        self._struct_parser = StructParser(self.C_DEFINITIONS)

    @property
    def cparser_le(self):
        return self._struct_parser.cparser_le

    @property
    def cparser_be(self):
        return self._struct_parser.cparser_be

    def parse_header(self, file: File, endian=Endian.LITTLE):
        header = self._struct_parser.parse(self.HEADER_STRUCT, file, endian)
        logger.debug("Header parsed", header=header, _verbosity=3)
        return header


Handlers = Tuple[Type[Handler], ...]
