import abc
import dataclasses
import itertools
import json
from collections.abc import Iterable
from enum import Enum
from pathlib import Path
from typing import Generic, Optional, TypeVar, Union

import attrs
from pydantic import BaseModel
from structlog import get_logger

from .file_utils import Endian, File, InvalidInputFormat, StructParser
from .identifiers import new_id
from .parser import hexstring2regex
from .report import (
    CarveDirectoryReport,
    ChunkReport,
    ErrorReportBase,
    MultiFileReport,
    RandomnessReport,
    Report,
    UnknownChunkReport,
)

logger = get_logger()

# The state transitions are:
#
# file ──► pattern match ──► ValidChunk
#


class HandlerType(Enum):
    ARCHIVE = "Archive"
    COMPRESSION = "Compression"
    FILESYSTEM = "FileSystem"
    EXECUTABLE = "Executable"
    BAREMETAL = "Baremetal"
    BOOTLOADER = "Bootloader"
    ENCRYPTION = "Encryption"


@dataclasses.dataclass(frozen=True)
class Reference:
    title: str
    url: str


@dataclasses.dataclass
class HandlerDoc:
    name: str
    description: Union[str, None]
    vendor: Union[str, None]
    references: list[Reference]
    limitations: list[str]
    handler_type: HandlerType
    fully_supported: bool = dataclasses.field(init=False)

    def __post_init__(self):
        self.fully_supported = len(self.limitations) == 0


class Task(BaseModel):
    path: Path
    depth: int
    blob_id: str
    is_multi_file: bool = False


@attrs.define
class Blob:
    id: str = attrs.field(
        factory=new_id,
    )


@attrs.define
class Chunk(Blob):
    """File chunk, have start and end offset, but still can be invalid.

    For an array ``b``, a chunk ``c`` represents the slice:
    ::

        b[c.start_offset:c.end_offset]
    """

    start_offset: int = attrs.field(kw_only=True)
    """The index of the first byte of the chunk"""

    end_offset: int = attrs.field(kw_only=True)
    """The index of the first byte after the end of the chunk"""

    file: Optional[File] = None

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

    @property
    def is_whole_file(self):
        assert self.file
        return self.start_offset == 0 and self.end_offset == self.file.size()

    def contains(self, other: "Chunk") -> bool:
        return (
            self.start_offset < other.start_offset
            and self.end_offset >= other.end_offset
        ) or (
            self.start_offset <= other.start_offset
            and self.end_offset > other.end_offset
        )

    def contains_offset(self, offset: int) -> bool:
        return self.start_offset <= offset < self.end_offset

    def __repr__(self) -> str:
        return self.range_hex


@attrs.define(repr=False)
class ValidChunk(Chunk):
    """Known to be valid chunk of a File, can be extracted with an external program."""

    handler: "Handler" = attrs.field(init=False, eq=False)
    is_encrypted: bool = attrs.field(default=False)

    def extract(self, inpath: Path, outdir: Path) -> Optional["ExtractResult"]:
        if self.is_encrypted:
            logger.warning(
                "Encrypted file is not extracted",
                path=inpath,
                chunk=self,
            )
            raise ExtractError

        return self.handler.extract(inpath, outdir)

    def as_report(self, extraction_reports: list[Report]) -> ChunkReport:
        return ChunkReport(
            id=self.id,
            start_offset=self.start_offset,
            end_offset=self.end_offset,
            size=self.size,
            handler_name=self.handler.NAME,
            is_encrypted=self.is_encrypted,
            extraction_reports=extraction_reports,
        )


@attrs.define(repr=False)
class UnknownChunk(Chunk):
    r"""Gaps between valid chunks or otherwise unknown chunks.

    Important for manual analysis, and analytical certainty: for example
    randomness, other chunks inside it, metadata, etc.

    These are not extracted, just logged for information purposes and further analysis,
    like most common bytes (like \x00 and \xFF), ASCII strings, high randomness, etc.
    """

    def as_report(self, randomness: Optional[RandomnessReport]) -> UnknownChunkReport:
        return UnknownChunkReport(
            id=self.id,
            start_offset=self.start_offset,
            end_offset=self.end_offset,
            size=self.size,
            randomness=randomness,
        )


@attrs.define(repr=False)
class PaddingChunk(Chunk):
    r"""Gaps between valid chunks or otherwise unknown chunks.

    Important for manual analysis, and analytical certanity: for example
    randomness, other chunks inside it, metadata, etc.
    """

    def as_report(
        self,
        randomness: Optional[RandomnessReport],  #   noqa: ARG002
    ) -> ChunkReport:
        return ChunkReport(
            id=self.id,
            start_offset=self.start_offset,
            end_offset=self.end_offset,
            size=self.size,
            is_encrypted=False,
            handler_name="padding",
            extraction_reports=[],
        )


@attrs.define
class MultiFile(Blob):
    name: str = attrs.field(kw_only=True)
    paths: list[Path] = attrs.field(kw_only=True)

    handler: "DirectoryHandler" = attrs.field(init=False, eq=False)

    def extract(self, outdir: Path) -> Optional["ExtractResult"]:
        return self.handler.extract(self.paths, outdir)

    def as_report(self, extraction_reports: list[Report]) -> MultiFileReport:
        return MultiFileReport(
            id=self.id,
            name=self.name,
            paths=self.paths,
            handler_name=self.handler.NAME,
            extraction_reports=extraction_reports,
        )


ReportType = TypeVar("ReportType", bound=Report)


class TaskResult(BaseModel):
    task: Task
    reports: list[Report] = []
    subtasks: list[Task] = []

    def add_report(self, report: Report):
        self.reports.append(report)

    def add_subtask(self, task: Task):
        self.subtasks.append(task)

    def filter_reports(self, report_class: type[ReportType]) -> list[ReportType]:
        return [report for report in self.reports if isinstance(report, report_class)]


class ProcessResult(BaseModel):
    results: list[TaskResult] = []

    @property
    def errors(self) -> list[ErrorReportBase]:
        reports = itertools.chain.from_iterable(r.reports for r in self.results)
        interesting_reports = (
            r for r in reports if isinstance(r, (ErrorReportBase, ChunkReport))
        )
        errors = []
        for report in interesting_reports:
            if isinstance(report, ErrorReportBase):
                errors.append(report)
            else:
                errors.extend(
                    r
                    for r in report.extraction_reports
                    if isinstance(r, ErrorReportBase)
                )
        return errors

    def register(self, result: TaskResult):
        self.results.append(result)

    def to_json(self, indent="  "):
        return json.dumps(
            [result.model_dump(mode="json") for result in self.results], indent=indent
        )

    def get_output_dir(self) -> Optional[Path]:
        try:
            top_result = self.results[0]
            if carves := top_result.filter_reports(CarveDirectoryReport):
                # we have a top level carve
                return carves[0].carve_dir

            # we either have an extraction,
            # and the extract directory registered as subtask
            return top_result.subtasks[0].path
        except IndexError:
            # or no extraction
            return None


class ExtractError(Exception):
    """There was an error during extraction."""

    def __init__(self, *reports: Report):
        super().__init__()
        self.reports: tuple[Report, ...] = reports


@attrs.define(kw_only=True)
class ExtractResult:
    reports: list[Report]


class Extractor(abc.ABC):
    def get_dependencies(self) -> list[str]:
        """Return the external command dependencies."""
        return []

    @abc.abstractmethod
    def extract(self, inpath: Path, outdir: Path) -> Optional[ExtractResult]:
        """Extract the carved out chunk.

        Raises ExtractError on failure.
        """


class DirectoryExtractor(abc.ABC):
    def get_dependencies(self) -> list[str]:
        """Return the external command dependencies."""
        return []

    @abc.abstractmethod
    def extract(self, paths: list[Path], outdir: Path) -> Optional[ExtractResult]:
        """Extract from a multi file path list.

        Raises ExtractError on failure.
        """


class Pattern(str):
    def as_regex(self) -> bytes:
        raise NotImplementedError


class HexString(Pattern):
    """Hex string can be a YARA rule like hexadecimal string.

    It is useful to simplify defining binary strings using hex
    encoding, wild-cards, jumps and alternatives.  Hexstrings are
    convereted to hyperscan compatible PCRE regex.

    See YARA & Hyperscan documentation for more details:

        - https://yara.readthedocs.io/en/stable/writingrules.html#hexadecimal-strings

        - https://intel.github.io/hyperscan/dev-reference/compilation.html#pattern-support

    You can specify the following:

        - normal bytes using hexadecimals: 01 de ad co de ff

        - wild-cards can match single bytes and can be mixed with
          normal hex: 01 ??  02

        - wild-cards can also match first and second nibles: 0?  ?0

        - jumps can be specified for multiple wildcard bytes: [3]
          [2-5]

        - alternatives can be specified as well: ( 01 02 | 03 04 ) The
          above can be combined and alternatives nested: 01 02 ( 03 04
          | (0?  | 03 | ?0) | 05 ??  ) 06

    Single line comments can be specified using //

    We do NOT support the following YARA syntax:

        - comments using /* */ notation

        - infinite jumps: [-]

        - unbounded jumps: [3-] or [-4] (use [0-4] instead)
    """

    def as_regex(self) -> bytes:
        return hexstring2regex(self)


class Regex(Pattern):
    """Byte PCRE regex.

    See hyperscan documentation for more details:
    https://intel.github.io/hyperscan/dev-reference/compilation.html#pattern-support.
    """

    def as_regex(self) -> bytes:
        return self.encode()


class DirectoryPattern:
    def get_files(self, directory: Path) -> Iterable[Path]:
        raise NotImplementedError


class Glob(DirectoryPattern):
    def __init__(self, pattern):
        self._pattern = pattern

    def get_files(self, directory: Path) -> Iterable[Path]:
        return directory.glob(self._pattern)


class SingleFile(DirectoryPattern):
    def __init__(self, filename):
        self._filename = filename

    def get_files(self, directory: Path) -> Iterable[Path]:
        path = directory / self._filename
        return [path] if path.exists() else []


class DirectoryHandler(abc.ABC):
    """A directory type handler is responsible for searching, validating and "unblobbing" files from multiple files in a directory."""

    NAME: str

    EXTRACTOR: DirectoryExtractor

    PATTERN: DirectoryPattern

    DOC: Union[HandlerDoc, None]

    @classmethod
    def get_dependencies(cls):
        """Return external command dependencies needed for this handler to work."""
        if cls.EXTRACTOR:
            return cls.EXTRACTOR.get_dependencies()
        return []

    @abc.abstractmethod
    def calculate_multifile(self, file: Path) -> Optional[MultiFile]:
        """Calculate the MultiFile in a directory, using a file matched by the pattern as a starting point."""

    def extract(self, paths: list[Path], outdir: Path) -> Optional[ExtractResult]:
        if self.EXTRACTOR is None:
            logger.debug("Skipping file: no extractor.", paths=paths)
            raise ExtractError

        # We only extract every blob once, it's a mistake to extract the same blob again
        outdir.mkdir(parents=True, exist_ok=False)

        return self.EXTRACTOR.extract(paths, outdir)


TExtractor = TypeVar("TExtractor", bound=Union[None, Extractor])


class Handler(abc.ABC, Generic[TExtractor]):
    """A file type handler is responsible for searching, validating and "unblobbing" files from Blobs."""

    NAME: str
    PATTERNS: list[Pattern]
    # We need this, because not every match reflects the actual start
    # (e.g. tar magic is in the middle of the header)
    PATTERN_MATCH_OFFSET: int = 0

    EXTRACTOR: TExtractor

    DOC: Union[HandlerDoc, None]

    @classmethod
    def get_dependencies(cls):
        """Return external command dependencies needed for this handler to work."""
        if cls.EXTRACTOR is not None:
            return cls.EXTRACTOR.get_dependencies()
        return []

    @abc.abstractmethod
    def calculate_chunk(self, file: File, start_offset: int) -> Optional[ValidChunk]:
        """Calculate the Chunk offsets from the File and the file type headers."""

    def extract(self, inpath: Path, outdir: Path) -> Optional[ExtractResult]:
        if self.EXTRACTOR is None:
            logger.debug("Skipping file: no extractor.", path=inpath)
            raise ExtractError

        # We only extract every blob once, it's a mistake to extract the same blob again
        outdir.mkdir(parents=True, exist_ok=False)

        return self.EXTRACTOR.extract(inpath, outdir)


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


Handlers = tuple[type[Handler], ...]
DirectoryHandlers = tuple[type[DirectoryHandler], ...]
