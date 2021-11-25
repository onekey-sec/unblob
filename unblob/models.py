import abc
import functools
import io
from typing import List, Optional

import attr
import yara
from structlog import get_logger

from .file_utils import Endian, StructParser

logger = get_logger()

# The state transitions are:
#
# file ──► YaraMatchResult ──► Chunk ──► ValidChunk
#


@attr.define
class YaraMatchResult:
    """Results of a YARA match grouped by file types (handlers).

    When running a YARA search for specific bytes, we get a list of Blobs
    and the Handler to the corresponding YARA rule.
    """

    handler: "Handler"
    match: yara.Match


@attr.define
class Chunk:
    """Chunk of a Blob, have start and end offset, but still can be invalid."""

    start_offset: int
    # This is the last byte included
    end_offset: int
    handler: "Handler" = attr.ib(init=False, eq=False)

    @property
    def size(self) -> int:
        return self.end_offset - self.start_offset + 1

    @property
    def range_hex(self) -> str:
        end_offset = f"0x{self.end_offset:x}" if self.end_offset is not None else ""
        return f"0x{self.start_offset:x}-{end_offset}"

    @property
    def range_dec(self) -> str:
        return f"{self.start_offset} - {self.end_offset}"

    def contains(self, other: "Chunk"):
        return (
            self.start_offset < other.start_offset
            and self.end_offset >= other.end_offset
        )

    def __repr__(self):
        return self.range_hex


@attr.define(repr=False)
class ValidChunk(Chunk):
    """Known to be valid chunk of a Blob, can be extracted with an external program."""


@attr.define(repr=False)
class UnknownChunk(Chunk):
    """Gaps between valid chunks or otherwise unknown chunks.

    Important for manual analysis, and analytical certanity: for example
    entropy, other chunks inside it, metadata, etc.

    These are not extracted, just logged for information purposes and further analysis,
    like most common bytest (like \x00 and \xFF), ASCII strings, high entropy, etc.
    """

    reason: str
    end_offset: Optional[int] = None


class Handler(abc.ABC):
    """A file type handler is responsible for searching, validating and "unblobbing" files from Blobs."""

    NAME: str
    YARA_RULE: str
    # We need this, because not every match reflects the actual start
    # (e.g. tar magic is in the middle of the header)
    YARA_MATCH_OFFSET: int = 0

    @abc.abstractmethod
    def calculate_chunk(
        self, file: io.BufferedIOBase, start_offset: int
    ) -> Optional[ValidChunk]:
        """Calculate the Chunk offsets from the Blob and the file type headers."""

    @staticmethod
    @abc.abstractmethod
    def make_extract_command(inpath: str, outdir: str) -> List[str]:
        """Make the extract command with the external tool, which can be passed for subprocess.run."""


class StructHandler(Handler):
    C_DEFINITIONS: str
    # A struct from the C_DEFINITIONS used to parse the file's header
    HEADER_STRUCT: str

    def __init__(self):
        struct_parser = StructParser(self.C_DEFINITIONS)
        self._header_parser = functools.partial(struct_parser.parse, self.HEADER_STRUCT)

    def parse_header(self, file: io.BufferedIOBase, endian=Endian.LITTLE):
        header = self._header_parser(file, endian)
        logger.debug("Header parsed", header=header)
        return header
