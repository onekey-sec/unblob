import io
from typing import List, Optional
from typing_extensions import Protocol
import attr

# The state transitions are:
#                                      ┌──► ValidChunk
# Blob ──► YaraMatchResult ──► Chunk ──┤
#                                      └──► UnknownChunk


@attr.s(auto_attribs=True)
class Blob:
    """Unknown bytes, can be file, memory, anything.

    Found as the result of a YARA search.
    These are the things we are "unblobbing".
    """

    name: str
    start_offset: int


@attr.s(auto_attribs=True)
class YaraMatchResult:
    """Results of a YARA match grouped by file types (handlers).

    When running a YARA search for specific bytes, we get a list of Blobs
    and the Handler to the corresponding YARA rule.
    """

    handler: "Handler"
    blobs: List[Blob]


@attr.s(auto_attribs=True)
class Chunk:
    """Chunk of a Blob, have start and end offset, but still can be invalid."""

    start_offset: int
    end_offset: int
    handler: Optional["Handler"] = None

    @property
    def size(self) -> int:
        return self.end_offset - self.start_offset

    @property
    def range_hex(self) -> str:
        return f"0x{self.start_offset:x} - 0x{self.end_offset:x}"

    @property
    def range_dec(self) -> str:
        return f"{self.start_offset} - {self.end_offset}"


class ValidChunk(Chunk):
    """Known to be valid chunk of a Blob, can be extracted with an external program."""


class UnknownChunk(Chunk):
    """Gaps between valid chunks or otherwise unknown chunks.

    Important for manual analysis, and analytical certanity: for example
    entropy, other chunks inside it, metadata, etc.

    These are not extracted, just logged for information purposes and further analysis,
    like most common bytest (like \x00 and \xFF), ASCII strings, high entropy, etc.
    """


class Handler(Protocol):
    """A file type handler is responsible for searching, validating and "unblobbing" files from Blobs."""

    NAME: str
    YARA_RULE: str

    @staticmethod
    def validate_blob(file: io.BufferedReader, blob: Blob):
        """Validate that the found YARA match is actually a valid Blob for this handler which it can extract."""

    @staticmethod
    def calculate_chunk(file: io.BufferedReader, blob: Blob) -> Chunk:
        """Calculate the Chunk offsets from the Blob and the file type headers."""

    @staticmethod
    def make_extract_command(inpath: str, outdir: str) -> List[str]:
        """Make the extract command with the external tool, which can be passed for subprocess.run."""
