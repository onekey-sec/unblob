# ruff: noqa: UP007,UP045

from __future__ import annotations

import base64
import hashlib
import stat
import traceback
from enum import Enum
from pathlib import Path
from typing import TYPE_CHECKING, Any, Optional, Union

if TYPE_CHECKING:
    from collections.abc import Iterable

from pydantic import (
    BaseModel,
    ConfigDict,
    computed_field,
    field_serializer,
    field_validator,
)


class Report(BaseModel):
    """A common base class for different reports. This will enable easy pydantic configuration of all models from a single point in the future if desired."""

    @computed_field
    @property
    def __typename__(self) -> str:
        return self.__class__.__name__


class Severity(Enum):
    """Represents possible problems encountered during execution."""

    ERROR = "ERROR"
    WARNING = "WARNING"


class ErrorReport(Report):
    severity: Severity


class UnknownError(ErrorReport):
    """Describes an exception raised during file processing."""

    severity: Severity = Severity.ERROR
    exception: Union[str, Exception]

    model_config = ConfigDict(
        arbitrary_types_allowed=True
    )  # Necessary to support Exception type

    def model_post_init(self, _: Any) -> None:
        if isinstance(self.exception, Exception):
            self.exception = "".join(
                traceback.format_exception(
                    type(self.exception), self.exception, self.exception.__traceback__
                )
            )

    """Exceptions are also formatted at construct time."""


class CalculateChunkExceptionReport(UnknownError):
    """Describes an exception raised during calculate_chunk execution."""

    start_offset: int
    # Stored in `str` rather than `Handler`, because the pickle picks ups structs from `C_DEFINITIONS`
    handler: str


class CalculateMultiFileExceptionReport(UnknownError):
    """Describes an exception raised during calculate_chunk execution."""

    path: Path
    # Stored in `str` rather than `Handler`, because the pickle picks ups structs from `C_DEFINITIONS`
    handler: str


class ExtractCommandFailedReport(ErrorReport):
    """Describes an error when failed to run the extraction command."""

    severity: Severity = Severity.WARNING
    command: str
    stdout: bytes
    stderr: bytes
    exit_code: int

    # Use base64 to encode and decode bytes data in case there are non-standard characters
    @field_serializer("stdout", "stderr")
    def encode_bytes(self, v: bytes, _):
        return base64.b64encode(v).decode("ascii")

    @field_validator("stdout", "stderr", mode="before")
    @classmethod
    def decode_bytes(cls, v: Any):
        if isinstance(v, str):
            return base64.b64decode(v)
        return v


class OutputDirectoryExistsReport(ErrorReport):
    severity: Severity = Severity.ERROR
    path: Path


class ExtractorDependencyNotFoundReport(ErrorReport):
    """Describes an error when the dependency of an extractor doesn't exist."""

    severity: Severity = Severity.ERROR
    dependencies: list[str]


class ExtractorTimedOut(ErrorReport):
    """Describes an error when the extractor execution timed out."""

    severity: Severity = Severity.ERROR
    cmd: str
    timeout: float


class MaliciousSymlinkRemoved(ErrorReport):
    """Describes an error when malicious symlinks have been removed from disk."""

    severity: Severity = Severity.WARNING
    link: str
    target: str


class MultiFileCollisionReport(ErrorReport):
    """Describes an error when MultiFiles collide on the same file."""

    severity: Severity = Severity.ERROR
    paths: set[Path]
    handler: str


class StatReport(Report):
    path: Path
    size: int
    is_dir: bool
    is_file: bool
    is_link: bool
    link_target: Optional[Path]

    @classmethod
    def from_path(cls, path: Path):
        st = path.lstat()
        mode = st.st_mode
        try:
            link_target = Path.readlink(path)
        except OSError:
            link_target = None

        return cls(
            path=path,
            size=st.st_size,
            is_dir=stat.S_ISDIR(mode),
            is_file=stat.S_ISREG(mode),
            is_link=stat.S_ISLNK(mode),
            link_target=link_target,
        )


class HashReport(Report):
    md5: str
    sha1: str
    sha256: str

    @classmethod
    def from_path(cls, path: Path):
        chunk_size = 1024 * 64
        md5 = hashlib.md5(usedforsecurity=False)
        sha1 = hashlib.sha1(usedforsecurity=False)
        sha256 = hashlib.sha256()

        with path.open("rb") as f:
            while chunk := f.read(chunk_size):
                md5.update(chunk)
                sha1.update(chunk)
                sha256.update(chunk)

        return cls(
            md5=md5.hexdigest(),
            sha1=sha1.hexdigest(),
            sha256=sha256.hexdigest(),
        )


class FileMagicReport(Report):
    magic: str
    mime_type: str


class RandomnessMeasurements(BaseModel):
    percentages: list[float]
    block_size: int
    mean: float

    @property
    def highest(self):
        return max(self.percentages)

    @property
    def lowest(self):
        return min(self.percentages)


class RandomnessReport(Report):
    shannon: RandomnessMeasurements
    chi_square: RandomnessMeasurements


class ChunkReport(Report):
    id: str
    handler_name: str
    start_offset: int
    end_offset: int
    size: int
    is_encrypted: bool
    extraction_reports: list[Report]

    @field_validator("extraction_reports", mode="before")
    @classmethod
    def validate_extraction_reports(cls, value: Any) -> list[Report]:
        return validate_report_list(value)


class UnknownChunkReport(Report):
    id: str
    start_offset: int
    end_offset: int
    size: int
    randomness: Optional[RandomnessReport]

    @field_validator("randomness", mode="before")
    @classmethod
    def validate_randomness(cls, value: Any) -> Optional[RandomnessReport]:
        if value is None:
            return None
        parsed = parse_report(value)
        if not isinstance(parsed, RandomnessReport):
            raise TypeError("Randomness must be a RandomnessReport.")
        return parsed


class CarveDirectoryReport(Report):
    carve_dir: Path


class MultiFileReport(Report):
    id: str
    handler_name: str
    name: str
    paths: list[Path]
    extraction_reports: list[Report]

    @field_validator("extraction_reports", mode="before")
    @classmethod
    def validate_extraction_reports(cls, value: Any) -> list[Report]:
        return validate_report_list(value)


class ExtractedFileDeletedReport(Report):
    path: Path
    handler_name: str


class ExtractionProblem(Report):
    """A non-fatal problem discovered during extraction.

    A report like this still means, that the extraction was successful,
    but there were problems that got resolved.
    The output is expected to be complete, with the exception of
    the reported path.

    Examples
    --------
    - duplicate entries for certain archive formats (tar, zip)
    - unsafe symlinks pointing outside of extraction directory

    """

    problem: str
    resolution: str
    path: Optional[str] = None

    @property
    def log_msg(self):
        return f"{self.problem} {self.resolution}"

    def log_with(self, logger):
        logger.warning(self.log_msg, path=self.path)


class PathTraversalProblem(ExtractionProblem):
    extraction_path: str

    def log_with(self, logger):
        logger.warning(
            self.log_msg,
            path=self.path,
            extraction_path=self.extraction_path,
        )


class LinkExtractionProblem(ExtractionProblem):
    link_path: str

    def log_with(self, logger):
        logger.warning(self.log_msg, path=self.path, link_path=self.link_path)


class SpecialFileExtractionProblem(ExtractionProblem):
    mode: int
    device: int

    def log_with(self, logger):
        logger.warning(self.log_msg, path=self.path, mode=self.mode, device=self.device)


BUILTIN_REPORT_TYPES: tuple[type[Report], ...] = (
    ErrorReport,
    UnknownError,
    CalculateChunkExceptionReport,
    CalculateMultiFileExceptionReport,
    ExtractCommandFailedReport,
    OutputDirectoryExistsReport,
    ExtractorDependencyNotFoundReport,
    ExtractedFileDeletedReport,
    ExtractorTimedOut,
    MaliciousSymlinkRemoved,
    MultiFileCollisionReport,
    StatReport,
    HashReport,
    FileMagicReport,
    RandomnessReport,
    ChunkReport,
    UnknownChunkReport,
    CarveDirectoryReport,
    MultiFileReport,
    ExtractionProblem,
    PathTraversalProblem,
    LinkExtractionProblem,
    SpecialFileExtractionProblem,
)

_REPORT_REGISTRY: dict[str, type[Report]] = {}


def register_report_type(report_type: type[Report]) -> None:
    typename = report_type.__name__
    existing = _REPORT_REGISTRY.get(typename)
    if existing is not None and existing is not report_type:
        raise ValueError(f"Report type name conflict: {typename}")
    _REPORT_REGISTRY[typename] = report_type


def register_report_types(report_types: Iterable[type[Report]]) -> None:
    for report_type in report_types:
        register_report_type(report_type)


def get_report_type(typename: str) -> type[Report] | None:
    return _REPORT_REGISTRY.get(typename)


def parse_report(report: Report | dict[str, Any]) -> Report:
    if isinstance(report, Report):
        return report
    if not isinstance(report, dict):
        raise TypeError("Report data must be a mapping or Report instance.")
    typename = report.get("__typename__")
    if not typename:
        raise ValueError("Report data is missing __typename__.")
    report_type = get_report_type(typename)
    if report_type is None:
        raise ValueError(f"Unknown report type: {typename}")
    return report_type.model_validate(report)


def validate_report_list(value: Any) -> list[Report]:
    if not isinstance(value, list):
        raise TypeError("Report list must be a list.")
    return [parse_report(item) for item in value]


register_report_types(BUILTIN_REPORT_TYPES)
