from __future__ import annotations

import hashlib
import stat
import traceback
from enum import Enum
from pathlib import Path
from typing import Annotated, Any, Literal, Optional, Union

from pydantic import BaseModel, ConfigDict, Field, field_serializer


class ReportBase(BaseModel):
    """A common base class for different reports. This will enable easy pydantic configuration of all models from a single point in the future if desired."""


class Severity(Enum):
    """Represents possible problems encountered during execution."""

    ERROR = "ERROR"
    WARNING = "WARNING"


class ErrorReportBase(ReportBase):
    severity: Severity


class ErrorReport(ErrorReportBase):
    report_type: Literal["ErrorReport"] = "ErrorReport"


class UnknownErrorBase(ErrorReportBase):
    """Describes an exception raised during file processing."""

    severity: Severity = Severity.ERROR
    exception: Union[str, Exception]

    model_config = ConfigDict(
        arbitrary_types_allowed=True
    )  # Necessary to support Exception type

    def model_post_init(self, __context: Any) -> None:
        if isinstance(self.exception, Exception):
            self.exception = "".join(
                traceback.format_exception(
                    type(self.exception), self.exception, self.exception.__traceback__
                )
            )

    """Exceptions are also formatted at construct time."""


class UnknownError(UnknownErrorBase):
    """Describes an exception raised during file processing."""

    report_type: Literal["UnknownError"] = "UnknownError"


class CalculateChunkExceptionReport(UnknownErrorBase):
    """Describes an exception raised during calculate_chunk execution."""

    start_offset: int
    # Stored in `str` rather than `Handler`, because the pickle picks ups structs from `C_DEFINITIONS`
    handler: str
    report_type: Literal["CalculateChunkExceptionReport"] = (
        "CalculateChunkExceptionReport"
    )


class CalculateMultiFileExceptionReport(UnknownErrorBase):
    """Describes an exception raised during calculate_chunk execution."""

    path: Path
    # Stored in `str` rather than `Handler`, because the pickle picks ups structs from `C_DEFINITIONS`
    handler: str
    report_type: Literal["CalculateMultiFileExceptionReport"] = (
        "CalculateMultiFileExceptionReport"
    )


class ExtractCommandFailedReport(ErrorReportBase):
    """Describes an error when failed to run the extraction command."""

    severity: Severity = Severity.WARNING
    command: str
    stdout: bytes
    stderr: bytes
    exit_code: int
    report_type: Literal["ExtractCommandFailedReport"] = "ExtractCommandFailedReport"

    # In case there is any strange encoding in stdout/stderr, convert them to str when serializing
    @field_serializer("stdout")
    def stdout_to_str(self, v: bytes, _info):
        return str(v)

    @field_serializer("stderr")
    def stderr_to_str(self, v: bytes, _info):
        return str(v)


class OutputDirectoryExistsReport(ErrorReportBase):
    severity: Severity = Severity.ERROR
    path: Path
    report_type: Literal["OutputDirectoryExistsReport"] = "OutputDirectoryExistsReport"


class ExtractorDependencyNotFoundReport(ErrorReportBase):
    """Describes an error when the dependency of an extractor doesn't exist."""

    severity: Severity = Severity.ERROR
    dependencies: list[str]
    report_type: Literal["ExtractorDependencyNotFoundReport"] = (
        "ExtractorDependencyNotFoundReport"
    )


class ExtractorTimedOut(ErrorReportBase):
    """Describes an error when the extractor execution timed out."""

    severity: Severity = Severity.ERROR
    cmd: str
    timeout: float
    report_type: Literal["ExtractorTimedOut"] = "ExtractorTimedOut"


class MaliciousSymlinkRemoved(ErrorReportBase):
    """Describes an error when malicious symlinks have been removed from disk."""

    severity: Severity = Severity.WARNING
    link: str
    target: str
    report_type: Literal["MaliciousSymlinkRemoved"] = "MaliciousSymlinkRemoved"


class MultiFileCollisionReport(ErrorReportBase):
    """Describes an error when MultiFiles collide on the same file."""

    severity: Severity = Severity.ERROR
    paths: set[Path]
    handler: str
    report_type: Literal["MultiFileCollisionReport"] = "MultiFileCollisionReport"


class StatReport(ReportBase):
    path: Path
    size: int
    is_dir: bool
    is_file: bool
    is_link: bool
    link_target: Optional[Path]
    report_type: Literal["StatReport"] = "StatReport"

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


class HashReport(ReportBase):
    md5: str
    sha1: str
    sha256: str
    report_type: Literal["HashReport"] = "HashReport"

    @classmethod
    def from_path(cls, path: Path):
        chunk_size = 1024 * 64
        md5 = hashlib.md5()  # noqa: S324
        sha1 = hashlib.sha1()  # noqa: S324
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


class FileMagicReport(ReportBase):
    magic: str
    mime_type: str
    report_type: Literal["FileMagicReport"] = "FileMagicReport"


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


class RandomnessReport(ReportBase):
    shannon: RandomnessMeasurements
    chi_square: RandomnessMeasurements
    report_type: Literal["RandomnessReport"] = "RandomnessReport"


class ChunkReport(ReportBase):
    id: str
    handler_name: str
    start_offset: int
    end_offset: int
    size: int
    is_encrypted: bool
    extraction_reports: list[Report]
    report_type: Literal["ChunkReport"] = "ChunkReport"


class UnknownChunkReport(ReportBase):
    id: str
    start_offset: int
    end_offset: int
    size: int
    randomness: Optional[RandomnessReport]
    report_type: Literal["UnknownChunkReport"] = "UnknownChunkReport"


class CarveDirectoryReport(ReportBase):
    carve_dir: Path
    report_type: Literal["CarveDirectoryReport"] = "CarveDirectoryReport"


class MultiFileReport(ReportBase):
    id: str
    handler_name: str
    name: str
    paths: list[Path]
    extraction_reports: list[Report]
    report_type: Literal["MultiFileReport"] = "MultiFileReport"


class ExtractionProblemBase(ReportBase):
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


class ExtractionProblem(ExtractionProblemBase):
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

    report_type: Literal["ExtractionProblem"] = "ExtractionProblem"


class PathTraversalProblem(ExtractionProblemBase):
    extraction_path: str
    report_type: Literal["PathTraversalProblem"] = "PathTraversalProblem"

    def log_with(self, logger):
        logger.warning(
            self.log_msg,
            path=self.path,
            extraction_path=self.extraction_path,
        )


class LinkExtractionProblem(ExtractionProblemBase):
    link_path: str
    report_type: Literal["LinkExtractionProblem"] = "LinkExtractionProblem"

    def log_with(self, logger):
        logger.warning(self.log_msg, path=self.path, link_path=self.link_path)


class SpecialFileExtractionProblem(ExtractionProblemBase):
    mode: int
    device: int
    report_type: Literal["SpecialFileExtractionProblem"] = (
        "SpecialFileExtractionProblem"
    )

    def log_with(self, logger):
        logger.warning(self.log_msg, path=self.path, mode=self.mode, device=self.device)


Report = Annotated[
    Union[
        ErrorReport,
        UnknownError,
        CalculateChunkExceptionReport,
        CalculateMultiFileExceptionReport,
        ExtractCommandFailedReport,
        OutputDirectoryExistsReport,
        ExtractorDependencyNotFoundReport,
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
    ],
    Field(discriminator="report_type"),
]
