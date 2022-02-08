from enum import Enum
from typing import List, Optional

import attr


class Severity(Enum):
    """Represents possible problems encountered during execution"""

    ERROR = "ERROR"
    WARNING = "WARNING"


@attr.define(frozen=True, kw_only=True)
class Report:
    """A common base class for different reports"""

    # Stored in `str` rather than `Handler`, because the pickle picks ups structs from `C_DEFINITIONS`
    handler: Optional[str] = None

    def asdict(self) -> dict:
        return attr.asdict(self)


class Error(Report):
    severity: Severity


class Reports(List[Report]):
    @property
    def errors(self) -> List[Error]:
        return [r for r in self if isinstance(r, Error)]


@attr.define(kw_only=True)
class UnknownError(Error):
    """Describes an exception raised during file processing"""

    severity: Severity = Severity.ERROR
    exception: Exception


@attr.define(kw_only=True)
class CalculateChunkExceptionReport(UnknownError):
    """Describes an exception raised during calculate_chunk execution"""

    start_offset: int


@attr.define(kw_only=True)
class ExtractCommandFailedReport(Error):
    """Describes an error when failed to run the extraction command"""

    severity: Severity = Severity.WARNING
    command: str
    stdout: bytes
    stderr: bytes
    exit_code: int


@attr.define(kw_only=True)
class ExtractorDependencyNotFoundReport(Error):
    """Describes an error when the dependency of an extractor doesn't exist"""

    severity: Severity = Severity.ERROR
    dependencies: List[str]


@attr.define(kw_only=True)
class MaliciousSymlinkRemoved(Error):
    """Describes an error when malicious symlinks have been removed from disk."""

    severity: Severity = Severity.WARNING
    link: str
    target: str
