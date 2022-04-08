from enum import Enum
from pathlib import Path
from typing import List, Optional

import attr


class Severity(Enum):
    """Represents possible problems encountered during execution"""

    ERROR = "ERROR"
    WARNING = "WARNING"


@attr.define(kw_only=True)
class Report:
    """A common base class for different reports"""

    severity: Severity

    # Stored in `str` rather than `Handler`, because the pickle picks ups structs from `C_DEFINITIONS`
    handler: Optional[str] = None

    def asdict(self) -> dict:
        return attr.asdict(self)


@attr.define(kw_only=True)
class UnknownError(Report):
    """Describes an exception raised during file processing"""

    severity: Severity = Severity.ERROR
    exception: Exception


@attr.define(kw_only=True)
class CalculateChunkExceptionReport(UnknownError):
    """Describes an exception raised during calculate_chunk execution"""

    start_offset: int


@attr.define(kw_only=True)
class ExtractCommandFailedReport(Report):
    """Describes an error when failed to run the extraction command"""

    severity: Severity = Severity.WARNING
    command: str
    stdout: bytes
    stderr: bytes
    exit_code: int


@attr.define(kw_only=True)
class ExtractDirectoriesExistReport(Report):
    severity: Severity = Severity.ERROR
    paths: List[Path]


@attr.define(kw_only=True)
class ExtractorDependencyNotFoundReport(Report):
    """Describes an error when the dependency of an extractor doesn't exist"""

    severity: Severity = Severity.ERROR
    dependencies: List[str]


@attr.define(kw_only=True)
class MaliciousSymlinkRemoved(Report):
    """Describes an error when malicious symlinks have been removed from disk."""

    severity: Severity = Severity.WARNING
    link: str
    target: str
