from typing import List, Optional

import attr


@attr.define(kw_only=True)
class Report:
    """A common base class for different reports"""

    # Stored in `str` rather than `Handler`, because the pickle picks ups structs from `C_DEFINITIONS`
    handler: Optional[str] = None

    def asdict(self) -> dict:
        return attr.asdict(self)


@attr.define(kw_only=True)
class UnknownError(Report):
    """Describes an exception raised during file processing"""

    exception: Exception


@attr.define(kw_only=True)
class CalculateChunkExceptionReport(UnknownError):
    """Describes an exception raised during calculate_chunk execution"""

    start_offset: int


@attr.define(kw_only=True)
class ExtractCommandFailedReport(Report):
    """Describes an error when failed to run the extraction command"""

    command: str
    stdout: bytes
    stderr: bytes
    exit_code: int


@attr.define(kw_only=True)
class ExtractorDependencyNotFoundReport(Report):
    """Describes an error when the dependency of an extractor doesn't exist"""

    dependencies: List[str]


@attr.define(kw_only=True)
class MaliciousSymlinkRemoved(Report):
    """Describes an error when malicious symlinks have been removed from disk."""

    link: str
    target: str
