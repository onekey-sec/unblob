import itertools
import json
import multiprocessing
from enum import Enum
from pathlib import Path
from typing import Iterable, List

import attr
from structlog import get_logger

from .handlers import BUILTIN_HANDLERS, Handlers
from .report import ChunkReport, ErrorReport, Report

logger = get_logger()

# The state transitions are:
#
# file ──► pattern match ──► ValidChunk
#


DEFAULT_DEPTH = 10
DEFAULT_PROCESS_NUM = multiprocessing.cpu_count()
DEFAULT_SKIP_MAGIC = (
    "BFLT",
    "JPEG",
    "GIF",
    "PNG",
    "SQLite",
    "compiled Java class",
    "TrueType Font data",
    "PDF document",
    "magic binary file",
    "MS Windows icon resource",
    "PE32+ executable (EFI application)",
    "Web Open Font Format",
    "GNU message catalog",
    "Xilinx BIT data",
    "Microsoft Excel",
    "Microsoft Word",
    "Microsoft PowerPoint",
    "OpenDocument",
)


@attr.define(kw_only=True)
class ExtractionConfig:
    extract_root: Path = attr.field(converter=lambda value: value.resolve())
    force_extract: bool = False
    entropy_depth: int
    entropy_plot: bool = False
    max_depth: int = DEFAULT_DEPTH
    skip_magic: Iterable[str] = DEFAULT_SKIP_MAGIC
    process_num: int = DEFAULT_PROCESS_NUM
    keep_extracted_chunks: bool = False
    extract_suffix: str = "_extract"
    handlers: Handlers = BUILTIN_HANDLERS

    def get_extract_dir_for(self, path: Path) -> Path:
        """Extraction dir under root with the name of path."""
        try:
            relative_path = path.relative_to(self.extract_root)
        except ValueError:
            # path is not inside root, i.e. it is an input file
            relative_path = Path(path.name)
        extract_name = path.name + self.extract_suffix
        extract_dir = self.extract_root / relative_path.with_name(extract_name)
        return extract_dir.expanduser().resolve()


@attr.define(frozen=True)
class Task:
    """A generic task working on a resource"""

    path: Path
    depth: int
    chunk_id: str
    # FIXME: chunk_id should be parent id?

    def extract(self, config: ExtractionConfig) -> "TaskResult":
        raise NotImplementedError


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
        reports = itertools.chain.from_iterable(r.reports for r in self.results)
        interesting_reports = (
            r for r in reports if isinstance(r, (ErrorReport, ChunkReport))
        )
        errors = []
        for report in interesting_reports:
            if isinstance(report, ErrorReport):
                errors.append(report)
            else:
                errors.extend(
                    r for r in report.extraction_reports if isinstance(r, ErrorReport)
                )
        return errors

    def register(self, result: TaskResult):
        self.results.append(result)

    def to_json(self, indent="  "):
        return json.dumps(self.results, cls=_JSONEncoder, indent=indent)


class _JSONEncoder(json.JSONEncoder):
    def default(self, obj):
        if attr.has(type(obj)):
            extend_attr_output = True
            attr_output = attr.asdict(obj, recurse=not extend_attr_output)
            attr_output["__typename__"] = obj.__class__.__name__
            return attr_output

        if isinstance(obj, Enum):
            return obj.name

        if isinstance(obj, Path):
            return str(obj)

        if isinstance(obj, bytes):
            try:
                return obj.decode()
            except UnicodeDecodeError:
                return str(obj)

        logger.error(f"JSONEncoder met a non-JSON encodable value: {obj}")
        # the usual fail path of custom JSONEncoders is to call the parent and let it fail
        #     return json.JSONEncoder.default(self, obj)
        # instead of failing, just return something usable
        return f"Non-JSON encodable value: {obj}"
