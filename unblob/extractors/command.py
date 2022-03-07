import shlex
import subprocess
from pathlib import Path
from typing import List

from structlog import get_logger

from unblob.models import Extractor, TaskResult
from unblob.report import ExtractCommandFailedReport, ExtractorDependencyNotFoundReport

logger = get_logger()


class Command(Extractor):
    def __init__(self, executable, *args):
        self._executable = executable
        self._command_template = [executable, *args]

    def extract(self, inpath: Path, outdir: Path, task_result: TaskResult):
        cmd = self._make_extract_command(inpath, outdir)
        command = shlex.join(cmd)
        logger.debug("Running extract command", command=command)
        try:
            res = subprocess.run(
                cmd,
                encoding="utf-8",
                errors="surrogateescape",
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )
            if res.returncode != 0:
                stdout = res.stdout.encode("utf-8", errors="surrogateescape")
                stderr = res.stderr.encode("utf-8", errors="surrogateescape")

                error_report = ExtractCommandFailedReport(
                    command=command,
                    stdout=stdout,
                    stderr=stderr,
                    exit_code=res.returncode,
                )

                task_result.add_report(error_report)
                logger.error("Extract command failed", **error_report.asdict())
        except FileNotFoundError:
            error_report = ExtractorDependencyNotFoundReport(
                dependencies=self.get_dependencies()
            )
            task_result.add_report(error_report)
            logger.error(
                "Can't run extract command. Is the extractor installed?",
                **error_report.asdict(),
            )

    def _make_extract_command(self, inpath: Path, outdir: Path):
        replacements = dict(inpath=inpath, outdir=outdir, infile=inpath.stem)

        args = []
        for t in self._command_template:
            try:
                args.append(t.format(**replacements))
            except KeyError as k:
                raise InvalidCommandTemplate("Invalid template placeholder", t) from k
            except ValueError as v:
                raise InvalidCommandTemplate("The template is malformed", t) from v

        return args

    def get_dependencies(self) -> List[str]:
        return [self._executable]


class InvalidCommandTemplate(ValueError):
    pass
