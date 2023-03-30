import shlex
import subprocess
from pathlib import Path
from typing import TYPE_CHECKING, List, Optional, Union

from structlog import get_logger

from unblob.models import ExtractError, Extractor
from unblob.report import ExtractCommandFailedReport, ExtractorDependencyNotFoundReport

if TYPE_CHECKING:
    import io

logger = get_logger()


class Command(Extractor):
    def __init__(self, executable, *args, stdout: Optional[str] = None):
        """Extract using external extractor and template parameters.

        Has extra support for extractors (notably 7z), which can not be directed to output to a file, but can extract to stdout:
        When the parameter `stdout` is set, the command's stdout will be redirected to `outdir / stdout`.
        """
        self._executable = executable
        self._command_template = [executable, *args]
        self._stdout = stdout

    def extract(self, inpath: Path, outdir: Path):
        cmd = self._make_extract_command(inpath, outdir)
        command = shlex.join(cmd)
        logger.debug("Running extract command", command=command)
        stdout_file: Union[int, "io.FileIO"] = subprocess.PIPE

        def no_op():
            pass

        cleanup = no_op

        try:
            if self._stdout:
                stdout_file = (outdir / self._stdout).open(mode="wb", buffering=0)
                cleanup = stdout_file.close

            res = subprocess.run(
                cmd,
                stdout=stdout_file,
                stderr=subprocess.PIPE,
            )
            if res.returncode != 0:
                error_report = ExtractCommandFailedReport(
                    command=command,
                    stdout=res.stdout,
                    stderr=res.stderr,
                    exit_code=res.returncode,
                )

                logger.error("Extract command failed", **error_report.asdict())
                raise ExtractError(error_report)  # noqa: TRY301
        except FileNotFoundError:
            error_report = ExtractorDependencyNotFoundReport(
                dependencies=self.get_dependencies()
            )
            logger.error(
                "Can't run extract command. Is the extractor installed?",
                **error_report.asdict(),
            )
            raise ExtractError(error_report) from None
        finally:
            cleanup()

    def _make_extract_command(self, inpath: Path, outdir: Path):
        replacements = dict(inpath=inpath, outdir=outdir)

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
