import shutil
from pathlib import Path
from typing import List, Optional

from structlog import get_logger

from .file_utils import valid_path
from .pool import make_pool
from .report import (
    CanNotCreateExtractDirectoryReport,
    ExtractDirectoryExistsReport,
    Report,
    UnknownError,
)
from .signals import terminate_gracefully
from .tasks import ClassifierTask, ExtractionConfig, ProcessResult, Task, TaskResult

logger = get_logger()


@terminate_gracefully
def process_file(
    config: ExtractionConfig, input_path: Path, report_file: Optional[Path] = None
) -> ProcessResult:
    task = ClassifierTask(path=input_path, depth=0)

    if not input_path.is_file():
        raise ValueError("input_path is not a file", input_path)

    errors = prepare_extract_dir(config, input_path)
    if not prepare_report_file(config, report_file):
        logger.error(
            "File not processed, as report could not be written", file=input_path
        )
        return ProcessResult()

    if errors:
        process_result = ProcessResult([TaskResult(task, errors)])
    else:
        process_result = _process_task(config, task)

    if report_file:
        write_json_report(report_file, process_result)

    extract_dir = config.get_extract_dir_for(input_path)
    try:
        extract_dir.mkdir(parents=True, exist_ok=True)
    except OSError:
        logger.error("Can not create extraction directory", path=str(extract_dir))
        report = CanNotCreateExtractDirectoryReport(path=extract_dir)
        errors.append(report)

    return process_result


def _process_task(config: ExtractionConfig, task: Task) -> ProcessResult:
    processor = Processor(config)
    aggregated_result = ProcessResult()

    def process_result(pool, result):
        for new_task in result.subtasks:
            pool.submit(new_task)
        aggregated_result.register(result)

    pool = make_pool(
        process_num=config.process_num,
        handler=processor.process_task,
        result_callback=process_result,
    )

    with pool:
        pool.submit(task)
        pool.process_until_done()

    return aggregated_result


def prepare_extract_dir(config: ExtractionConfig, input_file: Path) -> List[Report]:
    errors = []

    extract_dir = config.get_extract_dir_for(input_file)
    if extract_dir.exists():
        if config.force_extract:
            logger.info("Removing extract dir", path=extract_dir)
            shutil.rmtree(extract_dir)
        else:
            logger.error("Extraction directory already exist", path=str(extract_dir))
            report = ExtractDirectoryExistsReport(path=extract_dir)
            errors.append(report)

    return errors


def prepare_report_file(config: ExtractionConfig, report_file: Optional[Path]) -> bool:
    """An in advance preparation to prevent report writing failing after an expensive extraction.

    Returns True if there is no foreseen problem,
            False if report writing is known in advance to fail.
    """
    if not report_file:
        # we will not write report at all
        return True

    if report_file.exists():
        if config.force_extract:
            logger.warning("Removing existing report file", path=report_file)
            try:
                report_file.unlink()
            except OSError as e:
                logger.error(
                    "Can not remove existing report file",
                    path=report_file,
                    msg=str(e),
                )
                return False
        else:
            logger.error(
                "Report file exists and --force not specified", path=report_file
            )
            return False

    # check that the report directory can be written to
    try:
        report_file.write_text("")
        report_file.unlink()
    except OSError as e:
        logger.error("Can not create report file", path=report_file, msg=str(e))
        return False

    return True


def write_json_report(report_file: Path, process_result: ProcessResult):
    try:
        report_file.write_text(process_result.to_json())
    except OSError as e:
        logger.error("Can not write JSON report", path=report_file, msg=str(e))
    except Exception:
        logger.exception("Can not write JSON report", path=report_file)
    else:
        logger.info("JSON report written", path=report_file)


class Processor:
    def __init__(self, config: ExtractionConfig):
        self._config = config

    def process_task(self, task: Task) -> TaskResult:
        result = TaskResult(task)
        try:
            self._process_task(result, task)
        except Exception as exc:
            self._process_error(result, exc)
        return result

    def _process_error(self, result: TaskResult, exc: Exception):
        error_report = UnknownError(exception=exc)
        result.add_report(error_report)
        logger.exception("Unknown error happened", exc_info=exc)

    def _process_task(self, result: TaskResult, task: Task):
        log = logger.bind(path=task.path)
        log.info("Processing", task=task)

        if task.depth >= self._config.max_depth:
            # TODO: Use the reporting feature to warn the user (ONLY ONCE) at the end of execution, that this limit was reached.
            log.debug("Reached maximum depth, stop further processing")
            return

        if not valid_path(task.path):
            log.warn("Path contains invalid characters, it won't be processed")
            return

        return task.run(self._config, result)
