from pathlib import Path

from unblob.file_utils import File
from unblob.finder import search_chunks
from unblob.handlers.filesystem.extfs import ExtFSExtractor, EXTHandler


def _request_token(argv):
    """Return the libss request string passed to ``debugfs -R``."""
    return argv[argv.index("-R") + 1]


def test_extfs_handler_uses_escaping_extractor():
    assert isinstance(EXTHandler.EXTRACTOR, ExtFSExtractor)


def test_extfs_extractor_escapes_double_quote_in_outdir():
    # An output directory whose name contains a literal " (legal in filenames
    # and reachable through recursive extraction) must not break the debugfs
    # request. libss requires a literal " inside a quoted token to be doubled.
    extractor = ExtFSExtractor("debugfs", "-R", 'rdump / "{outdir}"', "{inpath}")
    argv = extractor._make_extract_command(  # noqa: SLF001
        Path("/in/0-1024.extfs"), Path('/out/evil"dir/x_extract')
    )
    request = _request_token(argv)
    # Stays balanced (even number of quotes) -> libss accepts it.
    assert request.count('"') % 2 == 0
    # The path's " was escaped to "" so it round-trips to the intended path.
    assert 'evil""dir' in request
    # The image path is a plain argv element, not part of the -R request.
    assert "/in/0-1024.extfs" in argv
    assert "/in/0-1024.extfs" not in request


def test_extfs_extractor_leaves_plain_outdir_unchanged():
    extractor = ExtFSExtractor("debugfs", "-R", 'rdump / "{outdir}"', "{inpath}")
    argv = extractor._make_extract_command(  # noqa: SLF001
        Path("/in/0-1024.extfs"), Path("/out/plain/x_extract")
    )
    assert _request_token(argv) == 'rdump / "/out/plain/x_extract"'


def test_reduced_oss_fuzz_extfs_input_is_rejected_without_exception_reports(
    task_result,
):
    testcase_path = (
        Path(__file__).parents[2]
        / "integration"
        / "filesystem"
        / "extfs"
        / "__input__"
        / "clusterfuzz-testcase-minimized-search_chunks_fuzzer-5641994765664256"
    )
    data = testcase_path.read_bytes()

    with File.from_bytes(data) as file:
        chunks = search_chunks(file, len(data), (EXTHandler,), task_result)

    assert chunks == []
    assert task_result.reports == []
