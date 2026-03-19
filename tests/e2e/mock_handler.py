import os
import re
import signal
import time
from pathlib import Path

from unblob.models import Extractor, Handler, Regex, ValidChunk
from unblob.plugins import hookimpl

BLOCKING_MAGIC = b"UNBLOB_E2E_BLOCKING"
TERMINATING_MAGIC = b"UNBLOB_E2E_TERMINATING"
READY_FLAG_NAME = "e2e_ready"


class BlockingExtractor(Extractor):
    def get_dependencies(self):
        return []

    def extract(self, inpath: Path, outdir: Path):  # noqa: ARG002
        # destination has to be allowed in the sandbox
        (outdir / READY_FLAG_NAME).touch()
        time.sleep(3600)


class BlockingHandler(Handler):
    NAME = "e2e_blocking"
    PATTERNS = [Regex(re.escape(BLOCKING_MAGIC.decode()))]
    EXTRACTOR = BlockingExtractor()
    DOC = None

    def calculate_chunk(self, file, start_offset: int):  # noqa: ARG002
        return ValidChunk(
            start_offset=start_offset,
            end_offset=start_offset + len(BLOCKING_MAGIC),
        )


class TerminatingExtractor(Extractor):
    def get_dependencies(self):
        return []

    def extract(self, inpath: Path, outdir: Path):  # noqa: ARG002
        # destination has to be allowed in the sandbox
        (outdir / READY_FLAG_NAME).touch()
        os.kill(os.getpid(), signal.SIGTERM)


class TerminatingHandler(Handler):
    NAME = "e2e_terminating"
    PATTERNS = [Regex(re.escape(TERMINATING_MAGIC.decode()))]
    EXTRACTOR = TerminatingExtractor()
    DOC = None

    def calculate_chunk(self, file, start_offset: int):  # noqa: ARG002
        return ValidChunk(
            start_offset=start_offset,
            end_offset=start_offset + len(TERMINATING_MAGIC),
        )


@hookimpl
def unblob_register_handlers():
    return [BlockingHandler, TerminatingHandler]
