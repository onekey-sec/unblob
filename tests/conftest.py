from unblob.extractors import Command
from unblob.models import Handler, HexString
from unblob.testing import configure_logging  # noqa: F401 (module imported but unused)


class TestHandler(Handler):
    NAME = "test_handler"
    PATTERNS = [HexString("21 3C")]
    EXTRACTOR = Command("testcommand", "for", "test", "handler")

    def calculate_chunk(self, *args, **kwargs):
        pass
