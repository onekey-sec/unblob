from unblob.extractors import Command
from unblob.models import Handler
from unblob.testing import configure_logging  # noqa: F401 (module imported but unused)


class TestHandler(Handler):
    NAME = "test_handler"
    YARA_RULE = r"""
        strings:
            $handler1_magic = { 21 3C }
        condition:
            $handler1_magic
    """
    EXTRACTOR = Command("testcommand", "for", "test", "handler")

    def calculate_chunk(self, *args, **kwargs):
        pass
