from pathlib import Path

from structlog import get_logger

from unblob.models import (
    DirectoryHandler,
    Glob,
    HandlerDoc,
    HandlerType,
    MultiFile,
    Reference,
)

logger = get_logger()

_MAGIC_PREFIX = b"dyld_v1 "


class MultifileDyldCacheHandler(DirectoryHandler):
    NAME = "multifile_dyld_cache"

    EXTRACTOR = None
    PATTERN = Glob("dyld_shared_cache_*")

    DOC = HandlerDoc(
        name="dyld Shared Cache",
        description="The dyld shared cache is a pre-linked collection of system dynamic libraries used by macOS and iOS to accelerate application launch. Modern caches are split across multiple files with suffixes such as .01, .symbols, .atlas, .dylddata, and .dyldlinkedit.",
        handler_type=HandlerType.ARCHIVE,
        vendor="Apple",
        references=[
            Reference(
                title="dyld - Apple open-source dynamic linker",
                url="https://github.com/apple-oss-distributions/dyld",
            ),
        ],
        limitations=[],
    )

    def calculate_multifile(self, file: Path) -> MultiFile | None:
        if file.suffix:
            return None

        try:
            with file.open("rb") as f:
                if not f.read(len(_MAGIC_PREFIX)).startswith(_MAGIC_PREFIX):
                    return None
        except (IsADirectoryError, PermissionError, FileNotFoundError):
            return None

        siblings = sorted(
            [
                p
                for p in file.parent.iterdir()
                if p.name.startswith(file.stem)
                and p.name != file.name
                and ":" not in p.name
            ],
            key=lambda p: (len(p.name), p.name),
        )

        if not siblings:
            return None

        logger.info(
            "creating unified dyld cache view", main=file.name, parts=len(siblings) + 1
        )

        return MultiFile(name=f"{file.stem}.unified", paths=[file, *siblings])
