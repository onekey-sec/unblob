from typing import Dict, List

from ..models import Handler
from .archive import cab, cpio, tar, zip
from .filesystem import squashfs


def _make_handler_map(*handlers: Handler) -> Dict[str, Handler]:
    return {h.NAME: h for h in handlers}


_ALL_MODULES_BY_PRIORITY: List[Dict[str, Handler]] = [
    _make_handler_map(
        cab,
        zip,
        squashfs,
        tar,
        cpio.PortableASCIIHandler,
        cpio.PortableASCIIWithCRCHandler,
        cpio.PortableOldASCIIHandler,
        cpio.BinaryHandler,
    ),
]
