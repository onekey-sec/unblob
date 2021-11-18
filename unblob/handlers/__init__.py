from typing import Dict, List

from ..models import Handler
from .archive import cab, cpio, sevenzip, tar, zip


def _make_handler_map(*handlers: Handler) -> Dict[str, Handler]:
    return {h.NAME: h for h in handlers}


_ALL_MODULES_BY_PRIORITY: List[Dict[str, Handler]] = [
    _make_handler_map(
        cab,
        sevenzip,
        zip,
        tar,
        cpio.PortableASCIIHandler,
        cpio.PortableASCIIWithCRCHandler,
        cpio.PortableOldASCIIHandler,
        cpio.BinaryHandler,
    ),
]
