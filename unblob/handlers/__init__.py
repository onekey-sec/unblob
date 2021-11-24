from typing import Dict, List

from ..models import Handler
from .archive import ar, cab, cpio, tar
from .filesystem.squashfs import squashfs_v3, squashfs_v4


def _make_handler_map(*handlers: Handler) -> Dict[str, Handler]:
    return {h.NAME: h for h in handlers}


_ALL_MODULES_BY_PRIORITY: List[Dict[str, Handler]] = [
    _make_handler_map(squashfs_v3, squashfs_v4, cramfs),
    _make_handler_map(
        ar,
        cab,
        tar,
        cpio.PortableASCIIHandler,
        cpio.PortableASCIIWithCRCHandler,
        cpio.PortableOldASCIIHandler,
        cpio.BinaryHandler,
    ),
]
