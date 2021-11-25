from typing import Dict, List, Type

from ..models import Handler
from .archive import ar, arc, cab, cpio, tar
from .filesystem import cramfs, squashfs


def _make_handler_map(*handlers: Type[Handler]) -> Dict[str, Handler]:
    return {h.NAME: h() for h in handlers}


_ALL_MODULES_BY_PRIORITY: List[Dict[str, Handler]] = [
    _make_handler_map(
        cramfs.CramFSHandler,
        squashfs.SquashFSv3Handler,
        squashfs.SquashFSv4Handler,
    ),
    _make_handler_map(
        ar.ARHandler,
        arc.ARCHandler,
        cab.CABHandler,
        tar.TarHandler,
        cpio.PortableASCIIHandler,
        cpio.PortableASCIIWithCRCHandler,
        cpio.PortableOldASCIIHandler,
        cpio.BinaryHandler,
    ),
]
