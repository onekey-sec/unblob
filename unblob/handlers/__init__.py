from typing import Dict, List, Type

from ..models import Handler
from .archive import ar, cab, cpio, rar, sevenzip, tar, zip
from .filesystem import cramfs, squashfs, ubi


def _make_handler_map(*handlers: Type[Handler]) -> Dict[str, Handler]:
    return {h.NAME: h() for h in handlers}


_ALL_MODULES_BY_PRIORITY: List[Dict[str, Handler]] = [
    _make_handler_map(
        cramfs.CramFSHandler,
        squashfs.SquashFSv3Handler,
        squashfs.SquashFSv4Handler,
        ubi.UBIHandler,
        ubi.UBIFSHandler,
    ),
    _make_handler_map(
        ar.ARHandler,
        cab.CABHandler,
        tar.TarHandler,
        cpio.PortableASCIIHandler,
        cpio.PortableASCIIWithCRCHandler,
        cpio.PortableOldASCIIHandler,
        cpio.BinaryHandler,
        sevenzip.SevenZipHandler,
        rar.RarHandler,
        zip.ZIPHandler,
    ),
]
