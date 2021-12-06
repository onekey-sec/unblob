from typing import Tuple, Type

from ..models import Handler
from .archive import ar, arc, arj, cab, cpio, dmg, rar, sevenzip, tar, zip
from .filesystem import cramfs, fat, iso9660, squashfs, ubi

_ALL_MODULES_BY_PRIORITY: Tuple[Tuple[Type[Handler], ...], ...] = (
    (
        cramfs.CramFSHandler,
        fat.FATHandler,
        squashfs.SquashFSv3Handler,
        squashfs.SquashFSv4Handler,
        ubi.UBIHandler,
        ubi.UBIFSHandler,
    ),
    (
        ar.ARHandler,
        arc.ARCHandler,
        arj.ARJHandler,
        cab.CABHandler,
        tar.TarHandler,
        cpio.PortableASCIIHandler,
        cpio.PortableASCIIWithCRCHandler,
        cpio.PortableOldASCIIHandler,
        cpio.BinaryHandler,
        sevenzip.SevenZipHandler,
        rar.RarHandler,
        zip.ZIPHandler,
        dmg.DMGHandler,
        iso9660.ISO9660FSHandler,
    ),
)
