from typing import List, Tuple, Type

from ..models import Handler
from .archive import ar, arc, arj, cab, cpio, dmg, rar, sevenzip, tar, zip
from .compression import bzip2, lz4, lzip, lzma, lzo, xz
from .filesystem import cramfs, fat, iso9660, squashfs, ubi

ALL_HANDLERS_BY_PRIORITY: List[Tuple[Type[Handler], ...]] = [
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
    (
        bzip2.BZip2Handler,
        lzip.LZipHandler,
        lzo.LZOHandler,
        lzma.LZMAHandler,
        lz4.LegacyFrameHandler,
        lz4.SkippableFrameHandler,
        lz4.DefaultFrameHandler,
        xz.XZHandler,
    ),
]
