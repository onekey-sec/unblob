from typing import List, Tuple, Type

from ..models import Handler
from .archive import ar, arc, arj, cab, cpio, dmg, rar, sevenzip, stuffit, tar, zip
from .compression import bzip2, lz4, lzh, lzip, lzma, lzo, xz
from .filesystem import cramfs, extfs, fat, iso9660, jffs2, ntfs, squashfs, ubi

ALL_HANDLERS_BY_PRIORITY: List[Tuple[Type[Handler], ...]] = [
    (
        cramfs.CramFSHandler,
        extfs.EXTHandler,
        fat.FATHandler,
        jffs2.JFFS2NewHandler,
        jffs2.JFFS2OldHandler,
        ntfs.NTFSHandler,
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
        stuffit.StuffItSITHandler,
        stuffit.StuffIt5Handler,
    ),
    (
        bzip2.BZip2Handler,
        lzh.LZHHandler,
        lzip.LZipHandler,
        lzo.LZOHandler,
        lzma.LZMAHandler,
        lz4.LegacyFrameHandler,
        lz4.SkippableFrameHandler,
        lz4.DefaultFrameHandler,
        xz.XZHandler,
    ),
]

ALL_HANDLERS = [
    handler for handlers in ALL_HANDLERS_BY_PRIORITY for handler in handlers
]
