import stat
import struct

import pytest

from unblob.file_utils import File, InvalidInputFormat, StructParser
from unblob.handlers.filesystem.ufs import UFS_C_DEFINITION, UFS2Parser

FSIZE = 512
IBLKNO = 4
INODES_PER_GROUP = 16
FRAGS_PER_GROUP = 8

# inode number whose cylinder group does not exist (16 // 16 == 1, but fs_ncg == 1)
OUT_OF_RANGE_INO = INODES_PER_GROUP
# byte offset read_inode() computes for OUT_OF_RANGE_INO, past the inode table
FAKE_INODE_OFFSET = (FRAGS_PER_GROUP + IBLKNO) * FSIZE


def _build_image(*, inodes_per_group: int = INODES_PER_GROUP) -> bytes:
    cs = StructParser(UFS_C_DEFINITION).cparser_le
    superblock = cs.ufs_superblock_t(bytes(bytearray(cs.ufs_superblock_t.size)))
    superblock.fs_fsize = FSIZE
    superblock.fs_bsize = FSIZE
    superblock.fs_frag = 1
    superblock.fs_ncg = 1
    superblock.fs_inodes_per_group = inodes_per_group
    superblock.fs_iblkno = IBLKNO
    superblock.fs_frags_per_group = FRAGS_PER_GROUP

    image = bytearray(superblock.dumps())
    image += b"\x00" * (FAKE_INODE_OFFSET + 256 - len(image))

    # plant a structurally valid regular-file inode where an out-of-range inode
    # number resolves, so an unguarded read would happily parse it
    fake_inode = bytearray(256)
    struct.pack_into("<H", fake_inode, 0, stat.S_IFREG | 0o644)
    struct.pack_into("<Q", fake_inode, 16, 32)  # size
    image[FAKE_INODE_OFFSET : FAKE_INODE_OFFSET + 256] = fake_inode
    return bytes(image)


def test_read_inode_rejects_out_of_range_number():
    parser = UFS2Parser(File.from_bytes(_build_image()), 0)

    # in-range inode is still readable
    assert parser.read_inode(2) is not None

    with pytest.raises(InvalidInputFormat, match="Inode number out of range"):
        parser.read_inode(OUT_OF_RANGE_INO)


def test_read_inode_rejects_zero_inodes_per_group():
    parser = UFS2Parser(File.from_bytes(_build_image(inodes_per_group=0)), 0)

    with pytest.raises(InvalidInputFormat, match="Inode number out of range"):
        parser.read_inode(2)
