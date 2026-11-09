import stat
import struct

import pytest

from unblob.file_utils import File, InvalidInputFormat, StructParser
from unblob.handlers.filesystem.ufs import (
    UFS_C_DEFINITION,
    UFS2Parser,
    UFSExtractor,
)
from unblob.report import ExtractionProblem

FSIZE = 512
IBLKNO = 4
DBLKNO = 6
INODES_PER_GROUP = 16
FRAGS_PER_GROUP = 8
TOTAL_FRAGMENTS = FRAGS_PER_GROUP  # fs_ncg == 1

# inode #2 location used by read_inode(): cylinder group 0 inode block + index 2
ROOT_INODE_OFFSET = IBLKNO * FSIZE + 2 * 256
# fs_dblkno places the first data fragment at frag 6; frag 6 holds file content
DATA_FRAGMENT = DBLKNO
DATA_MARKER = b"REAL_FILE_DATA__"

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


def _build_block_pointer_image(direct_block: int) -> bytes:
    cs = StructParser(UFS_C_DEFINITION).cparser_le
    superblock = cs.ufs_superblock_t(bytes(bytearray(cs.ufs_superblock_t.size)))
    superblock.fs_fsize = FSIZE
    superblock.fs_bsize = FSIZE
    superblock.fs_frag = 1
    superblock.fs_ncg = 1
    superblock.fs_inodes_per_group = INODES_PER_GROUP
    superblock.fs_iblkno = IBLKNO
    superblock.fs_dblkno = DBLKNO
    superblock.fs_frags_per_group = FRAGS_PER_GROUP
    superblock.fs_u11.fs_u2.fs_size_64 = TOTAL_FRAGMENTS

    image = bytearray(TOTAL_FRAGMENTS * FSIZE)
    image[: cs.ufs_superblock_t.size] = superblock.dumps()
    # frag 1 sits in the metadata area; mark it so an over-read is observable
    image[FSIZE : 2 * FSIZE] = b"METADATA".ljust(FSIZE, b"\xaa")
    # frag 6 (fs_dblkno) is the first valid data fragment
    image[DATA_FRAGMENT * FSIZE : (DATA_FRAGMENT + 1) * FSIZE] = DATA_MARKER.ljust(
        FSIZE, b"\x00"
    )

    inode = bytearray(256)
    struct.pack_into("<H", inode, 0, stat.S_IFREG | 0o644)
    struct.pack_into("<Q", inode, 16, len(DATA_MARKER))  # size
    struct.pack_into("<Q", inode, 112, direct_block)  # direct_blocks[0]
    image[ROOT_INODE_OFFSET : ROOT_INODE_OFFSET + 256] = inode
    return bytes(image)


def test_read_file_content_rejects_block_pointer_in_metadata():
    # frag 1 is before fs_dblkno, so it points at filesystem metadata
    parser = UFS2Parser(File.from_bytes(_build_block_pointer_image(1)), 0)
    with pytest.raises(InvalidInputFormat, match="Block pointer outside the data area"):
        b"".join(parser.read_file_content(parser.read_inode(2)))


def test_read_file_content_rejects_block_pointer_past_filesystem():
    parser = UFS2Parser(File.from_bytes(_build_block_pointer_image(999)), 0)
    with pytest.raises(InvalidInputFormat, match="Block pointer outside the data area"):
        b"".join(parser.read_file_content(parser.read_inode(2)))


def test_read_file_content_reads_valid_data_block():
    parser = UFS2Parser(File.from_bytes(_build_block_pointer_image(DATA_FRAGMENT)), 0)
    assert b"".join(parser.read_file_content(parser.read_inode(2))) == DATA_MARKER


ROOT_INO = 2
DIR_INO = 3
FILE_INO = 4
FILE_DATA = b"apple"
# data fragments start right after the 16 inode table entries
TREE_DBLKNO = IBLKNO + INODES_PER_GROUP * 256 // FSIZE


def _dir_block(entries: list[tuple[str, int]]) -> bytes:
    block = b""
    for i, (name, ino) in enumerate(entries):
        reclen = (8 + len(name) + 3) & ~3
        if i == len(entries) - 1:
            reclen = FSIZE - len(block)
        # struct ufs_dirent: d_ino, d_reclen, d_type, d_namlen, d_name
        entry = struct.pack("<IHBB", ino, reclen, 0, len(name)) + name.encode()
        block += entry.ljust(reclen, b"\x00")
    return block


def _inode(mode: int, size: int, block: int) -> bytes:
    inode = bytearray(256)
    struct.pack_into("<H", inode, 0, mode)
    struct.pack_into("<Q", inode, 16, size)
    struct.pack_into("<Q", inode, 112, block)  # direct_blocks[0]
    return bytes(inode)


def _build_tree_image(dirs: dict[int, list[tuple[str, int]]]) -> bytes:
    """Build a UFS2 image with the given directories and one regular file."""
    total_fragments = TREE_DBLKNO + len(dirs) + 1
    cs = StructParser(UFS_C_DEFINITION).cparser_le
    superblock = cs.ufs_superblock_t(bytes(bytearray(cs.ufs_superblock_t.size)))
    superblock.fs_fsize = FSIZE
    superblock.fs_bsize = FSIZE
    superblock.fs_frag = 1
    superblock.fs_ncg = 1
    superblock.fs_inodes_per_group = INODES_PER_GROUP
    superblock.fs_iblkno = IBLKNO
    superblock.fs_dblkno = TREE_DBLKNO
    superblock.fs_frags_per_group = total_fragments
    superblock.fs_u11.fs_u2.fs_size_64 = total_fragments

    image = bytearray(total_fragments * FSIZE)
    image[: cs.ufs_superblock_t.size] = superblock.dumps()

    inodes = [
        (ino, stat.S_IFDIR | 0o755, _dir_block([(".", ino), ("..", ino), *entries]))
        for ino, entries in dirs.items()
    ]
    inodes.append((FILE_INO, stat.S_IFREG | 0o644, FILE_DATA))
    for block, (ino, mode, data) in enumerate(inodes, start=TREE_DBLKNO):
        image[block * FSIZE : block * FSIZE + len(data)] = data
        offset = IBLKNO * FSIZE + ino * 256
        image[offset : offset + 256] = _inode(mode, len(data), block)
    return bytes(image)


@pytest.mark.parametrize(
    "dirs, skipped_ino, skipped_path",
    [
        pytest.param(
            {
                ROOT_INO: [("a", DIR_INO), ("b", DIR_INO)],
                DIR_INO: [("f", FILE_INO)],
            },
            DIR_INO,
            "/b",
            id="shared-directory",
        ),
        pytest.param(
            {
                ROOT_INO: [("a", DIR_INO)],
                DIR_INO: [("f", FILE_INO), ("up", ROOT_INO)],
            },
            ROOT_INO,
            "/a/up",
            id="loop-to-ancestor",
        ),
    ],
)
def test_walk_extract_skips_directory_already_extracted(
    tmp_path, dirs, skipped_ino, skipped_path
):
    image_path = tmp_path / "ufs2.img"
    image_path.write_bytes(_build_tree_image(dirs))
    outdir = tmp_path / "out"

    result = UFSExtractor(UFS2Parser, 0).extract(image_path, outdir)

    assert sorted(p.relative_to(outdir).as_posix() for p in outdir.rglob("*")) == [
        "a",
        "a/f",
    ]
    assert (outdir / "a" / "f").read_bytes() == FILE_DATA
    assert result.reports == [
        ExtractionProblem(
            problem=f"Directory inode {skipped_ino} is already extracted.",
            resolution="Skipped.",
            path=skipped_path,
        )
    ]
