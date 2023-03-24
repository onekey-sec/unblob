import io
import itertools
import os
from enum import IntEnum
from pathlib import Path
from typing import Iterable, List, Optional, Tuple

import attr
from dissect.cstruct import Instance
from structlog import get_logger
from treelib import Tree
from treelib.exceptions import DuplicatedNodeIdError, NodeIDAbsentError

from unblob.extractor import is_safe_path
from unblob.file_utils import Endian, InvalidInputFormat, StructParser, snull

from ....models import File

C_DEFINITIONS = """
    struct yaffs1_obj_hdr {
        uint32 type;                   /* enum yaffs_obj_type  */
        uint32 parent_obj_id;
        uint16 sum_no_longer_used;
        char name[258];
        uint32 st_mode; // protection
        uint32 st_uid; // user ID of owner
        uint32 st_gid; // group ID of owner
        uint32 st_atime; // time of last access
        uint32 st_mtime; // time of last modification
        uint32 st_ctime; // time of last change
        uint32 file_size; // File size applies to files only
        uint32 equivalent_object_id; // Equivalent object id applies to hard links only.
        char alias[160]; // alias only applies to symlinks
    } yaffs1_obj_hdr_t;

    struct yaffs1_packed_tags {
        uint32 chunk_id:20;
        uint32 serial:2;
        uint32 byte_count:10;
        uint32 object_id:18;
        uint32 ecc:12;
        uint32 unused:2;
    } yaffs1_packed_tags_t;

    typedef struct yaffs_spare
    {
        uint8 tag_b0;
        uint8 tag_b1;
        uint8 tag_b2;
        uint8 tag_b3;
        uint8 page_status; 	// set to 0 to delete the chunk
        uint8 block_status;
        uint8 tag_b4;
        uint8 tag_b5;
        uint8 ecc_0;
        uint8 ecc_1;
        uint8 ecc_2;
        uint8 tag_b6;
        uint8 tag_b7;
        uint8 ecc_3;
        uint8 ecc_4;
        uint8 ecc_5;
    } yaffs_spare_t;

    struct yaffs_file_var {
        uint32 file_size;
        uint32 stored_size;
        uint32 shrink_size;
        int top_level;
    };

    typedef struct yaffs2_obj_hdr {
        uint32 type;                   /* enum yaffs_obj_type  */
        /* Apply to everything  */
        uint32 parent_obj_id;
        uint16 sum_no_longer_used;	    /* checksum of name. No longer used */
        char name[256];
        uint16 chksum;
        /* The following apply to all object types except for hard links */
        uint32 yst_mode;		        /* protection */
        uint32 yst_uid;
        uint32 yst_gid;
        uint32 yst_atime;
        uint32 yst_mtime;
        uint32 yst_ctime;
        uint32 file_size_low;          /* File size  applies to files only */
        int equiv_id;               /* Equivalent object id applies to hard links only. */
        char alias[160];    /* Alias is for symlinks only. */
        uint32 yst_rdev;	            /* stuff for block and char devices (major/min) */
        uint32 win_ctime[2];
        uint32 win_atime[2];
        uint32 win_mtime[2];
        uint32 inband_shadowed_obj_id;
        uint32 inband_is_shrink;
        uint32 file_size_high;
        uint32 reserved[1];
        int shadows_obj;	    /* This object header shadows the specified object if > 0 */
        /* is_shrink applies to object headers written when we make a hole. */
        uint32 is_shrink;
        yaffs_file_var filehead;
    } yaffs2_obj_hdr_t;

    typedef struct yaffs2_packed_tags {
        uint32 seq_number;
        uint32 object_id;
        uint32 chunk_id;
        uint32 byte_count;
    }  yaffs2_packed_tags_t;
"""


class YAFFS_OBJECT_TYPE(IntEnum):
    UNKNOWN = 0
    FILE = 1
    SYMLINK = 2
    DIRECTORY = 3
    HARDLINK = 4
    SPECIAL = 5


@attr.define
class YAFFSChunk:
    id: int
    byte_count: int
    object_id: int


@attr.define
class YAFFS1Chunk(YAFFSChunk):
    serial: int
    ecc: bytes
    page_status: int
    block_status: int


@attr.define
class YAFFS2Chunk(YAFFSChunk):
    seq_number: int


@attr.define
class YAFFSConfig:
    endianness: Endian
    page_size: int
    spare_size: int
    ecc: bool


VALID_PAGE_SIZES = [512, 1024, 2048, 4096, 8192, 16384]
VALID_SPARE_SIZES = [16, 32, 64, 128, 256, 512]
DEFAULT_CONFIG = YAFFSConfig(
    page_size=2048, spare_size=16, endianness=Endian.LITTLE, ecc=False
)

logger = get_logger()


def iterate_over_file(
    file: File, config: YAFFSConfig
) -> Iterable[Tuple[int, bytes, bytes]]:
    start_offset = file.tell()
    page = file.read(config.page_size)
    spare = file.read(config.spare_size)

    while len(page) == config.page_size and len(spare) == config.spare_size:
        yield (start_offset, page, spare)
        page = file.read(config.page_size)
        spare = file.read(config.spare_size)
        start_offset = file.tell()


def decode_file_size(high: int, low: int) -> int:
    """File size can be encoded as 64 bits or 32 bits values.
    If upper 32 bits are set, it's a 64 bits integer value.
    Otherwise it's a 32 bits value. 0xFFFFFFFF means zero.
    """
    if high != 0xFFFFFFFF:
        return (high << 32) | (low & 0xFFFFFFFF)
    elif low != 0xFFFFFFFF:
        return low
    else:
        return 0


def valid_name(name: bytes) -> bool:
    # a valid name is either full of null bytes, or unicode decodable
    try:
        snull(name[:-1]).decode("utf-8")
        return True
    except UnicodeDecodeError:
        return False


def is_valid_header(header: Instance) -> bool:
    if not valid_name(header.name[:-3]):
        return False
    if header.type > 5:
        return False
    if header.sum_no_longer_used != 0xFFFF:
        return False
    return True


@attr.define
class YAFFSEntry:
    type: int
    object_id: int
    parent_obj_id: int
    sum_no_longer_used: int
    name: str
    alias: str
    file_size: int
    start_offset: int
    chunks: List[YAFFSChunk]

    @property
    def chunks(self):
        raise NotImplementedError

    def __lt__(self, other):
        return self.object_id < other.object_id

    def __gt__(self, other):
        return self.object_id > other.object_id

    def __eq__(self, other):
        return self.object_id == other.object_id

    def __str__(self):
        return f"{self.object_id}: {self.name}"


@attr.define
class YAFFS1Entry(YAFFSEntry):
    @property
    def chunks(self) -> Iterable[YAFFS1Chunk]:
        """Return a filtered and ordered list of chunks"""

        # YAFFS1 chunks have a page_status field indicating
        # whether or not the chunk is still active. We therefore
        # filter out chunks that are inactive.

        # YAFFS1 chunks have a serial number that is used to track
        # which chunk takes precedence if two chunks have the same
        # identifier. This is used in scenarios like power loss
        # during a copy operation. Whenever we have two chunks with
        # the same id, we only return the one with the highest serial.

        for _, chunks in itertools.groupby(
            sorted(
                # filter out deleted chunks (page_status=0)
                [chunk for chunk in self.chunks if chunk.page_status != 0x0],
                key=lambda chunk: chunk.id,
            )
        ):
            yield max(chunks, key=lambda chunk: chunk.serial)


@attr.define
class YAFFSFileVar:
    file_size: int
    stored_size: int
    shrink_size: int
    top_level: int


@attr.define(kw_only=True)
class YAFFS2Entry(YAFFSEntry):
    _chksum: int
    yst_mode: int
    yst_uid: int
    yst_gid: int
    yst_atime: int
    yst_mtime: int
    yst_ctime: int
    equiv_id: int
    yst_rdev: int
    win_ctime: List[int]
    win_mtime: List[int]
    inband_shadowed_obj_id: int
    inband_is_shrink: int
    reserved: List[int]
    shadows_obj: int
    is_shrink: int
    filehead: YAFFSFileVar

    @property
    def chunks(self) -> Iterable[YAFFS2Chunk]:
        """Return a filtered and ordered list of chunks"""

        # The Yaffs2 sequence number is not the same as the Yaffs1 serial number!

        # As each block is allocated, the file system's
        # sequence number is incremented and each chunk in the block is marked with that
        # sequence number. The sequence number thus provides a way of organising the log in
        # chronological order.

        # Since we're scanning backwards, the most recently written – and thus current – chunk
        # matching an obj_id:chunk_id pair will be encountered first and all subsequent matching chunks must be obsolete and treated as deleted.

        # note: there is no deletion marker in YAFFS2

        for _, chunks in itertools.groupby(
            sorted(self.chunks, key=lambda chunk: chunk.id)
        ):
            yield max(chunks, key=lambda chunk: chunk.seq_number)


ROOT = YAFFSEntry(
    type=0,
    object_id=-1,
    parent_obj_id=-1,
    sum_no_longer_used=0,
    name=".",
    alias="",
    file_size=0,
    start_offset=0,
    chunks=[],
)


SPARE_START_BIG_ENDIAN_ECC = b"\x00\x00\x10\x00"
SPARE_START_BIG_ENDIAN_NO_ECC = b"\xFF\xFF\x00\x00\x10\x00"
SPARE_START_LITTLE_ENDIAN_ECC = b"\x00\x10\x00\x00"
SPARE_START_LITTLE_ENDIAN_NO_ECC = b"\xFF\xFF\x00\x10\x00\x00"
PAGE_START_LITTLE_ENDIAN = b"\x01\x00\x00\x00\x01\x00\x00\x00\xff\xff"
PAGE_START_BIG_ENDIAN = b"\x00\x00\x00\x01\x00\x00\x00\x01\xff\xff"

# 00 00 c0 ff ff ff 01 00  9a aa a7 a4 c1 59 aa ab
# 00 00 c0 ff ff ff 01 01  03 ff 0f 00 c1 59 aa ab
# 00 00 c0 ff ff ff 02 01  0f ff f3 0c c1 fc ff 03

# 00 00 03 ff ff ff 00 00  95 aa a7 40 3f 56 aa ab
# 00 00 03 ff ff ff 00 40  0c ff 0f 40 83 56 aa ab
# 00 00 03 ff ff ff 00 40  00 ff f3 80 bf fc ff 03


class YAFFSParser:
    def __init__(self, file: File, config: YAFFSConfig = None):
        self.file_entries = Tree()
        self.file_entries.create_node(ROOT, 1)
        self.file = file
        self._struct_parser = StructParser(C_DEFINITIONS)
        self.file.seek(0, io.SEEK_END)
        self.eof = self.file.tell()
        self.file.seek(0, io.SEEK_SET)
        self.end_offset = -1
        if config is None:
            self.config = self.auto_detect()
        else:
            self.config = config

    def bruteforce(self) -> YAFFSConfig:
        # let's do a trick here
        entries = []
        count = 0
        config = YAFFSConfig(
            endianness=Endian.LITTLE, page_size=-1, spare_size=-1, ecc=False
        )
        for page_size in VALID_PAGE_SIZES:
            for spare_size in VALID_SPARE_SIZES:
                entries = []
                for i in range(0, self.eof // (page_size + spare_size)):
                    start = (page_size + spare_size) * i
                    entries.append(self.file[start : start + 10])  # noqa: E203

                le_count = sum(
                    [entry.startswith(PAGE_START_LITTLE_ENDIAN) for entry in entries]
                )
                be_count = sum(
                    [entry.startswith(PAGE_START_BIG_ENDIAN) for entry in entries]
                )

                if le_count > count or be_count > count:
                    config.endianness = (
                        Endian.LITTLE if le_count > be_count else Endian.BIG
                    )
                    config.page_size = page_size
                    config.spare_size = spare_size
                    count = max([le_count, be_count])

        if config.page_size == -1:
            raise InvalidInputFormat("Can't find YAFFS config through bruteforce.")

        return config

    def auto_detect(self) -> YAFFSConfig:
        """Auto-detect page_size, spare_size, and ECC using known signatures."""

        config = None
        for page_size in VALID_PAGE_SIZES:
            if self.file[page_size:].startswith(SPARE_START_LITTLE_ENDIAN_ECC):
                config = YAFFSConfig(
                    endianness=Endian.LITTLE,
                    page_size=page_size,
                    ecc=True,
                    spare_size=-1,
                )
                break
            elif self.file[page_size:].startswith(SPARE_START_LITTLE_ENDIAN_NO_ECC):
                config = YAFFSConfig(
                    endianness=Endian.LITTLE,
                    page_size=page_size,
                    ecc=False,
                    spare_size=-1,
                )
                break
            elif self.file[page_size:].startswith(SPARE_START_BIG_ENDIAN_ECC):
                config = YAFFSConfig(
                    endianness=Endian.BIG, page_size=page_size, ecc=True, spare_size=-1
                )
                break
            elif self.file[page_size:].startswith(SPARE_START_BIG_ENDIAN_NO_ECC):
                config = YAFFSConfig(
                    endianness=Endian.BIG, page_size=page_size, ecc=False, spare_size=-1
                )
                break

        logger.debug("got config before bruteforce", config=config)

        if config is None:
            return self.bruteforce()

        # Now to try to identify the spare data size...
        # If not using the ECC layout, there are 2 extra bytes at the beginning of the
        # spare data block. Ignore them.

        ecc_offset = 0 if config.ecc else 2

        # TODO: it works except for 512/16

        # The spare data signature is built dynamically, as there are repeating data patterns
        # that we can match on to find where the spare data ends. Take this hexdump for example:
        #
        # 00000800  00 10 00 00 01 01 00 00  00 00 00 00 ff ff ff ff  |................|
        # 00000810  03 00 00 00 01 01 00 00  ff ff 62 61 72 00 00 00  |..........bar...|
        # 00000820  00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00  |................|
        #
        # The spare data starts at offset 0x800 and is 16 bytes in size. The next page data then
        # starts at offset 0x810. Not that the four bytes at 0x804 (in the spare data section) and
        # the four bytes at 0x814 (in the next page data section) are identical. This is because
        # the four bytes at offset 0x804 represent the object ID of the previous object, and the four
        # bytes at offset 0x814 represent the parent object ID of the next object. Also, the
        # four bytes in the page data are always followed by 0xFFFF, as those are the unused name
        # checksum bytes.
        #
        # Thus, the signature for identifying the next page section (and hence, the end of the
        # spare data section) becomes: [the 4 bytes starting at offset 0x804] + 0xFFFF
        #
        # Note that this requires at least one non-empty subdirectory; in practice, any Linux
        # file system should meet this requirement, but one could create a file system that
        # does not meet this requirement.

        object_id_offset = 4
        object_id_start = page_size + ecc_offset + object_id_offset
        object_id_end = object_id_start + 4
        spare_signature = self.file[object_id_start:object_id_end] + b"\xFF\xFF"

        idx = self.file[object_id_end : object_id_end + page_size].find(  # noqa: E203
            spare_signature
        )
        logger.debug(
            "looking for spare signature",
            ecc_offset=ecc_offset,
            object_id_start=object_id_start,
            object_id_end=object_id_end,
            object_id=spare_signature.hex(),
            content=self.file[
                object_id_end : object_id_end + page_size  # noqa: E203
            ].hex(),
            idx=idx,
        )

        config.spare_size = (
            self.file[object_id_end : object_id_end + page_size].find(  # noqa: E203
                spare_signature
            )
            + object_id_offset
            + ecc_offset
        )

        # Sanity check the spare size, make sure it looks legit
        if config.spare_size not in VALID_SPARE_SIZES:
            raise InvalidInputFormat(
                "Auto-detection failed: Detected an unlikely spare size: %d"
                % config.spare_size
            )

        return config

    def insert_entry(self, entry: YAFFSEntry):
        try:
            self.file_entries.create_node(
                entry.object_id,
                entry.object_id,
                data=entry,
                parent=entry.parent_obj_id,
            )
        except NodeIDAbsentError:
            pass
        except DuplicatedNodeIdError:
            pass

    def get_entry(self, object_id: int) -> Optional[YAFFSEntry]:
        try:
            entry = self.file_entries.get_node(object_id)
            if entry:
                return entry.data
            else:
                return None
        except NodeIDAbsentError:
            pass

    def resolve_path(self, entry: YAFFSEntry) -> Path:
        resolved_path = Path(entry.name)
        parent = self.file_entries[entry.parent_obj_id].data
        if parent is not None:
            return self.resolve_path(parent).joinpath(resolved_path)
        else:
            return resolved_path

    def get_file_bytes(self, entry: YAFFSEntry) -> Iterable[bytes]:
        for chunk in entry.chunks:
            self.file.seek(
                entry.start_offset
                + ((chunk.id - 1) * (self.config.page_size + self.config.spare_size)),
                io.SEEK_SET,
            )
            yield self.file.read(chunk.byte_count)

    def extract(self, outdir: Path):
        self.file_entries.show()
        for entry in [
            self.file_entries.get_node(node).data
            for node in self.file_entries.expand_tree(mode=Tree.DEPTH)
        ]:
            if entry is None:
                continue
            self.extract_entry(entry, outdir)

    def extract_entry(self, entry: YAFFSEntry, outdir: Path):  # noqa: C901
        entry_path = self.resolve_path(entry)

        if not is_safe_path(outdir, entry_path):
            logger.warning(
                "Potential path traversal attempt", outdir=outdir, path=entry_path
            )
            return

        out_path = outdir.joinpath(entry_path)

        if entry.type == YAFFS_OBJECT_TYPE.DIRECTORY:
            logger.debug("creating directory", dir_path=out_path, _verbosity=3)
            out_path.mkdir(exist_ok=True)
        elif entry.type == YAFFS_OBJECT_TYPE.FILE:
            logger.debug("creating file", file_path=out_path, _verbosity=3)
            with out_path.open("wb") as f:
                for chunk in self.get_file_bytes(entry):
                    f.write(chunk)
        elif entry.type == YAFFS_OBJECT_TYPE.SPECIAL:
            if os.geteuid() == 0:
                logger.debug(
                    "creating special file", special_path=out_path, _verbosity=3
                )
                os.mknod(out_path.as_posix(), entry.yst_mode, entry.yst_rdev)
            else:
                logger.warn(
                    "creating special files requires elevated privileges, skipping.",
                    path=out_path,
                    yst_mode=entry.yst_mode,
                    yst_rdev=entry.yst_rdev,
                )
        elif entry.type == YAFFS_OBJECT_TYPE.SYMLINK:
            if not is_safe_path(outdir, out_path / Path(entry.alias)):
                logger.warning(
                    "Potential path traversal attempt through symlink",
                    outdir=outdir,
                    path=entry.alias,
                )
                return
            logger.debug("creating symlink", file_path=out_path, _verbosity=3)
            out_path.symlink_to(Path(entry.alias))
        elif entry.type == YAFFS_OBJECT_TYPE.HARDLINK:
            logger.debug("creating hardlink", file_path=out_path, _verbosity=3)
            src_entry = self.file_entries[entry.equiv_id]
            src_path = self.resolve_path(src_entry)
            if not is_safe_path(outdir, out_path / src_path):
                logger.warning(
                    "Potential path traversal attempt through hardlink",
                    outdir=outdir,
                    path=src_path,
                )
                return
            src_path.link_to(out_path)
        elif entry.type == YAFFS_OBJECT_TYPE.UNKNOWN:
            logger.debug("unknown type entry", entry=entry, _verbosity=3)
