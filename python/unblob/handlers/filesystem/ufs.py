import io
import stat
import struct
from collections.abc import Iterator
from pathlib import Path

from unblob.file_utils import (
    Endian,
    FileSystem,
    InvalidInputFormat,
    StructParser,
)
from unblob.models import (
    Extractor,
    ExtractResult,
    File,
    HandlerDoc,
    HandlerType,
    HexString,
    Reference,
    StructHandler,
    ValidChunk,
)

UFS_C_DEFINITION = """
        #define UFS_MAXMNTLEN    512
        #define UFS2_MAXMNTLEN   468
        #define UFS2_MAXVOLLEN   32
        #define UFS_MAXCSBUFS    31
        #define UFS2_NOCSPTRS    28

        struct ufs_csum {
            uint32  cs_ndir;
            uint32  cs_nbfree;
            uint32  cs_nifree;
            uint32  cs_nffree;
        };

        struct ufs2_csum_total {
            uint64  cs_ndir;
            uint64  cs_nbfree;
            uint64  cs_nifree;
            uint64  cs_nffree;
            uint64  cs_numclusters;
            uint64  cs_spare[3];
        };

        struct ufs_timeval {
            uint32  tv_sec;
            uint32  tv_usec;
        };

        struct ufs_super_block {
            union {
                struct {
                    uint32  fs_link;        /* UNUSED */
                } fs_42;
                struct {
                    uint32  fs_state;       /* file system state flag */
                } fs_sun;
            } fs_u0;

            uint32  fs_rlink;               /* UNUSED */
            uint32  fs_sblkno;              /* addr of super-block in filesys */
            uint32  fs_cblkno;              /* offset of cyl-block in filesys */
            uint32  fs_iblkno;              /* offset of inode-blocks in filesys */
            uint32  fs_dblkno;              /* offset of first data after cg */
            uint32  fs_cgoffset;            /* cylinder group offset in cylinder */
            uint32  fs_cgmask;              /* used to calc mod fs_ntrak */
            uint32  fs_time;                /* last time written */
            uint32  fs_size;                /* number of blocks in fs */
            uint32  fs_dsize;               /* number of data blocks in fs */
            uint32  fs_ncg;                 /* number of cylinder groups */
            uint32  fs_bsize;               /* size of basic blocks in fs */
            uint32  fs_fsize;               /* size of frag blocks in fs */
            uint32  fs_frag;                /* number of frags in a block in fs */
            /* configuration parameters */
            uint32  fs_minfree;             /* minimum percentage of free blocks */
            uint32  fs_rotdelay;            /* num of ms for optimal next block */
            uint32  fs_rps;                 /* disk revolutions per second */
            /* fields computed from the others */
            uint32  fs_bmask;               /* blkoff calc of blk offsets */
            uint32  fs_fmask;               /* fragoff calc of frag offsets */
            uint32  fs_bshift;              /* lblkno calc of logical blkno */
            uint32  fs_fshift;              /* numfrags calc number of frags */
            /* configuration parameters */
            uint32  fs_maxcontig;           /* max number of contiguous blks */
            uint32  fs_maxbpg;              /* max number of blks per cyl group */
            /* fields computed from the others */
            uint32  fs_fragshift;           /* block to frag shift */
            uint32  fs_fsbtodb;             /* fsbtodb and dbtofsb shift constant */
            uint32  fs_sbsize;              /* actual size of super block */
            uint32  fs_csmask;              /* csum block offset */
            uint32  fs_csshift;             /* csum block number */
            uint32  fs_nindir;              /* value of NINDIR */
            uint32  fs_inopb;               /* value of INOPB */
            uint32  fs_nspf;                /* value of NSPF */
            /* optimization preference */
            uint32  fs_optim;

            /* fields derived from the hardware */
            union {
                struct {
                    uint32  fs_npsect;      /* # sectors/track including spares */
                } fs_sun;
                struct {
                    uint32  fs_state;       /* file system state time stamp */
                } fs_sunx86;
            } fs_u1;

            uint32  fs_interleave;          /* hardware sector interleave */
            uint32  fs_trackskew;           /* sector 0 skew, per track */
            uint32  fs_id[2];               /* file system id */
            /* sizes determined by number of cylinder groups and their sizes */
            uint32  fs_csaddr;              /* blk addr of cyl grp summary area */
            uint32  fs_cssize;              /* size of cyl grp summary area */
            uint32  fs_cgsize;              /* cylinder group size */
            /* fields derived from the hardware */
            uint32  fs_ntrak;               /* tracks per cylinder */
            uint32  fs_nsect;               /* sectors per track */
            uint32  fs_spc;                 /* sectors per cylinder */
            /* this comes from the disk driver partitioning */
            uint32  fs_ncyl;                /* cylinders in file system */
            /* fields computed from the others */
            uint32  fs_cpg;                 /* cylinders per group */
            uint32  fs_inodes_per_group;    /* inodes per cylinder group */
            uint32  fs_frags_per_group;     /* blocks per group * fs_frag */

            /* this data must be re-computed after crashes */
            struct ufs_csum fs_cstotal;     /* cylinder summary information */

            /* fields cleared at mount time */
            int8    fs_fmod;                /* super block modified flag */
            int8    fs_clean;               /* file system is clean flag */
            int8    fs_ronly;               /* mounted read-only flag */
            int8    fs_flags;

            union {
                struct {
                    int8    fs_fsmnt[UFS_MAXMNTLEN];    /* name mounted on */
                    uint32  fs_cgrotor;                 /* last cg searched */
                    uint32  fs_csp[UFS_MAXCSBUFS];      /* list of fs_cs info buffers */
                    uint32  fs_maxcluster;
                    uint32  fs_cpc;                     /* cyl per cycle in postbl */
                    uint16  fs_opostbl[16][8];          /* old rotation block list head */
                } fs_u1;
                struct {
                    int8    fs_fsmnt[UFS2_MAXMNTLEN];   /* name mounted on */
                    uint8   fs_volname[UFS2_MAXVOLLEN]; /* volume name */
                    uint64  fs_swuid;                   /* system-wide uid */
                    uint32  fs_pad;                     /* due to alignment of fs_swuid */
                    uint32  fs_cgrotor;                 /* last cg searched */
                    uint32  fs_ocsp[UFS2_NOCSPTRS];     /* list of fs_cs info buffers */
                    uint32  fs_contigdirs;              /* # of contiguously allocated dirs */
                    uint32  fs_csp;                     /* cg summary info buffer */
                    uint32  fs_maxcluster;
                    uint32  fs_active;                  /* used by snapshots to track fs */
                    uint32  fs_old_cpc;                 /* cyl per cycle in postbl */
                    uint32  fs_maxbsize;                /* maximum blocking factor permitted */
                    uint64  fs_sparecon64[17];          /* old rotation block list head */
                    uint64  fs_sblockloc;               /* byte offset of standard superblock */
                    struct  ufs2_csum_total fs_cstotal; /* cylinder summary information */
                    struct  ufs_timeval    fs_time;     /* last time written */
                    uint64  fs_size_64;                 /* number of blocks in fs */
                    uint64  fs_dsize;                   /* number of data blocks in fs */
                    uint64  fs_csaddr;                  /* blk addr of cyl grp summary area */
                    uint64  fs_pendingblocks;           /* blocks in process of being freed */
                    uint32  fs_pendinginodes;           /* inodes in process of being freed */
                } fs_u2;
            } fs_u11;

            union {
                struct {
                    uint32  fs_sparecon[53];            /* reserved for future constants */
                    uint32  fs_reclaim;
                    uint32  fs_sparecon2[1];
                    uint32  fs_state;                   /* file system state time stamp */
                    uint32  fs_qbmask[2];               /* ~usb_bmask */
                    uint32  fs_qfmask[2];               /* ~usb_fmask */
                } fs_sun;
                struct {
                    uint32  fs_sparecon[53];            /* reserved for future constants */
                    uint32  fs_reclaim;
                    uint32  fs_sparecon2[1];
                    uint32  fs_npsect;                  /* # sectors/track including spares */
                    uint32  fs_qbmask[2];               /* ~usb_bmask */
                    uint32  fs_qfmask[2];               /* ~usb_fmask */
                } fs_sunx86;
                struct {
                    uint32  fs_sparecon[50];            /* reserved for future constants */
                    uint32  fs_contigsumsize;           /* size of cluster summary array */
                    uint32  fs_maxsymlinklen;           /* max length of an internal symlink */
                    uint32  fs_inodefmt;                /* format of on-disk inodes */
                    uint32  fs_maxfilesize[2];          /* max representable file size */
                    uint32  fs_qbmask[2];               /* ~usb_bmask */
                    uint32  fs_qfmask[2];               /* ~usb_fmask */
                    uint32  fs_state;                   /* file system state time stamp */
                } fs_44;
            } fs_u2_arch;

            uint32  fs_postblformat;        /* format of positional layout tables */
            uint32  fs_nrpos;               /* number of rotational positions */
            uint32  fs_postbloff;           /* rotation block list head */
            uint32  fs_rotbloff;            /* blocks for each rotation */
            uint32  fs_magic;               /* magic number */
            uint8   fs_space[1];            /* list of blocks for each rotation */
} ufs_superblock_t;

        #define UFS_NDADDR  12
        #define UFS_NINDIR  3

        /* UFS1 FreeBSD & Solaris */
        struct ufs1_inode {
            uint16	mode;		/*  0x0 */
            uint16	nlink;		/*  0x2 */
            union {
                struct {
                    uint16	suid;	/*  0x4 */
                    uint16	sgid;	/*  0x6 */
                } oldids;
                uint32	inumber;		/*  0x4 lsf: inode number */
                uint32	author;		/*  0x4 GNU HURD: author */
            } u1;
            uint64	size;		/*  0x8 */
            struct ufs_timeval atime;	/* 0x10 access */
            struct ufs_timeval mtime;	/* 0x18 modification */
            struct ufs_timeval ctime;	/* 0x20 creation */
            union {
                struct {
                    uint32	direct_blocks[UFS_NDADDR];/* 0x28 data blocks */
                    uint32	indirect_blocks[UFS_NINDIR];/* 0x58 indirect blocks */
                } addr;
                uint8	symlink[4*(UFS_NDADDR+UFS_NINDIR)];/* 0x28 fast symlink */
            } u2;
            uint32	flags;		/* 0x64 immutable, append-only... */
            uint32	blocks;		/* 0x68 blocks in use */
            uint32	gen;			/* 0x6c like ext2 i_version, for NFS support */
            union {
                struct {
                    uint32	shadow;	/* 0x70 shadow inode with security data */
                    uint32	uid;		/* 0x74 long EFT version of uid */
                    uint32	gid;		/* 0x78 long EFT version of gid */
                    uint32	oeftflag;	/* 0x7c reserved */
                } sun;
                struct {
                    uint32	uid;		/* 0x70 File owner */
                    uint32	gid;		/* 0x74 File group */
                    uint32	spare[2];	/* 0x78 reserved */
                } bsd44;
                struct {
                    uint32	uid;		/* 0x70 */
                    uint32	gid;		/* 0x74 */
                    uint16	modeh;	/* 0x78 mode high bits */
                    uint16	spare;	/* 0x7A unused */
                    uint32	trans;	/* 0x7c filesystem translator */
                } hurd;
            } u3;
        } ufs1_inode_t;

        #define UFS_NXADDR  2

        /* ---- UFS2 on-disk inode (256 bytes) ---- */
        struct ufs2_inode {
            uint16     mode;        /*   0: IFMT, permissions; see below. */
            uint16     nlink;       /*   2: File link count. */
            uint32     uid;         /*   4: File owner. */
            uint32     gid;         /*   8: File group. */
            uint32     blksize;     /*  12: Inode blocksize. */
            uint64     size;        /*  16: File byte count. */
            uint64     blocks;      /*  24: Bytes actually held. */
            uint64   atime;       /*  32: Last access time. */
            uint64   mtime;       /*  40: Last modified time. */
            uint64   ctime;       /*  48: Last inode change time. */
            uint64   birthtime;   /*  56: Inode creation time. */
            uint32     mtimensec;   /*  64: Last modified time. */
            uint32     atimensec;   /*  68: Last access time. */
            uint32     ctimensec;   /*  72: Last inode change time. */
            uint32     birthnsec;   /*  76: Inode creation time. */
            uint32     gen;         /*  80: Generation number. */
            uint32     kernflags;   /*  84: Kernel flags. */
            uint32     flags;       /*  88: Status flags (chflags). */
            uint32     extsize;     /*  92: External attributes block. */
            uint64     extb[UFS_NXADDR];/*  96: External attributes block. */
            union {
                struct {
                    uint64     direct_blocks[UFS_NDADDR]; /* 112: Direct disk blocks. */
                    uint64     indirect_blocks[UFS_NINDIR];/* 208: Indirect disk blocks.*/
                } addr;
            uint8	symlink[2*4*(UFS_NDADDR+UFS_NINDIR)];/* 0x28 fast symlink */
            } u2;
            uint64     spare[3];    /* 232: Reserved; currently unused */
        } ufs2_inode_t;

        /* New OpenBSD & FreeBSD */

        struct ufs_dirent {
            uint32  d_ino;  /* inode number of this entry */
            uint16  d_reclen; /* length of this entry */
            uint8   d_type; /* file type */
            uint8   d_namlen;
            char    d_name[d_namlen];
        };

"""

MAGIC_OFFSET = 0x55C  #  relative to SB_OFFSET
UFS_ROOT_INO = 2
DELETED_INO = 0
MAX_BLOCK_SIZE = 65536  # FreeBSD MAXBSIZE (sys/sys/param.h)


class UFSParser:
    INODE_STRUCT: str
    INODE_SIZE: int
    PTR_SIZE: int

    def __init__(self, file: File, sb_offset: int):
        self.file = file
        self._struct_parser = StructParser(UFS_C_DEFINITION)
        self.file.seek(sb_offset, io.SEEK_SET)
        self.super_block = self._struct_parser.parse(
            "ufs_superblock_t", self.file, Endian.LITTLE
        )

    def walk_extract(self, fs: FileSystem, ino_num: int, path: Path):  # noqa: C901
        inode = self.read_inode(ino_num)
        file_type = stat.S_IFMT(inode.mode)

        match file_type:
            case stat.S_IFDIR:
                fs.mkdir(path, exist_ok=True)
                for child_ino, name in self.parse_dentries(inode):
                    if name in (".", ".."):
                        continue
                    self.walk_extract(fs, child_ino, path / name)
            case stat.S_IFREG:
                fs.write_chunks(path, self.read_file_content(inode))
            case stat.S_IFLNK:
                fs.create_symlink(src=Path(self.read_symlink(inode)), dst=path)
            case stat.S_IFIFO:
                fs.mkfifo(path)
            case stat.S_IFSOCK:
                fs.mknod(path, mode=inode.mode)
            case stat.S_IFCHR | stat.S_IFBLK:
                fs.mknod(path, mode=inode.mode, device=self.get_direct_blocks(inode)[0])

    def parse_dentries(self, inode) -> Iterator[tuple[int, str]]:
        for chunk in self.read_file_content(inode):
            offset = 0
            while offset < len(chunk):
                entry = self._struct_parser.parse(
                    "ufs_dirent", chunk[offset:], Endian.LITTLE
                )
                # d_reclen == 0 means end of valid entries in this block
                if entry.d_reclen == 0:
                    break
                offset += entry.d_reclen
                if entry.d_ino == DELETED_INO:
                    continue
                yield (
                    entry.d_ino,
                    entry.d_name.decode("utf-8", errors="replace"),
                )

    def read_file_content(self, inode) -> Iterator[bytes]:
        remaining = inode.size
        for chunk in self.read_direct_blocks(inode):
            to_read = min(len(chunk), remaining)
            yield chunk[:to_read]
            remaining -= to_read
            if remaining <= 0:
                return
        for chunk in self.read_indirect_blocks(inode, remaining):
            yield chunk

    def read_direct_blocks(self, inode) -> Iterator[bytes]:
        for fragment_index in self.get_direct_blocks(inode):
            if fragment_index == 0:
                # Sparse file: unallocated block reads as zeroes
                yield b"\x00" * self.super_block.fs_bsize
            else:
                self.file.seek(self.frag_to_offset(fragment_index), io.SEEK_SET)
                yield self.file.read(self.super_block.fs_bsize)

    def read_indirect_blocks(self, inode, remaining: int) -> Iterator[bytes]:  # noqa: C901
        indirect_blocks = self.get_indirect_blocks(inode)
        for level, fragment_index in enumerate(indirect_blocks, start=1):
            if fragment_index == 0 or remaining <= 0:
                break
            # levels: single=1, double=2, triple=3
            indexes = [fragment_index]
            for _ in range(level):
                next_indexes = []
                for idx in indexes:
                    if idx != 0:
                        next_indexes.extend(self.read_block_pointers(idx))
                indexes = next_indexes
            for data_index in indexes:
                if remaining <= 0:
                    return
                to_read = min(self.super_block.fs_bsize, remaining)
                if data_index == 0:
                    # Sparse file: unallocated block reads as zeroes
                    yield b"\x00" * to_read
                else:
                    self.file.seek(self.frag_to_offset(data_index), io.SEEK_SET)
                    yield self.file.read(to_read)
                remaining -= to_read

    def read_block_pointers(self, fragment_index: int) -> list[int]:
        self.file.seek(self.frag_to_offset(fragment_index), io.SEEK_SET)
        data = self.file.read(self.super_block.fs_bsize)
        count = self.super_block.fs_bsize // self.PTR_SIZE
        fmt = f"<{count}I" if self.PTR_SIZE == 4 else f"<{count}Q"
        return list(struct.unpack(fmt, data))

    def read_symlink(self, inode) -> str:
        if inode.blocks == 0:
            return bytes(inode.u2.symlink[: inode.size]).decode(
                "utf-8", errors="replace"
            )
        chunk = next(self.read_file_content(inode))
        return chunk[: inode.size].decode("utf-8", errors="replace")

    def read_inode(self, ino_number: int):
        cylinder_group = ino_number // self.super_block.fs_inodes_per_group
        index = ino_number % self.super_block.fs_inodes_per_group
        offset = (
            self.frag_to_offset(
                self.cylinder_group_start(cylinder_group) + self.super_block.fs_iblkno
            )
            + index * self.INODE_SIZE
        )
        self.file.seek(offset, io.SEEK_SET)
        return self._struct_parser.parse(self.INODE_STRUCT, self.file, Endian.LITTLE)

    def frag_to_offset(self, fragment_index: int) -> int:
        """Convert a fragment index to a byte offset."""
        return fragment_index * self.super_block.fs_fsize

    def cylinder_group_start(self, cylinder_group: int) -> int:
        return cylinder_group * self.super_block.fs_frags_per_group

    def get_direct_blocks(self, inode) -> list[int]:
        return inode.u2.addr.direct_blocks

    def get_indirect_blocks(self, inode) -> list[int]:
        return inode.u2.addr.indirect_blocks


class UFS1Parser(UFSParser):
    INODE_STRUCT = "ufs1_inode_t"
    INODE_SIZE = 128
    PTR_SIZE = 4

    def cylinder_group_start(self, cylinder_group: int) -> int:
        # Old UFS1 rotates cylinder group layout to minimize seek time on spinning disks
        return (
            cylinder_group * self.super_block.fs_frags_per_group
            + self.super_block.fs_cgoffset
            * (cylinder_group & ~self.super_block.fs_cgmask)
        )


class UFS2Parser(UFSParser):
    INODE_STRUCT = "ufs2_inode_t"
    INODE_SIZE = 256
    PTR_SIZE = 8


class UFSExtractor(Extractor):
    def __init__(self, parser: type[UFSParser], sb_offset: int):
        self.parser = parser
        self.sb_offset = sb_offset

    def extract(self, inpath: Path, outdir: Path):
        fs = FileSystem(outdir)
        with File.from_path(inpath) as f:
            parser = self.parser(f, self.sb_offset)
            parser.walk_extract(fs, UFS_ROOT_INO, Path("/"))
        return ExtractResult(reports=fs.problems)


class _UFSBaseHandler(StructHandler):
    HEADER_STRUCT = "ufs_superblock_t"
    C_DEFINITIONS = UFS_C_DEFINITION
    EXTRACTOR = None
    SB_OFFSET = 0

    def get_block_size(self, header) -> int:
        raise NotImplementedError("Subclasses must implement this function.")

    def is_valid_header(self, header) -> bool:
        return (
            header.fs_fsize > 0
            and header.fs_bsize > 0
            and header.fs_bsize <= MAX_BLOCK_SIZE
            and header.fs_frag == (header.fs_bsize // header.fs_fsize)
            and self.get_block_size(header) > 0
            and header.fs_ncg > 0
        )

    def calculate_chunk(self, file: File, start_offset: int) -> ValidChunk | None:
        file.seek(
            start_offset + self.SB_OFFSET, io.SEEK_SET
        )  # Skip the boot sector to reach the start of UFS superblock
        header = self.parse_header(file)
        if not self.is_valid_header(header):
            raise InvalidInputFormat("Invalid UFS Header")

        end_offset = start_offset + (self.get_block_size(header) * header.fs_fsize)
        return ValidChunk(start_offset=start_offset, end_offset=end_offset)


class UFS1Handler(_UFSBaseHandler):
    NAME = "ufs1"
    PATTERNS = [
        HexString("( 01 | 02 ) 00 00 00 [8] 54 19 01 00")
    ]  # fs_nrpos +  UFS1 fs_magic + null fs_space
    SB_OFFSET = 0x2000
    EXTRACTOR = UFSExtractor(UFS1Parser, SB_OFFSET)
    PATTERN_MATCH_OFFSET = -SB_OFFSET - (MAGIC_OFFSET - 12)
    DOC = HandlerDoc(
        name="ufs1",
        description="UFS1 (Unix File System 1) is the original UFS implementation supported by Unix-like operating systems such as FreeBSD and Solaris. It utilizes a hierarchical tree structure and inodes to manage file metadata and data block addresses, with 32-bit block addressing limiting partition sizes to 1TB.",
        handler_type=HandlerType.FILESYSTEM,
        vendor=None,
        references=[
            Reference(
                title="Unix File System Wikipedia",
                url="https://en.wikipedia.org/wiki/Unix_File_System",
            )
        ],
        limitations=[],
    )

    def get_block_size(self, header) -> int:
        return header.fs_size


class UFS2Handler(_UFSBaseHandler):
    NAME = "ufs2"
    PATTERNS = [HexString("19 01 54 19 00")]  # UFS2 fs_magic + null fs_space
    SB_OFFSET = 0x10000
    PATTERN_MATCH_OFFSET = -SB_OFFSET - MAGIC_OFFSET
    EXTRACTOR = UFSExtractor(UFS2Parser, SB_OFFSET)
    DOC = HandlerDoc(
        name="ufs2",
        description="UFS2 (Unix File System 2) is an extended version of UFS1 supported by Unix-like operating systems such as FreeBSD. It introduces 64-bit block addressing, extended file attributes, and improved performance over UFS1, while retaining the hierarchical tree structure and inodes for file metadata and data block management.",
        handler_type=HandlerType.FILESYSTEM,
        vendor=None,
        references=[
            Reference(
                title="Unix File System Wikipedia",
                url="https://en.wikipedia.org/wiki/Unix_File_System",
            )
        ],
        limitations=[],
    )

    def get_block_size(self, header) -> int:
        return header.fs_u11.fs_u2.fs_size_64
