import io

from unblob.file_utils import (
    InvalidInputFormat,
)
from unblob.models import (
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
                    uint32  fs_link;
                } fs_42;
                struct {
                    uint32  fs_state;
                } fs_sun;
            } fs_u0;

            uint32  fs_rlink;
            uint32  fs_sblkno;
            uint32  fs_cblkno;
            uint32  fs_iblkno;
            uint32  fs_dblkno;
            uint32  fs_cgoffset;
            uint32  fs_cgmask;
            uint32  fs_time;
            uint32  fs_size;
            uint32  fs_dsize;
            uint32  fs_ncg;
            uint32  fs_bsize;
            uint32  fs_fsize;
            uint32  fs_frag;
            uint32  fs_minfree;
            uint32  fs_rotdelay;
            uint32  fs_rps;
            uint32  fs_bmask;
            uint32  fs_fmask;
            uint32  fs_bshift;
            uint32  fs_fshift;
            uint32  fs_maxcontig;
            uint32  fs_maxbpg;
            uint32  fs_fragshift;
            uint32  fs_fsbtodb;
            uint32  fs_sbsize;
            uint32  fs_csmask;
            uint32  fs_csshift;
            uint32  fs_nindir;
            uint32  fs_inopb;
            uint32  fs_nspf;
            uint32  fs_optim;

            union {
                struct {
                    uint32  fs_npsect;
                } fs_sun;
                struct {
                    uint32  fs_state;
                } fs_sunx86;
            } fs_u1;

            uint32  fs_interleave;
            uint32  fs_trackskew;
            uint32  fs_id[2];
            uint32  fs_csaddr;
            uint32  fs_cssize;
            uint32  fs_cgsize;
            uint32  fs_ntrak;
            uint32  fs_nsect;
            uint32  fs_spc;
            uint32  fs_ncyl;
            uint32  fs_cpg;
            uint32  fs_ipg;
            uint32  fs_fpg;

            struct ufs_csum fs_cstotal;

            int8    fs_fmod;
            int8    fs_clean;
            int8    fs_ronly;
            int8    fs_flags;

            union {
                struct {
                    int8    fs_fsmnt[UFS_MAXMNTLEN];
                    uint32  fs_cgrotor;
                    uint32  fs_csp[UFS_MAXCSBUFS];
                    uint32  fs_maxcluster;
                    uint32  fs_cpc;
                    uint16  fs_opostbl[16][8];
                } fs_u1;
                struct {
                    int8    fs_fsmnt[UFS2_MAXMNTLEN];
                    uint8	fs_volname[UFS2_MAXVOLLEN];
                    uint64  fs_swuid;
                    uint32  fs_pad;
                    uint32  fs_cgrotor;
                    uint32  fs_ocsp[UFS2_NOCSPTRS];
                    uint32  fs_contigdirs;
                    uint32  fs_csp;
                    uint32  fs_maxcluster;
                    uint32  fs_active;
                    uint32  fs_old_cpc;
                    uint32  fs_maxbsize;
                    uint64  fs_sparecon64[17];
                    uint64  fs_sblockloc;
                    struct  ufs2_csum_total fs_cstotal;
                    struct  ufs_timeval    fs_time;
                    uint64  fs_size_64;
                    uint64  fs_dsize;
                    uint64  fs_csaddr;
                    uint64  fs_pendingblocks;
                    uint32  fs_pendinginodes;
                } fs_u2;
            } fs_u11;

            union {
                struct {
                    uint32  fs_sparecon[53];
                    uint32  fs_reclaim;
                    uint32  fs_sparecon2[1];
                    uint32  fs_state;
                    uint32  fs_qbmask[2];
                    uint32  fs_qfmask[2];
                } fs_sun;
                struct {
                    uint32  fs_sparecon[53];
                    uint32  fs_reclaim;
                    uint32  fs_sparecon2[1];
                    uint32  fs_npsect;
                    uint32  fs_qbmask[2];
                    uint32  fs_qfmask[2];
                } fs_sunx86;
                struct {
                    uint32  fs_sparecon[50];
                    uint32  fs_contigsumsize;
                    uint32  fs_maxsymlinklen;
                    uint32  fs_inodefmt;
                    uint32  fs_maxfilesize[2];
                    uint32  fs_qbmask[2];
                    uint32  fs_qfmask[2];
                    uint32  fs_state;
                } fs_44;
            } fs_u2_arch;

            uint32  fs_postblformat;
            uint32  fs_nrpos;
            uint32  fs_postbloff;
            uint32  fs_rotbloff;
            uint32  fs_magic;
            uint8
    fs_space[1];
} ufs_superblock_t;
"""

MAGIC_OFFSET = 0x55C  #  relative to SB_OFFSET


class _UFSHandler(StructHandler):
    HEADER_STRUCT = "ufs_superblock_t"
    C_DEFINITIONS = UFS_C_DEFINITION
    EXTRACTOR = None
    SB_OFFSET = 0

    def get_block_size(self, header) -> int:
        raise NotImplementedError("Subclasses must implement this function.")

    def is_valid_header(self, header) -> bool:
        return (
            header.fs_frag == (header.fs_bsize // header.fs_fsize)
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


class UFS1Handler(_UFSHandler):
    NAME = "ufs1"
    PATTERNS = [HexString("54 19 01")]  # UFS1 little endian
    SB_OFFSET = 0x2000
    PATTERN_MATCH_OFFSET = -SB_OFFSET - MAGIC_OFFSET
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
        limitations=[
            "File extraction is not yet supported, only carving of the filesystem is currently available."
        ],
    )

    def get_block_size(self, header) -> int:
        return header.fs_size


class UFS2Handler(_UFSHandler):
    NAME = "ufs2"
    PATTERNS = [HexString("19 01 54 19")]
    SB_OFFSET = 0x10000
    PATTERN_MATCH_OFFSET = -SB_OFFSET - MAGIC_OFFSET
    DOC = HandlerDoc(
        name="ufs2",
        description="UFS2 (Unix File System 2) is an extended version of UFS1 supported by Unix-like operating systems such as FreeBSD and Solaris. It introduces 64-bit block addressing, extended file attributes, and improved performance over UFS1, while retaining the hierarchical tree structure and inodes for file metadata and data block management.",
        handler_type=HandlerType.FILESYSTEM,
        vendor=None,
        references=[
            Reference(
                title="Unix File System Wikipedia",
                url="https://en.wikipedia.org/wiki/Unix_File_System",
            )
        ],
        limitations=[
            "File extraction is not yet supported, only carving of the filesystem is currently available."
        ],
    )

    def get_block_size(self, header) -> int:
        return header.fs_u11.fs_u2.fs_size_64
