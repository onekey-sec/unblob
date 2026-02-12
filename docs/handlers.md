??? example "All supported formats"
    | Format        | Type                                 | Fully supported?    |
    | :------------ | :----------------------------------- | :-----------------: |
    | [`7-ZIP`](#7-zip) | ARCHIVE | :octicons-check-16: |
    | [`ANDROID EROFS`](#android-erofs) | FILESYSTEM | :octicons-check-16: |
    | [`ANDROID SPARSE`](#android-sparse) | FILESYSTEM | :octicons-check-16: |
    | [`AR`](#ar) | ARCHIVE | :octicons-check-16: |
    | [`ARC`](#arc) | ARCHIVE | :octicons-check-16: |
    | [`ARJ`](#arj) | ARCHIVE | :octicons-check-16: |
    | [`AUTEL ECC`](#autel-ecc) | ARCHIVE | :octicons-check-16: |
    | [`BZIP2`](#bzip2) | COMPRESSION | :octicons-check-16: |
    | [`CAB`](#cab) | ARCHIVE | :octicons-check-16: |
    | [`COMPRESS`](#compress) | COMPRESSION | :octicons-check-16: |
    | [`CPIO (BINARY)`](#cpio-binary) | ARCHIVE | :octicons-check-16: |
    | [`CPIO (PORTABLE ASCII CRC)`](#cpio-portable-ascii-crc) | ARCHIVE | :octicons-check-16: |
    | [`CPIO (PORTABLE ASCII)`](#cpio-portable-ascii) | ARCHIVE | :octicons-check-16: |
    | [`CPIO (PORTABLE OLD ASCII)`](#cpio-portable-old-ascii) | ARCHIVE | :octicons-check-16: |
    | [`CRAMFS`](#cramfs) | FILESYSTEM | :octicons-check-16: |
    | [`D-LINK ALPHA ENCIMG V1 FIRMWARE`](#d-link-alpha-encimg-v1-firmware) | ARCHIVE | :octicons-check-16: |
    | [`D-LINK ALPHA ENCIMG V2 FIRMWARE`](#d-link-alpha-encimg-v2-firmware) | ARCHIVE | :octicons-check-16: |
    | [`D-LINK DEAFBEAD`](#d-link-deafbead) | ARCHIVE | :octicons-check-16: |
    | [`D-LINK ENCRPTED_IMG`](#d-link-encrpted_img) | ARCHIVE | :octicons-check-16: |
    | [`D-LINK FPKG`](#d-link-fpkg) | ARCHIVE | :octicons-check-16: |
    | [`D-LINK SHRS`](#d-link-shrs) | ARCHIVE | :octicons-check-16: |
    | [`DMG`](#dmg) | ARCHIVE | :octicons-check-16: |
    | [`ELF (32-BIT)`](#elf-32-bit) | EXECUTABLE | :octicons-check-16: |
    | [`ELF (64-BIT)`](#elf-64-bit) | EXECUTABLE | :octicons-check-16: |
    | [`ENGENIUS`](#engenius) | ARCHIVE | :octicons-alert-fill-12: |
    | [`EXTFS`](#extfs) | FILESYSTEM | :octicons-check-16: |
    | [`FAT`](#fat) | FILESYSTEM | :octicons-check-16: |
    | [`GZIP`](#gzip) | COMPRESSION | :octicons-check-16: |
    | [`GZIP (MULTI-VOLUME)`](#gzip-multi-volume) | COMPRESSION | :octicons-check-16: |
    | [`HP BDL`](#hp-bdl) | ARCHIVE | :octicons-check-16: |
    | [`HP IPKG`](#hp-ipkg) | ARCHIVE | :octicons-check-16: |
    | [`INSTAR BNEG`](#instar-bneg) | ARCHIVE | :octicons-check-16: |
    | [`INSTAR HD`](#instar-hd) | ARCHIVE | :octicons-check-16: |
    | [`ISO 9660`](#iso-9660) | FILESYSTEM | :octicons-check-16: |
    | [`JFFS2 (NEW)`](#jffs2-new) | FILESYSTEM | :octicons-check-16: |
    | [`JFFS2 (OLD)`](#jffs2-old) | FILESYSTEM | :octicons-check-16: |
    | [`LZ4`](#lz4) | COMPRESSION | :octicons-check-16: |
    | [`LZ4 (LEGACY)`](#lz4-legacy) | COMPRESSION | :octicons-check-16: |
    | [`LZ4 (SKIPPABLE)`](#lz4-skippable) | COMPRESSION | :octicons-check-16: |
    | [`LZH`](#lzh) | COMPRESSION | :octicons-check-16: |
    | [`LZIP`](#lzip) | COMPRESSION | :octicons-check-16: |
    | [`LZMA`](#lzma) | COMPRESSION | :octicons-check-16: |
    | [`LZO`](#lzo) | COMPRESSION | :octicons-check-16: |
    | [`MSI`](#msi) | ARCHIVE | :octicons-alert-fill-12: |
    | [`MULTI-SEVENZIP`](#multi-sevenzip) | ARCHIVE | :octicons-check-16: |
    | [`NETGEAR CHK`](#netgear-chk) | ARCHIVE | :octicons-check-16: |
    | [`NETGEAR TRX V1`](#netgear-trx-v1) | ARCHIVE | :octicons-check-16: |
    | [`NETGEAR TRX V2`](#netgear-trx-v2) | ARCHIVE | :octicons-check-16: |
    | [`NTFS`](#ntfs) | FILESYSTEM | :octicons-check-16: |
    | [`PAR2 (MULTI-VOLUME)`](#par2-multi-volume) | ARCHIVE | :octicons-check-16: |
    | [`PARTCLONE`](#partclone) | ARCHIVE | :octicons-check-16: |
    | [`QNAP NAS`](#qnap-nas) | ARCHIVE | :octicons-check-16: |
    | [`RAR`](#rar) | ARCHIVE | :octicons-alert-fill-12: |
    | [`ROMFS`](#romfs) | FILESYSTEM | :octicons-check-16: |
    | [`SQUASHFS (V1)`](#squashfs-v1) | FILESYSTEM | :octicons-check-16: |
    | [`SQUASHFS (V2)`](#squashfs-v2) | FILESYSTEM | :octicons-check-16: |
    | [`SQUASHFS (V2-NON-STANDARD)`](#squashfs-v2-non-standard) | FILESYSTEM | :octicons-check-16: |
    | [`SQUASHFS (V3)`](#squashfs-v3) | FILESYSTEM | :octicons-check-16: |
    | [`SQUASHFS (V3-BROADCOM)`](#squashfs-v3-broadcom) | FILESYSTEM | :octicons-check-16: |
    | [`SQUASHFS (V3-DDWRT)`](#squashfs-v3-ddwrt) | FILESYSTEM | :octicons-check-16: |
    | [`SQUASHFS (V3-NON-STANDARD)`](#squashfs-v3-non-standard) | FILESYSTEM | :octicons-check-16: |
    | [`SQUASHFS (V4-BE)`](#squashfs-v4-be) | FILESYSTEM | :octicons-check-16: |
    | [`SQUASHFS (V4-BROADCOM)`](#squashfs-v4-broadcom) | FILESYSTEM | :octicons-check-16: |
    | [`SQUASHFS (V4-LE)`](#squashfs-v4-le) | FILESYSTEM | :octicons-check-16: |
    | [`STUFFIT SIT`](#stuffit-sit) | ARCHIVE | :octicons-check-16: |
    | [`STUFFIT SIT (V5)`](#stuffit-sit-v5) | ARCHIVE | :octicons-check-16: |
    | [`TAR (UNIX)`](#tar-unix) | ARCHIVE | :octicons-check-16: |
    | [`TAR (USTAR)`](#tar-ustar) | ARCHIVE | :octicons-check-16: |
    | [`UBI`](#ubi) | FILESYSTEM | :octicons-check-16: |
    | [`UBIFS`](#ubifs) | FILESYSTEM | :octicons-check-16: |
    | [`UZIP`](#uzip) | COMPRESSION | :octicons-check-16: |
    | [`XIAOMI HDR1`](#xiaomi-hdr1) | ARCHIVE | :octicons-check-16: |
    | [`XIAOMI HDR2`](#xiaomi-hdr2) | ARCHIVE | :octicons-check-16: |
    | [`XZ`](#xz) | COMPRESSION | :octicons-check-16: |
    | [`YAFFS`](#yaffs) | FILESYSTEM | :octicons-check-16: |
    | [`ZIP`](#zip) | ARCHIVE | :octicons-alert-fill-12: |
    | [`ZLIB`](#zlib) | COMPRESSION | :octicons-check-16: |
    | [`ZSTD`](#zstd) | COMPRESSION | :octicons-check-16: |

## 7-Zip

!!! success "Fully supported"

    === "Description"

        The 7-Zip file format is a compressed archive format with high compression ratios, supporting multiple algorithms, CRC checks, and multi-volume archives.

        ---

        - **Handler type:** Archive
        

    === "References"

        - [7-Zip Technical Documentation](https://fastapi.metacpan.org/source/BJOERN/Compress-Deflate7-1.0/7zip/DOC/7zFormat.txt){ target="_blank" }
## Android EROFS

!!! success "Fully supported"

    === "Description"

        EROFS (Enhanced Read-Only File System) is a lightweight, high-performance file system designed for read-only use cases, commonly used in Android and Linux. It features compression support, metadata efficiency, and a fixed superblock structure.

        ---

        - **Handler type:** FileSystem
        - **Vendor:** Google

    === "References"

        - [EROFS Documentation](https://www.kernel.org/doc/html/latest/filesystems/erofs.html){ target="_blank" }
        - [EROFS Wikipedia](https://en.wikipedia.org/wiki/Enhanced_Read-Only_File_System){ target="_blank" }
## Android Sparse

!!! success "Fully supported"

    === "Description"

        Android sparse images are a file format used to efficiently store disk images by representing sequences of zero blocks compactly. The format includes a file header, followed by chunk headers and data, with support for raw, fill, and 'don't care' chunks.

        ---

        - **Handler type:** FileSystem
        - **Vendor:** Google

    === "References"

        - [Android Sparse Image Format Documentation](https://formats.kaitai.io/android_sparse/){ target="_blank" }
        - [simg2img Tool](https://github.com/anestisb/android-simg2img){ target="_blank" }
## AR

!!! success "Fully supported"

    === "Description"

        Unix AR (archive) files are used to store multiple files in a single archive with a simple header format.

        ---

        - **Handler type:** Archive
        

    === "References"

        - [Unix AR File Format Documentation](https://en.wikipedia.org/wiki/Ar_(Unix)){ target="_blank" }
## ARC

!!! success "Fully supported"

    === "Description"

        ARC is a legacy archive format used to store multiple files with metadata such as file size, creation date, and CRC.

        ---

        - **Handler type:** Archive
        

    === "References"

        - [ARC File Format Documentation](https://en.wikipedia.org/wiki/ARC_(file_format)){ target="_blank" }
## ARJ

!!! success "Fully supported"

    === "Description"

        ARJ is a legacy compressed archive formats used to store multiple files with metadata such as file size, creation date, and CRC.

        ---

        - **Handler type:** Archive
        

    === "References"

        - [ARJ File Format Documentation](https://docs.fileformat.com/compression/arj/){ target="_blank" }
        - [ARJ Technical Information](https://github.com/tripsin/unarj/blob/master/UNARJ.H#L203){ target="_blank" }
## Autel ECC

!!! success "Fully supported"

    === "Description"

        Autel ECC files consist of a custom header followed by encrypted data blocks. The header includes metadata such as magic bytes, file size, and copyright information.

        ---

        - **Handler type:** Archive
        - **Vendor:** Autel

    === "References"

        - [Autel ECC Decryption Script (Sector7)](https://gist.github.com/sector7-nl/3fc815cd2497817ad461bfbd393294cb){ target="_blank" }
## bzip2

!!! success "Fully supported"

    === "Description"

        The bzip2 format is a block-based compression format that uses the Burrows-Wheeler transform and Huffman coding for high compression efficiency. Each stream starts with a header and consists of one or more compressed blocks, ending with a footer containing a checksum.

        ---

        - **Handler type:** Compression
        

    === "References"

        - [bzip2 File Format Documentation](https://sourceware.org/bzip2/manual/manual.html){ target="_blank" }
        - [bzip2 Technical Specification](https://en.wikipedia.org/wiki/Bzip2){ target="_blank" }
## CAB

!!! success "Fully supported"

    === "Description"

        Microsoft Cabinet (CAB) archive files are used for compressed file storage and software installation.

        ---

        - **Handler type:** Archive
        - **Vendor:** Microsoft

    === "References"

        - [Microsoft Cabinet File Format Documentation](https://en.wikipedia.org/wiki/Cabinet_(file_format)){ target="_blank" }
        - [Ubuntu Manual - cabextract](https://manpages.ubuntu.com/manpages/focal/man1/cabextract.1.html){ target="_blank" }
## compress

!!! success "Fully supported"

    === "Description"

        Unix compress files use the Lempel-Ziv-Welch (LZW) algorithm for data compression and are identified by a 2-byte magic number (0x1F 0x9D). This format supports optional block compression and variable bit lengths ranging from 9 to 16 bits.

        ---

        - **Handler type:** Compression
        

    === "References"

        - [Unix Compress File Format Documentation](https://fuchsia.googlesource.com/third_party/wuffs/+/HEAD/std/lzw/README.md){ target="_blank" }
        - [LZW Compression Algorithm](https://en.wikipedia.org/wiki/Lempel%E2%80%93Ziv%E2%80%93Welch){ target="_blank" }
## CPIO (binary)

!!! success "Fully supported"

    === "Description"

        CPIO (Copy In, Copy Out) is an archive file format used for bundling files and directories along with their metadata. It is commonly used in Unix-like systems for creating backups or transferring files, and supports various encoding formats including binary and ASCII.

        ---

        - **Handler type:** Archive
        

    === "References"

        - [GNU CPIO Manual](https://www.gnu.org/software/cpio/manual/cpio.html){ target="_blank" }
## CPIO (portable ASCII CRC)

!!! success "Fully supported"

    === "Description"

        CPIO (Copy In, Copy Out) is an archive file format used for bundling files and directories along with their metadata. It is commonly used in Unix-like systems for creating backups or transferring files, and supports various encoding formats including binary and ASCII.

        ---

        - **Handler type:** Archive
        

    === "References"

        - [GNU CPIO Manual](https://www.gnu.org/software/cpio/manual/cpio.html){ target="_blank" }
## CPIO (portable ASCII)

!!! success "Fully supported"

    === "Description"

        CPIO (Copy In, Copy Out) is an archive file format used for bundling files and directories along with their metadata. It is commonly used in Unix-like systems for creating backups or transferring files, and supports various encoding formats including binary and ASCII.

        ---

        - **Handler type:** Archive
        

    === "References"

        - [GNU CPIO Manual](https://www.gnu.org/software/cpio/manual/cpio.html){ target="_blank" }
## CPIO (portable old ASCII)

!!! success "Fully supported"

    === "Description"

        CPIO (Copy In, Copy Out) is an archive file format used for bundling files and directories along with their metadata. It is commonly used in Unix-like systems for creating backups or transferring files, and supports various encoding formats including binary and ASCII.

        ---

        - **Handler type:** Archive
        

    === "References"

        - [GNU CPIO Manual](https://www.gnu.org/software/cpio/manual/cpio.html){ target="_blank" }
## CramFS

!!! success "Fully supported"

    === "Description"

        CramFS is a lightweight, read-only file system format designed for simplicity and efficiency in embedded systems. It uses zlib compression for file data and stores metadata in a compact, contiguous structure.

        ---

        - **Handler type:** FileSystem
        

    === "References"

        - [CramFS Documentation](https://web.archive.org/web/20160304053532/http://sourceforge.net/projects/cramfs/){ target="_blank" }
        - [CramFS Wikipedia](https://en.wikipedia.org/wiki/Cramfs){ target="_blank" }
## D-Link Alpha encimg V1 Firmware

!!! success "Fully supported"

    === "Description"

        Encrypted firmware images found in D-Link DIR devices manufactured by Alpha Networks.Uses AES-256-CBC encryption with device-specific keys.

        ---

        - **Handler type:** Archive
        - **Vendor:** D-Link

    === "References"

        - [OpenWRT forum](https://forum.openwrt.org/t/adding-openwrt-support-for-d-link-dir-x1860-mt7621-mt7915-ax1800/106500){ target="_blank" }
        - [delink tool](https://github.com/devttys0/delink/blob/main/src/encimg.rs){ target="_blank" }
## D-Link Alpha encimg v2 Firmware

!!! success "Fully supported"

    === "Description"

        Encrypted firmware images found in D-Link DIR devices manufactured by Alpha Networks.Uses AES-256-CBC encryption with device-specific keys.Unlike the other variant, this one uses a prepended unencrypted WRGG03 header.

        ---

        - **Handler type:** Archive
        - **Vendor:** D-Link

    === "References"

        - [OpenWRT Wiki](https://openwrt.org/toh/d-link/d-link_dap_series_of_business_access_points#old_generation_dap-2xxxdap-3xxx_built_by_alpha_networks){ target="_blank" }
        - [delink tool](https://github.com/devttys0/delink/blob/main/src/encimg.rs){ target="_blank" }
## D-Link DEAFBEAD

!!! success "Fully supported"

    === "Description"

        Archive files as found in D-Link DSL-500G and DSL-504G firmware images.

        ---

        - **Handler type:** Archive
        - **Vendor:** D-Link

    === "References"
## D-Link encrpted_img

!!! success "Fully supported"

    === "Description"

        A binary format used by D-Link to store encrypted firmware or data. It consists of a custom 12-byte magic header followed by the encrypted payload.

        ---

        - **Handler type:** Archive
        - **Vendor:** D-Link

    === "References"

        - [How-To: Extracting Decryption Keys for D-Link](https://www.onekey.com/resource/extracting-decryption-keys-dlink){ target="_blank" }
## D-Link FPKG

!!! success "Fully supported"

    === "Description"

        CPKG and FPKG are archive formats used in D-Link DFL firewall firmware

        ---

        - **Handler type:** Archive
        - **Vendor:** D-Link

    === "References"
## D-Link SHRS

!!! success "Fully supported"

    === "Description"

        SHRS is a D-Link firmware format with a custom header containing metadata, SHA-512 digests, and AES-CBC encryption parameters. The firmware data is encrypted using a fixed key and IV stored in the header.

        ---

        - **Handler type:** Archive
        - **Vendor:** D-Link

    === "References"

        - [Breaking the D-Link DIR3060 Firmware Encryption - Recon - Part 1](https://0x00sec.org/t/breaking-the-d-link-dir3060-firmware-encryption-recon-part-1/21943){ target="_blank" }
## DMG

!!! success "Fully supported"

    === "Description"

        Apple Disk Image (DMG) files are commonly used on macOS for software distribution and disk image storage.

        ---

        - **Handler type:** Archive
        - **Vendor:** Apple

    === "References"

        - [Apple Disk Image Format Documentation](http://newosxbook.com/DMG.html){ target="_blank" }
## ELF (32-bit)

!!! success "Fully supported"

    === "Description"

        The 32-bit ELF (Executable and Linkable Format) is a binary file format used for executables, object code, shared libraries, and core dumps. It supports 32-bit addressing and includes headers for program and section information.

        ---

        - **Handler type:** Executable
        

    === "References"

        - [ELF File Format Specification](https://refspecs.linuxfoundation.org/elf/elf.pdf){ target="_blank" }
        - [ELF Wikipedia](https://en.wikipedia.org/wiki/Executable_and_Linkable_Format){ target="_blank" }
## ELF (64-bit)

!!! success "Fully supported"

    === "Description"

        The 64-bit ELF (Executable and Linkable Format) is a binary file format used for executables, object code, shared libraries, and core dumps. It supports 64-bit addressing and includes headers for program and section information.

        ---

        - **Handler type:** Executable
        

    === "References"

        - [ELF File Format Specification](https://refspecs.linuxfoundation.org/elf/elf.pdf){ target="_blank" }
        - [ELF Wikipedia](https://en.wikipedia.org/wiki/Executable_and_Linkable_Format){ target="_blank" }
## Engenius

!!! warning "Partially supported"

    === "Description"

        Engenius firmware files contain a custom header with metadata, followed by encrypted data using an XOR cipher.

        ---

        - **Handler type:** Archive
        - **Vendor:** Engenius

    === "References"

        - [enfringement - Tools for working with EnGenius WiFi hardware.](https://github.com/ryancdotorg/enfringement){ target="_blank" }

    === "Limitations"

        - Does not support all firmware versions.
## ExtFS

!!! success "Fully supported"

    === "Description"

        ExtFS (Ext2/Ext3/Ext4) is a family of journaling file systems commonly used in Linux-based operating systems. It supports features like large file sizes, extended attributes, and journaling for improved reliability.

        ---

        - **Handler type:** FileSystem
        

    === "References"

        - [Ext4 Documentation](https://www.kernel.org/doc/html/latest/filesystems/ext4/index.html){ target="_blank" }
        - [ExtFS Wikipedia](https://en.wikipedia.org/wiki/Ext4){ target="_blank" }
## FAT

!!! success "Fully supported"

    === "Description"

        FAT (File Allocation Table) is a file system format used for organizing and managing files on storage devices, supporting FAT12, FAT16, and FAT32 variants. It uses a table to map file clusters, enabling efficient file storage and retrieval.

        ---

        - **Handler type:** FileSystem
        

    === "References"

        - [FAT Wikipedia](https://en.wikipedia.org/wiki/File_Allocation_Table){ target="_blank" }
## GZIP

!!! success "Fully supported"

    === "Description"

        GZIP is a compressed file format that uses the DEFLATE algorithm and includes metadata such as original file name and modification time. It is commonly used for efficient file storage and transfer.

        ---

        - **Handler type:** Compression
        

    === "References"

        - [GZIP File Format Specification](https://datatracker.ietf.org/doc/html/rfc1952){ target="_blank" }
        - [GZIP Wikipedia](https://en.wikipedia.org/wiki/Gzip){ target="_blank" }
## GZIP (multi-volume)

!!! success "Fully supported"

    === "Description"

        GZIP is a compressed file format that uses the DEFLATE algorithm and includes metadata such as original file name and modification time. It is commonly used for efficient file storage and transfer.

        ---

        - **Handler type:** Compression
        

    === "References"

        - [GZIP File Format Specification](https://datatracker.ietf.org/doc/html/rfc1952){ target="_blank" }
        - [GZIP Wikipedia](https://en.wikipedia.org/wiki/Gzip){ target="_blank" }
## HP BDL

!!! success "Fully supported"

    === "Description"

        The HP BDL format is a firmware archive containing a custom header and a table of contents that specifies offsets and sizes of embedded firmware components. It includes metadata such as release, brand, device ID, version, and revision.

        ---

        - **Handler type:** Archive
        - **Vendor:** HP

    === "References"

        - [hpbdl](https://github.com/tylerwhall/hpbdl){ target="_blank" }
## HP IPKG

!!! success "Fully supported"

    === "Description"

        HP IPKG firmware archives consist of a custom header, followed by a table of contents and file entries. Each entry specifies metadata such as file name, offset, size, and CRC32 checksum.

        ---

        - **Handler type:** Archive
        - **Vendor:** HP

    === "References"

        - [hpbdl](https://github.com/tylerwhall/hpbdl){ target="_blank" }
## Instar BNEG

!!! success "Fully supported"

    === "Description"

        BNEG firmware files consist of a custom header followed by two partitions containing firmware components. The header specifies metadata such as magic value, version, and partition sizes.

        ---

        - **Handler type:** Archive
        - **Vendor:** Instar

    === "References"
## Instar HD

!!! success "Fully supported"

    === "Description"

        Instar HD firmware files are modified ZIP archives with non-standard local file headers, central directory headers, and end-of-central-directory records. These modifications include custom magic bytes to differentiate them from standard ZIP files.

        ---

        - **Handler type:** Archive
        - **Vendor:** Instar

    === "References"
## ISO 9660

!!! success "Fully supported"

    === "Description"

        ISO 9660 is a file system standard for optical disc media, defining a volume descriptor structure and directory hierarchy. It is widely used for CD-ROMs and supports cross-platform compatibility.

        ---

        - **Handler type:** FileSystem
        

    === "References"

        - [ISO 9660 Specification](https://wiki.osdev.org/ISO_9660){ target="_blank" }
        - [ISO 9660 Wikipedia](https://en.wikipedia.org/wiki/ISO_9660){ target="_blank" }
## JFFS2 (new)

!!! success "Fully supported"

    === "Description"

        JFFS2 (Journaling Flash File System version 2) is a log-structured file system for flash memory devices, using an older magic number to identify its nodes. It organizes data into nodes with headers containing metadata and CRC checks for integrity.

        ---

        - **Handler type:** FileSystem
        

    === "References"

        - [JFFS2 Documentation](https://sourceware.org/jffs2/){ target="_blank" }
        - [JFFS2 Wikipedia](https://en.wikipedia.org/wiki/JFFS2){ target="_blank" }
## JFFS2 (old)

!!! success "Fully supported"

    === "Description"

        JFFS2 (Journaling Flash File System version 2) is a log-structured file system for flash memory devices, using an older magic number to identify its nodes. It organizes data into nodes with headers containing metadata and CRC checks for integrity.

        ---

        - **Handler type:** FileSystem
        

    === "References"

        - [JFFS2 Documentation](https://sourceware.org/jffs2/){ target="_blank" }
        - [JFFS2 Wikipedia](https://en.wikipedia.org/wiki/JFFS2){ target="_blank" }
## LZ4

!!! success "Fully supported"

    === "Description"

        LZ4 is a high-speed lossless compression algorithm designed for real-time data compression with minimal memory usage.

        ---

        - **Handler type:** Compression
        

    === "References"

        - [LZ4 Frame Format Documentation](https://github.com/lz4/lz4/blob/dev/doc/lz4_Frame_format.md){ target="_blank" }
        - [LZ4 Wikipedia](https://en.wikipedia.org/wiki/LZ4_(compression_algorithm)){ target="_blank" }
## LZ4 (legacy)

!!! success "Fully supported"

    === "Description"

        LZ4 legacy format is an older framing format used prior to the LZ4 Frame specification, featuring a simpler structure and no support for skippable frames or extensive metadata. Unlike the default LZ4 Frame format, it lacks built-in checksums, versioning, or block independence flags, making it less robust and primarily used for backward compatibility.

        ---

        - **Handler type:** Compression
        

    === "References"

        - [LZ4 Frame Format Documentation](https://github.com/lz4/lz4/blob/dev/doc/lz4_Frame_format.md){ target="_blank" }
        - [LZ4 Wikipedia](https://en.wikipedia.org/wiki/LZ4_(compression_algorithm)){ target="_blank" }
## LZ4 (skippable)

!!! success "Fully supported"

    === "Description"

        LZ4 skippable format is designed to encapsulate arbitrary data within an LZ4 stream allowing compliant parsers to skip over it safely. This format does not contain compressed data itself but is often used for embedding metadata or non-LZ4 content alongside standard frames.

        ---

        - **Handler type:** Compression
        

    === "References"

        - [LZ4 Frame Format Documentation](https://github.com/lz4/lz4/blob/dev/doc/lz4_Frame_format.md){ target="_blank" }
        - [LZ4 Wikipedia](https://en.wikipedia.org/wiki/LZ4_(compression_algorithm)){ target="_blank" }
## LZH

!!! success "Fully supported"

    === "Description"

        LZH is a legacy archive format that uses various compression methods such as '-lh0-' and '-lh5-'. It was widely used in Japan and on older systems for compressing and archiving files.

        ---

        - **Handler type:** Compression
        

    === "References"

        - [LZH Compression Format](https://en.wikipedia.org/wiki/LHA_(file_format)){ target="_blank" }
## Lzip

!!! success "Fully supported"

    === "Description"

        Lzip is a lossless compressed file format based on the LZMA algorithm. It features a simple header, CRC-checked integrity, and efficient compression for large files.

        ---

        - **Handler type:** Compression
        

    === "References"

        - [Lzip File Format Documentation](https://www.nongnu.org/lzip/manual/lzip_manual.html){ target="_blank" }
        - [Lzip Wikipedia](https://en.wikipedia.org/wiki/Lzip){ target="_blank" }
## LZMA

!!! success "Fully supported"

    === "Description"

        LZMA is a compression format based on the Lempel-Ziv-Markov chain algorithm, offering high compression ratios and efficient decompression. It is commonly used in standalone `.lzma` files and embedded in other formats like 7z.

        ---

        - **Handler type:** Compression
        

    === "References"

        - [LZMA File Format Documentation](https://tukaani.org/xz/lzma.txt){ target="_blank" }
        - [LZMA Wikipedia](https://en.wikipedia.org/wiki/Lempel%E2%80%93Ziv%E2%80%93Markov_chain_algorithm){ target="_blank" }
## LZO

!!! success "Fully supported"

    === "Description"

        LZO is a data compression format featuring a simple header structure and optional checksum verification. It is optimized for fast decompression and supports various compression levels and flags for additional metadata.

        ---

        - **Handler type:** Compression
        

    === "References"

        - [LZO File Format Documentation](http://www.lzop.org/){ target="_blank" }
        - [LZO Wikipedia](https://en.wikipedia.org/wiki/Lempel%E2%80%93Ziv%E2%80%93Oberhumer){ target="_blank" }
## MSI

!!! warning "Partially supported"

    === "Description"

        Microsoft Installer (MSI) files are used for the installation, maintenance, and removal of software.

        ---

        - **Handler type:** Archive
        - **Vendor:** Microsoft

    === "References"

        - [MSI File Format Documentation](https://docs.microsoft.com/en-us/windows/win32/msi/overview-of-windows-installer){ target="_blank" }
        - [Compound File Binary Format](https://en.wikipedia.org/wiki/Compound_File_Binary_Format){ target="_blank" }

    === "Limitations"

        - Limited to CFB based extraction, not full-on MSI extraction
        - Extracted files have names coming from CFB internal representation, and may not correspond to the one they would have on disk after running the installer
## multi-sevenzip

!!! success "Fully supported"

    === "Description"

        The 7-Zip file format is a compressed archive format with high compression ratios, supporting multiple algorithms, CRC checks, and multi-volume archives.

        ---

        - **Handler type:** Archive
        

    === "References"

        - [7-Zip Technical Documentation](https://fastapi.metacpan.org/source/BJOERN/Compress-Deflate7-1.0/7zip/DOC/7zFormat.txt){ target="_blank" }
## Netgear CHK

!!! success "Fully supported"

    === "Description"

        Netgear CHK firmware files consist of a custom header containing metadata and checksums, followed by kernel and root filesystem partitions. The header includes fields for partition sizes, checksums, and a board identifier.

        ---

        - **Handler type:** Archive
        - **Vendor:** Netgear

    === "References"

        - [CHK Image Format Image Builder Tool for the R7800 Series](https://github.com/Getnear/R7800/blob/master/tools/firmware-utils/src/mkchkimg.c){ target="_blank" }
## Netgear TRX v1

!!! success "Fully supported"

    === "Description"

        Netgear TRX v1 firmware format includes a custom header with partition offsets and a CRC32 checksum for integrity verification. It supports up to three partitions defined in the header.

        ---

        - **Handler type:** Archive
        - **Vendor:** Netgear

    === "References"
## Netgear TRX v2

!!! success "Fully supported"

    === "Description"

        Netgear TRX v2 firmware format includes a custom header with partition offsets and a CRC32 checksum for integrity verification. It supports up to four partitions defined in the header.

        ---

        - **Handler type:** Archive
        - **Vendor:** Netgear

    === "References"
## NTFS

!!! success "Fully supported"

    === "Description"

        NTFS (New Technology File System) is a proprietary file system developed by Microsoft, featuring metadata support, advanced data structures, and journaling for reliability. It is commonly used in Windows operating systems for efficient storage and retrieval of files.

        ---

        - **Handler type:** FileSystem
        - **Vendor:** Microsoft

    === "References"

        - [NTFS Wikipedia](https://en.wikipedia.org/wiki/NTFS){ target="_blank" }
## PAR2 (multi-volume)

!!! success "Fully supported"

    === "Description"

        Parchive or PAR2, is a format for creating redundant data that helps detect and repair corrupted files. These archives typically accompany split-file sets (like multi-volume RAR or ZIP archives). Each PAR2 file is composed of multiple 'packets'.

        ---

        - **Handler type:** Archive
        

    === "References"

        - [Parchive Documentation](https://parchive.github.io/){ target="_blank" }
## Partclone

!!! success "Fully supported"

    === "Description"

        Partclone is a utility used for backing up and restoring partitions. Many cloning tools (such as Clonezilla) rely on it to create block-level images that include filesystem metadata.

        ---

        - **Handler type:** Archive
        

    === "References"

        - [Partclone GitHub Repository](https://github.com/Thomas-Tsai/partclone){ target="_blank" }
        - [Clonezilla Official Documentation](https://clonezilla.org/){ target="_blank" }
## QNAP NAS

!!! success "Fully supported"

    === "Description"

        QNAP NAS firmware files consist of a custom header, encrypted data sections, and a footer marking the end of the encrypted stream. The header contains metadata such as device ID, firmware version, and encryption details.

        ---

        - **Handler type:** Archive
        - **Vendor:** QNAP

    === "References"
## RAR

!!! warning "Partially supported"

    === "Description"

        RAR archive files are commonly used for compressed data storage. They can contain multiple files and directories, and support various compression methods.

        ---

        - **Handler type:** Archive
        

    === "References"

        - [RAR 4.x File Format Documentation](https://codedread.github.io/bitjs/docs/unrar.html){ target="_blank" }
        - [RAR 5.x File Format Documentation](https://www.rarlab.com/technote.htm#rarsign){ target="_blank" }

    === "Limitations"

        - Does not support encrypted RAR files.
## RomFS

!!! success "Fully supported"

    === "Description"

        RomFS is a simple, space-efficient, read-only file system format designed for embedded systems. It features 16-byte alignment, minimal metadata overhead, and supports basic file types like directories, files, symlinks, and devices.

        ---

        - **Handler type:** FileSystem
        

    === "References"

        - [RomFS Documentation](https://www.kernel.org/doc/html/latest/filesystems/romfs.html){ target="_blank" }
        - [RomFS Wikipedia](https://en.wikipedia.org/wiki/Romfs){ target="_blank" }
## SquashFS (v1)

!!! success "Fully supported"

    === "Description"

        SquashFS version 1 is a compressed, read-only file system format designed for minimal storage usage. It is commonly used in embedded systems and early Linux distributions.

        ---

        - **Handler type:** FileSystem
        

    === "References"

        - [SquashFS Documentation](https://dr-emann.github.io/squashfs/){ target="_blank" }
        - [SquashFS Wikipedia](https://en.wikipedia.org/wiki/SquashFS){ target="_blank" }
## SquashFS (v2)

!!! success "Fully supported"

    === "Description"

        SquashFS version 2 is a compressed, read-only file system format designed for minimal storage usage. It builds upon version 1 with additional features and improvements for embedded systems and Linux distributions.

        ---

        - **Handler type:** FileSystem
        

    === "References"

        - [SquashFS Documentation](https://dr-emann.github.io/squashfs/){ target="_blank" }
        - [SquashFS Wikipedia](https://en.wikipedia.org/wiki/SquashFS){ target="_blank" }
## SquashFS (v2-non-standard)

!!! success "Fully supported"

    === "Description"

        SquashFS version 2 is a compressed, read-only file system format designed for minimal storage usage. It is commonly used in embedded systems and early Linux distributions.

        ---

        - **Handler type:** FileSystem
        

    === "References"

        - [SquashFS Documentation](https://dr-emann.github.io/squashfs/){ target="_blank" }
        - [SquashFS Wikipedia](https://en.wikipedia.org/wiki/SquashFS){ target="_blank" }
## SquashFS (v3)

!!! success "Fully supported"

    === "Description"

        SquashFS version 3 is a compressed, read-only file system format designed for minimal storage usage. It is widely used in embedded systems and Linux distributions for efficient storage and fast access.

        ---

        - **Handler type:** FileSystem
        

    === "References"

        - [SquashFS Documentation](https://dr-emann.github.io/squashfs/){ target="_blank" }
        - [SquashFS Wikipedia](https://en.wikipedia.org/wiki/SquashFS){ target="_blank" }
## SquashFS (v3-Broadcom)

!!! success "Fully supported"

    === "Description"

        SquashFS version 3 Broadcom is a variant of the SquashFS v3 format used in Broadcom firmware. It features a unique magic number and may include specific optimizations for Broadcom devices.

        ---

        - **Handler type:** FileSystem
        - **Vendor:** Broadcom

    === "References"

        - [SquashFS Documentation](https://dr-emann.github.io/squashfs/){ target="_blank" }
        - [SquashFS Wikipedia](https://en.wikipedia.org/wiki/SquashFS){ target="_blank" }
## SquashFS (v3-DDWRT)

!!! success "Fully supported"

    === "Description"

        SquashFS version 3 DD-WRT is a variant of the SquashFS v3 format used in DD-WRT firmware. It features a unique magic number and may include specific optimizations for embedded systems.

        ---

        - **Handler type:** FileSystem
        - **Vendor:** DDWRT

    === "References"

        - [SquashFS Documentation](https://dr-emann.github.io/squashfs/){ target="_blank" }
        - [SquashFS Wikipedia](https://en.wikipedia.org/wiki/SquashFS){ target="_blank" }
## SquashFS (v3-non-standard)

!!! success "Fully supported"

    === "Description"

        SquashFS version 3 is a compressed, read-only file system format designed for minimal storage usage. It is widely used in embedded systems and Linux distributions for efficient storage and fast access.

        ---

        - **Handler type:** FileSystem
        - **Vendor:** unknown

    === "References"

        - [SquashFS Documentation](https://dr-emann.github.io/squashfs/){ target="_blank" }
        - [SquashFS Wikipedia](https://en.wikipedia.org/wiki/SquashFS){ target="_blank" }
## SquashFS (v4-BE)

!!! success "Fully supported"

    === "Description"

        SquashFS version 4 is a compressed, read-only file system format designed for minimal storage usage and fast access. It supports both big-endian and little-endian formats and is widely used in embedded systems and Linux distributions.

        ---

        - **Handler type:** FileSystem
        

    === "References"

        - [SquashFS Documentation](https://dr-emann.github.io/squashfs/){ target="_blank" }
        - [SquashFS Wikipedia](https://en.wikipedia.org/wiki/SquashFS){ target="_blank" }
## SquashFS (v4-broadcom)

!!! success "Fully supported"

    === "Description"

        SquashFS version 4 is a compressed, read-only file system format designed for minimal storage usage. It is widely used in embedded systems and Linux distributions for efficient storage and fast access.

        ---

        - **Handler type:** FileSystem
        - **Vendor:** Broadcom

    === "References"

        - [SquashFS Documentation](https://dr-emann.github.io/squashfs/){ target="_blank" }
        - [SquashFS Wikipedia](https://en.wikipedia.org/wiki/SquashFS){ target="_blank" }
## SquashFS (v4-LE)

!!! success "Fully supported"

    === "Description"

        SquashFS version 4 is a compressed, read-only file system format designed for minimal storage usage and fast access. It is widely used in embedded systems and Linux distributions for efficient storage management.

        ---

        - **Handler type:** FileSystem
        

    === "References"

        - [SquashFS Documentation](https://dr-emann.github.io/squashfs/){ target="_blank" }
        - [SquashFS Wikipedia](https://en.wikipedia.org/wiki/SquashFS){ target="_blank" }
## Stuffit SIT

!!! success "Fully supported"

    === "Description"

        StuffIt SIT archives is a legacy compressed archive format commonly used on macOS and earlier Apple systems.

        ---

        - **Handler type:** Archive
        - **Vendor:** StuffIt Technologies

    === "References"

        - [StuffIt SIT File Format Documentation](https://en.wikipedia.org/wiki/StuffIt){ target="_blank" }
## Stuffit SIT (v5)

!!! success "Fully supported"

    === "Description"

        StuffIt SIT archives is a legacy compressed archive format commonly used on macOS and earlier Apple systems.

        ---

        - **Handler type:** Archive
        - **Vendor:** StuffIt Technologies

    === "References"

        - [StuffIt SIT File Format Documentation](https://en.wikipedia.org/wiki/StuffIt){ target="_blank" }
## TAR (Unix)

!!! success "Fully supported"

    === "Description"

        Unix tar files are a widely used archive format for storing files and directories with metadata.

        ---

        - **Handler type:** Archive
        

    === "References"

        - [Unix Tar Format Documentation](https://en.wikipedia.org/wiki/Tar_(computing)){ target="_blank" }
        - [GNU Tar Manual](https://www.gnu.org/software/tar/manual/){ target="_blank" }
## TAR (USTAR)

!!! success "Fully supported"

    === "Description"

        USTAR (Uniform Standard Tape Archive) tar files are extensions of the original tar format with additional metadata fields.

        ---

        - **Handler type:** Archive
        

    === "References"

        - [USTAR Format Documentation](https://en.wikipedia.org/wiki/Tar_(computing)#USTAR_format){ target="_blank" }
        - [POSIX Tar Format Specification](https://pubs.opengroup.org/onlinepubs/9699919799/utilities/pax.html){ target="_blank" }
## UBI

!!! success "Fully supported"

    === "Description"

        UBI (Unsorted Block Image) is a volume management system for raw flash devices, providing wear leveling and bad block management. It operates as a layer between the MTD subsystem and higher-level filesystems like UBIFS.

        ---

        - **Handler type:** FileSystem
        

    === "References"

        - [UBI Documentation](https://www.kernel.org/doc/html/latest/driver-api/ubi.html){ target="_blank" }
        - [UBI Wikipedia](https://en.wikipedia.org/wiki/UBIFS#UBI){ target="_blank" }
## UBIFS

!!! success "Fully supported"

    === "Description"

        UBIFS (Unsorted Block Image File System) is a flash file system designed for raw flash memory, providing wear leveling, error correction, and power failure resilience. It operates on top of UBI volumes, which manage flash blocks on raw NAND or NOR flash devices.

        ---

        - **Handler type:** FileSystem
        

    === "References"

        - [UBIFS Documentation](https://www.kernel.org/doc/html/latest/filesystems/ubifs.html){ target="_blank" }
        - [UBIFS Wikipedia](https://en.wikipedia.org/wiki/UBIFS){ target="_blank" }
## UZIP

!!! success "Fully supported"

    === "Description"

        FreeBSD UZIP is a block-based compressed disk image format. It uses a table of contents to index compressed blocks, supporting ZLIB, LZMA, and ZSTD compression algorithms.

        ---

        - **Handler type:** Compression
        - **Vendor:** FreeBSD

    === "References"

        - [FreeBSD UZIP Documentation](https://github.com/freebsd/freebsd-src/tree/master/sys/geom/uzip){ target="_blank" }
## Xiaomi HDR1

!!! success "Fully supported"

    === "Description"

        Xiaomi HDR1 firmware files feature a custom header containing metadata, CRC32 checksum, and blob offsets for embedded data. These files are used in Xiaomi devices for firmware updates.

        ---

        - **Handler type:** Archive
        - **Vendor:** Xiaomi

    === "References"
## Xiaomi HDR2

!!! success "Fully supported"

    === "Description"

        Xiaomi HDR2 firmware files feature a custom header with metadata, CRC32 checksum, and blob offsets for embedded data. These files also include additional fields for device ID and region information.

        ---

        - **Handler type:** Archive
        - **Vendor:** Xiaomi

    === "References"
## XZ

!!! success "Fully supported"

    === "Description"

        XZ is a compressed file format that uses the LZMA2 algorithm for high compression efficiency. It is designed for general-purpose data compression with support for integrity checks and padding for alignment.

        ---

        - **Handler type:** Compression
        

    === "References"

        - [XZ File Format Specification](https://tukaani.org/xz/xz-file-format-1.0.4.txt){ target="_blank" }
        - [XZ Wikipedia](https://en.wikipedia.org/wiki/XZ_Utils){ target="_blank" }
## YAFFS

!!! success "Fully supported"

    === "Description"

        YAFFS (Yet Another Flash File System) is a log-structured file system designed for NAND flash memory, storing data in fixed-size chunks with associated metadata. It supports features like wear leveling, error correction, and efficient handling of power loss scenarios.

        ---

        - **Handler type:** FileSystem
        

    === "References"

        - [YAFFS Documentation](https://yaffs.net/){ target="_blank" }
        - [YAFFS Wikipedia](https://en.wikipedia.org/wiki/YAFFS){ target="_blank" }
## ZIP

!!! warning "Partially supported"

    === "Description"

        ZIP is a widely used archive file format that supports multiple compression methods, file spanning, and optional encryption. It includes metadata such as file names, sizes, and timestamps, and supports both standard and ZIP64 extensions for large files.

        ---

        - **Handler type:** Archive
        

    === "References"

        - [ZIP File Format Specification](https://pkware.com/documents/casestudies/APPNOTE.TXT){ target="_blank" }
        - [ZIP64 Format Specification](https://pkware.cachefly.net/webdocs/APPNOTE/APPNOTE-6.3.1.TXT){ target="_blank" }

    === "Limitations"

        - Does not support encrypted ZIP files.
## zlib

!!! success "Fully supported"

    === "Description"

        The zlib format is a compressed data format based on the DEFLATE algorithm, often used for data compression in various applications. It includes a lightweight header and checksum for data integrity.

        ---

        - **Handler type:** Compression
        

    === "References"

        - [zlib File Format Specification](https://www.zlib.net/manual.html){ target="_blank" }
        - [zlib Wikipedia](https://en.wikipedia.org/wiki/Zlib){ target="_blank" }
## ZSTD

!!! success "Fully supported"

    === "Description"

        Zstandard (ZSTD) is a fast lossless compression algorithm with high compression ratios, designed for modern data storage and transfer. Its file format includes a frame structure with optional dictionary support and checksums for data integrity.

        ---

        - **Handler type:** Compression
        

    === "References"

        - [Zstandard File Format Specification](https://facebook.github.io/zstd/zstd_manual.html){ target="_blank" }
        - [Zstandard Wikipedia](https://en.wikipedia.org/wiki/Zstandard){ target="_blank" }
