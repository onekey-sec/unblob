import io
from typing import List, Optional

from structlog import get_logger

from unblob.file_utils import Endian

from ...models import StructHandler, ValidChunk

logger = get_logger()


# The system area, the first 32,768 data bytes of the disc (16 sectors of 2,048 bytes each),
# is unused by ISO 9660 and therefore available for other uses.
SYSTEM_AREA_SIZE = 0x8000


def from_733(u: bytes) -> int:
    """Convert from ISO 9660 7.3.3 format to uint32_t
    Return the little-endian part always, to handle non-specs-compliant images
    """
    return u[0] | (u[1] << 8) | (u[2] << 16) | (u[3] << 24)


def from_723(u: bytes) -> int:
    """Convert from ISO 9660 7.2.3 format to uint16_t
    Return the little-endian part always, to handle non-specs-compliant images.
    """
    return u[0] | (u[1] << 8)


class ISO9660FSHandler(StructHandler):

    NAME = "iso9660"

    YARA_RULE = r"""
        strings:
            /**
            Match on volume descriptor type, followed by ISO_STANDARD_ID, which corresponds to the beginning of a volume descriptor.

            Volume descriptor types can be:
                - 0x00	Boot record volume descriptor
                - 0x01	Primary volume descriptor
                - 0x02	Supplementary volume descriptor, or enhanced volume descriptor
                - 0x03	Volume partition descriptor
                - 0xFF Volume descriptor terminator
            */
            $iso9660_header = { ( 00 | 01 | 02 | 03 ) 43 44 30 30 31 } // vd_type + "CD001" (ISO_STANDARD_ID within primary volume descriptor)

        condition:
            $iso9660_header
    """

    C_DEFINITIONS = r"""
        struct iso9660_dtime_s {
            uint8 dt_year;
            uint8 dt_month;
            uint8 dt_day;
            uint8 dt_hour;
            uint8 dt_minute;
            uint8 dt_second;
            int8 dt_gmtoff;
        } iso9660_dtime_t;

        struct  iso9660_ltime_s {
            char lt_year[4];
            char lt_month[2];
            char lt_day[2];
            char lt_hour[2];
            char lt_minute[2];
            char lt_second[2];
            char lt_hsecond[2];
            int8 lt_gmtoff;
        } iso9660_ltime_t;

        struct iso9660_dir_s {
            uint8 length;
            uint8 xa_length;
            uint64 extent;
            uint64 size;
            iso9660_dtime_t recording_time;
            uint8 file_flags;
            uint8 file_unit_size;
            uint8 interleave_gap;
            uint32 volume_sequence_number;
            union {
            uint8 len;
            char str[1];
            } filename;
        } iso9660_dir_t;

        struct iso9660_pvd_s {
            uint8         type;                         /**< ISO_VD_PRIMARY - 1 */
            char             id[5];                        /**< ISO_STANDARD_ID "CD001"
                                                            */
            uint8         version;                      /**< value 1 for ECMA 119 */
            char             unused1[1];                   /**< unused - value 0 */
            char          system_id[32]; /**< each char is an achar */
            char          volume_id[32]; /**< each char is a dchar */
            uint8          unused2[8];                   /**< unused - value 0 */
            /**uint64         volume_space_size;            /**< total number of
                                                            sectors */
            uint8       volume_space_size[8];
            char          unused3[32];                  /**< unused - value 0 */
            uint32         volume_set_size;              /**< often 1 */
            uint32         volume_sequence_number;       /**< often 1 */
            uint8         logical_block_size[4];           /**< sector size, e.g. 2048 */

            // We don't need to parse any more from here, but keep it for future reference
            // uint64         path_table_size;              /**< bytes in path table */
            // uint32         type_l_path_table;            /**< first sector of L Path
            //                                                     Table */
            // uint32         opt_type_l_path_table;        /**< first sector of optional
            //                                                 L Path Table */
            // uint32         type_m_path_table;            /**< first sector of M Path
            //                                                 table */
            // uint32         opt_type_m_path_table;        /**< first sector of optional
            //                                                 M Path table */
            // iso9660_dir_t    root_directory_record;        /**< See 8.4.18 and
            //                                                 section 9.1 of
            //                                                 ISO 9660 spec. */
            // char             root_directory_filename;      /**< Is '\\0' or root
            //                                                 directory. Also pads previous
            //                                                 field to 34 bytes */
            // char          volume_set_id[128]; /**< Volume Set of
            //                                                         which the volume is
            //                                                         a member. See
            //                                                     section 8.4.19 */
            // char          publisher_id[128];  /**< Publisher of
            //                                                     volume. If the first
            //                                                     character is '_' 0x5F,
            //                                                     the remaining bytes
            //                                                     specify a file
            //                                                     containing the user.
            //                                                     If all bytes are " "
            //                                                     (0x20) no publisher
            //                                                     is specified. See
            //                                                     section 8.4.20 of
            //                                                     ECMA 119 */
            // char          preparer_id[128]; /**< preparer of
            //                                                     volume. If the first
            //                                                     character is '_' 0x5F,
            //                                                     the remaining bytes
            //                                                     specify a file
            //                                                     containing the user.
            //                                                     If all bytes are " "
            //                                                     (0x20) no preparer
            //                                                     is specified.
            //                                                     See section 8.4.21
            //                                                     of ECMA 119 */
            // char          application_id[128]; /**< application
            //                                                     use to create the
            //                                                     volume. If the first
            //                                                     character is '_' 0x5F,
            //                                                     the remaining bytes
            //                                                     specify a file
            //                                                     containing the user.
            //                                                     If all bytes are " "
            //                                                     (0x20) no application
            //                                                     is specified.
            //                                                     See section of 8.4.22
            //                                                     of ECMA 119 */
            // char          copyright_file_id[37];     /**< Name of file for
            //                                             copyright info. If
            //                                             all bytes are " "
            //                                             (0x20), then no file
            //                                             is identified.  See
            //                                             section 8.4.23 of ECMA 119
            //                                             9660 spec. */
            // char          abstract_file_id[37];      /**< See section 8.4.24 of
            //                                             ECMA 119. */
            // char          bibliographic_file_id[37]; /**< See section 7.5 of
            //                                             ISO 9660 spec. */
            // iso9660_ltime_t  creation_date;             /**< date and time of volume
            //                                             creation. See section 8.4.26.1
            //                                             of the ISO 9660 spec. */
            // iso9660_ltime_t  modification_date;         /**< date and time of the most
            //                                             recent modification.
            //                                             See section 8.4.27 of the
            //                                             ISO 9660 spec. */
            // iso9660_ltime_t  expiration_date;           /**< date and time when volume
            //                                             expires. See section 8.4.28
            //                                             of the ISO 9660 spec. */
            // iso9660_ltime_t  effective_date;            /**< date and time when volume
            //                                             is effective. See section
            //                                             8.4.29 of the ISO 9660
            //                                             spec. */
            // uint8         file_structure_version;    /**< value 1 for ECMA 119 */
            // uint8           unused4[1];                /**< unused - value 0 */
            // char             application_data[512];     /**< Application can put
            //                                             whatever it wants here. */
            // uint8          unused5[653];              /**< Unused - value 0 */
        } iso9660_pvd_t;
    """

    HEADER_STRUCT = "iso9660_pvd_t"

    def calculate_chunk(
        self, file: io.BufferedIOBase, start_offset: int
    ) -> Optional[ValidChunk]:
        header = self.parse_header(file, Endian.LITTLE)
        size = from_733(header.volume_space_size) * from_723(header.logical_block_size)

        # We need to substract the system area given that we matched on volume descriptor,
        # which is the first struct afterward.
        real_start_offset = start_offset - SYSTEM_AREA_SIZE
        if real_start_offset < 0:
            logger.warning("Invalid ISO 9660 file", offset=real_start_offset, size=size)
            return

        return ValidChunk(
            start_offset=real_start_offset,
            end_offset=real_start_offset + size,
        )

    @staticmethod
    def make_extract_command(inpath: str, outdir: str) -> List[str]:
        return ["7z", "x", inpath, f"-o{outdir}"]
