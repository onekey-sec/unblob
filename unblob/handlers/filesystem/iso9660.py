from typing import Optional

from structlog import get_logger

from unblob.extractors import Command
from unblob.file_utils import Endian

from ...models import File, HexString, StructHandler, ValidChunk

logger = get_logger()


# The system area, the first 32,768 data bytes of the disc (16 sectors of 2,048 bytes each),
# is unused by ISO 9660 and therefore available for other uses.
SYSTEM_AREA_SIZE = 0x8000


def from_733(u: bytes) -> int:
    """Convert from ISO 9660 7.3.3 format to uint32_t.

    Return the little-endian part always, to handle non-specs-compliant images.
    """
    return u[0] | (u[1] << 8) | (u[2] << 16) | (u[3] << 24)


def from_723(u: bytes) -> int:
    """Convert from ISO 9660 7.2.3 format to uint16_t.

    Return the little-endian part always, to handle non-specs-compliant images.
    """
    return u[0] | (u[1] << 8)


class ISO9660FSHandler(StructHandler):
    NAME = "iso9660"

    #
    # Match on volume descriptor type, followed by ISO_STANDARD_ID, which corresponds to the beginning of a volume descriptor.
    #
    # Volume descriptor types can be:
    #     - 0x00	Boot record volume descriptor
    #     - 0x01	Primary volume descriptor
    #     - 0x02	Supplementary volume descriptor, or enhanced volume descriptor
    #     - 0x03	Volume partition descriptor
    #     - 0xFF Volume descriptor terminator

    PATTERNS = [
        HexString(
            "( 00 | 01 | 02 | 03 ) 43 44 30 30 31 // vd_type + 'CD001' (ISO_STANDARD_ID within primary volume descriptor)"
        )
    ]

    C_DEFINITIONS = r"""
        typedef struct iso9660_dtime_s {
            uint8 dt_year;
            uint8 dt_month;
            uint8 dt_day;
            uint8 dt_hour;
            uint8 dt_minute;
            uint8 dt_second;
            int8 dt_gmtoff;
        } iso9660_dtime_t;

        typedef struct iso9660_ltime_s {
            char lt_year[4];
            char lt_month[2];
            char lt_day[2];
            char lt_hour[2];
            char lt_minute[2];
            char lt_second[2];
            char lt_hsecond[2];
            int8 lt_gmtoff;
        } iso9660_ltime_t;

        typedef struct iso9660_dir_s {
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

        typedef struct iso9660_pvd_s {
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
        } iso9660_pvd_t;
    """

    HEADER_STRUCT = "iso9660_pvd_t"

    EXTRACTOR = Command("7z", "x", "-y", "{inpath}", "-o{outdir}")

    def calculate_chunk(self, file: File, start_offset: int) -> Optional[ValidChunk]:
        header = self.parse_header(file, Endian.LITTLE)
        size = from_733(header.volume_space_size) * from_723(header.logical_block_size)

        # We need to substract the system area given that we matched on volume descriptor,
        # which is the first struct afterward.
        real_start_offset = start_offset - SYSTEM_AREA_SIZE
        if real_start_offset < 0:
            logger.warning("Invalid ISO 9660 file", offset=real_start_offset, size=size)
            return None

        return ValidChunk(
            start_offset=real_start_offset,
            end_offset=real_start_offset + size,
        )
