import io
from typing import List, Union

from structlog import get_logger

from ...file_utils import Endian
from ...models import StructHandler, UnknownChunk, ValidChunk

logger = get_logger()

# There are several varieties of StuffIt file:
#
# Original with "SIT!" magic
#   https://apple2.org.za/gswv/a2zine/GS.WorldView/Resources/The.MacShrinkIt.Project/ARCHIVES.TXT
#
# StuffIt 5 with "StuffIt (c)1997-\xFF\xFF\xFF\xFF Aladdin Systems, Inc., http://www.aladdinsys.com/StuffIt/\x0d\x0a" magic
#   Can see the header structure in The Unarchiver source code (XADMaster\XADStuffIt5Parser.m line 29).
#
# StuffIt X with "StuffIt!" or "StuffIt?" magic
#   http://fileformats.archiveteam.org/wiki/StuffIt_X#Identification
#
# The Unarchiver supports all these, the source is available at
#   https://cdn.theunarchiver.com/downloads/TheUnarchiverSource.zip
#
#
# There is also others (TODO):
#
# StuffIt Deluxe with "SITD" magic
#   Mentioned in libmagic definitions (StuffIt Deluxe (data)). But not supported by The Uniarchiver!


class StuffItSITHandler(StructHandler):
    NAME = "stuffit"

    YARA_RULE = r"""
        strings:
            // "SIT!\\x00", then 6 bytes (uint16 number of files and uint32 size), then "rLau".
            $sit_magic = { 53 49 54 21 [6] 72 4C 61 75 }
        condition:
            $sit_magic
    """

    # http://www.mit.edu/afs.new/athena/contrib/potluck/src/unstuffit/unsit.c
    C_DEFINITIONS = r"""
        struct sit_header
        {
            char signature[4];
            uint16 num_files;
            uint32 archive_length;
            char signature2[4];
        };
    """
    HEADER_STRUCT = "sit_header"

    def calculate_chunk(
        self, file: io.BufferedIOBase, start_offset: int
    ) -> Union[ValidChunk, UnknownChunk]:

        header = self.parse_header(file, endian=Endian.BIG)

        return ValidChunk(
            start_offset=start_offset,
            end_offset=start_offset + header.archive_length,
        )

    @staticmethod
    def make_extract_command(inpath: str, outdir: str) -> List[str]:
        return ["unar", inpath, "-o", outdir]


class StuffIt5Handler(StructHandler):
    NAME = "stuffit5"

    YARA_RULE = r"""
        strings:
            // "StuffIt (c)1997-"
            $stuffit5_magic = { 53 74 75 66 66 49 74 20 28 63 29 31 39 39 37 2D }
        condition:
            $stuffit5_magic
    """

    # TheUnarchiver XADMaster\XADStuffIt5Parser.m
    C_DEFINITIONS = r"""
        struct stuffit5_header
        {
            char signature[80];
            uint32 unknown;
            uint32 archive_length;
            uint32 entry_offset;
            uint16 num_root_dir_entries;
            uint32 first_entry_offset;
        };
    """
    HEADER_STRUCT = "stuffit5_header"

    def calculate_chunk(
        self, file: io.BufferedIOBase, start_offset: int
    ) -> Union[ValidChunk, UnknownChunk]:

        header = self.parse_header(file, endian=Endian.BIG)

        return ValidChunk(
            start_offset=start_offset,
            end_offset=start_offset + header.archive_length,
        )

    @staticmethod
    def make_extract_command(inpath: str, outdir: str) -> List[str]:
        return ["unar", inpath, "-o", outdir]


class StuffItXHandler(StructHandler):
    NAME = "stuffitx"

    YARA_RULE = r"""
        strings:
            // "StuffIt!" or "StuffIt?"
            $stuffitx_magic = { 53 74 75 66 66 49 74 (21 | 5C) }
        condition:
            $stuffitx_magic
    """

    # Info from TheUnarchiver XADMaster\XADStuffItXParser.m:recognizeFileWithHandle()
    C_DEFINITIONS = r"""
        struct stuffitx_header
        {
            char signature[7];
            char encoding_marker;
        };

        // XADMaster\XADStuffItXParser.m
        struct stuffitx_element {
            int something;
            int type;
            int64 attribs[10];
            int64 alglist[6];
            int64 alglist3_extra;
            int64 dataoffset;
            int64 actualsize;
            uint32 datacrc;
        };
    """
    HEADER_STRUCT = "stuffitx_header"

    def calculate_chunk(
        self, file: io.BufferedIOBase, start_offset: int
    ) -> Union[ValidChunk, UnknownChunk]:

        header = self.parse_header(file)

        if header.encoding_marker == b"?":
            # If the encoding marker is "?", TheUnarchiver won't support it.
            # From XADMaster\XADStuffItXParser.m:
            # """
            #   // The file has been encoded using a base-N encoder.
            #   // TODO: Support these encodings.
            # """
            logger.debug(
                f"Found StuffIt X file at 0x{start_offset:x} with base-N encoding, which unar doesn't support."
            )
            return

        logger.debug(
            "Identified StuffIt X, but don't have a calculate_chunk() procedure yet."
        )

        return

    @staticmethod
    def make_extract_command(inpath: str, outdir: str) -> List[str]:
        # TODO: The Unarchiver DOES support this, but we need to test once we have a
        # solid calculate_chunk() procedure.
        return ["unar", inpath, "-o", outdir]


class StuffItDeluxeHandler(StructHandler):
    NAME = "stuffit_deluxe"

    # TODO: Is SITD header "SITD", then 6 bytes, then "rLau". Same as the SIT!?
    YARA_RULE = r"""
        strings:

            $sitd_magic = { 53 49 54 44 }
        condition:
            $sitd_magic
    """

    C_DEFINITIONS = r"""
        struct sitd_header
        {
            // TODO
        };
    """
    HEADER_STRUCT = "sit_header"

    def calculate_chunk(
        self, file: io.BufferedIOBase, start_offset: int
    ) -> Union[ValidChunk, UnknownChunk]:

        logger.debug(
            "Found something which might be a StuffIt Deluxe, but we don't have a calculate_chunk() procedure yet."
        )

        return

    @staticmethod
    def make_extract_command(inpath: str, outdir: str) -> List[str]:
        # TODO: The Unarchiver doesn't seem to support this, what does?
        return []
