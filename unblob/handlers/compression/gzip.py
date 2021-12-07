import gzip
import io
import os
import re
from binascii import unhexlify
from typing import List, Optional

from structlog import get_logger

from unblob.file_utils import find_first_backwards

from ...models import StructHandler, ValidChunk

logger = get_logger()


# https://datatracker.ietf.org/doc/html/rfc1952
class GZIPHandler(StructHandler):
    NAME = "gzip"

    YARA_RULE = r"""
    strings:
        // id1 & id2
        // compression method (0x8 = DEFLATE)
        // flags, 00011111 (0x1f) is the highest since the first 3 bits are reserved
        // unix time
        // eXtra FLags
        // Operating System (RFC1952 describes 0-13, or 255)
        $gzip_magic = /\x1f\x8b\x08[\x00-\x1f][\x00-\xff]{4}[\x02\x04][\x00-\x0c\xff]/
    condition:
        $gzip_magic
    """

    C_DEFINITIONS = r"""
        struct gzip_struct {
            char id1;
            char id2;
            char compression_method;
            uint8 flags;
            uint32 modification_time;
            char extra_flags;
            uint8 os; // Operating system
        }

        struct gzip_footer {
            uint32 crc;
            uint32 decompressed_length;
        }
    """

    HEADER_STRUCT = "gzip_struct"

    def calculate_chunk(
        self, file: io.BufferedIOBase, start_offset: int
    ) -> Optional[ValidChunk]:

        try:
            # If this is just a valid gzip file, we should be able to just read it into a
            # gzip.py GzipFile, and just get the end offset like that. Easy!

            with gzip.open(file) as g:
                g.seek(0, os.SEEK_END)
            
            end_offset = file.tell()

            gzip_size = end_offset - start_offset

        except gzip.BadGzipFile as gze:

            # If the gzip segment doesn't end at the end of the file, gzip will try to continue
            # reading the next member and complain with something like:
            # Not a gzipped file (b'@\x00')
            # The two bytes here are what gzip tried to confirm were gzip "magic" bytes. Useful!
            # Unfortunately, the file.tell() at this particular moment is much further along than
            # the bytes that caused this error to be thrown. So, we have to search backwards, from
            # the existing file.tell(), for the two bytes that the error message tells us about.

            error_message = gze.args[0]

            if not error_message.startswith("Not a gzipped file"):
                logger.warning(
                    "Got BadGzipFile error that we don't know how to handle, this needs looking into."
                )
                return

            logger.debug(f"BadGzipFile error got raised: {error_message}.")

            # We need to convert the string representation of bytes to actual bytes we can use
            # to find in the actual stream.
            normalized_bytes_hint = self.error_string_to_bytes(error_message)

            raise_cursor_tell = file.tell()

            logger.debug(f"On raise, cursor is at 0x{raise_cursor_tell:x}")
            gzip_size = self.brute_force_gzip_with_bytes_hint(
                file, start_offset, raise_cursor_tell, normalized_bytes_hint
            )

            if gzip_size == -1:
                logger.warning(
                    "Couldn't figure out the gzip stream size with the bytes hint."
                )
                return

        # We have another issue here: gzip.GzipFile() will ingest all the null bytes after
        # the end of a gzip stream. So the file that gzip.GzipFile() returns to us will be
        # longer be than the actual gzip stream is. This isn't a problem for us until it
        # comes to extraction where, for example, 7z will complain about there being extra
        # data in the file after the gzip stream. Bad!
        # (See https://github.com/python/cpython/blob/ddbab69b6d44085564a9b5022b96b002a52b2f2b/Lib/gzip.py#L541)
        #
        # Here's some strategies to find the end of the stream that we _could_ do, but
        # shouldn't:
        #
        # We could calculate the CRC for the compressed file and compare it to the CRC at
        # the end of the stream. HOWEVER, we don't really want to rely on a CRCs in unblob.
        #
        # We could also check the size of the uncompressed file, and compare it to the
        # final size field at the end of the stream. HOWEVER, in testing, this final field
        # doesn't seem to be necessarily accurate in some cases. It's also not necessarily
        # used by 7z when doing extraction.
        #
        # So, to mitigate this issue, we just need to trim the trailing null bytes,
        # although not so far as to eat into any null bytes at the end of the length field.

        trimmed_size = self.trim_trailing_nulls(file, start_offset, gzip_size)

        end_offset = start_offset + trimmed_size

        return ValidChunk(
            start_offset=start_offset,
            end_offset=end_offset,
        )

    @staticmethod
    def trim_trailing_nulls(
        file: io.BufferedIOBase, start_offset: int, gzip_size: int
    ) -> int:
        while True:
            # gzip.py will tolerate extra nulls at the end, so we will loop until we get an
            # exception.
            file.seek(start_offset)
            gzip_data = io.BytesIO(file.read(gzip_size))
            try:
                with gzip.open(gzip_data) as g:
                    g.seek(0, os.SEEK_END)
            except Exception as e:
                logger.debug(e)
                logger.debug(
                    f"gzip threw an error with gzip size {gzip_size}, so trimmed size is {gzip_size + 1}"
                )
                return gzip_size + 1
            gzip_size = gzip_size - 1

    def brute_force_gzip_with_bytes_hint(
        self,
        file: io.BufferedIOBase,
        start_offset: int,
        end_offset: int,
        bytes_hint: bytes,
    ) -> int:

        logger.debug(f"Starting to try and find {bytes_hint} in the stream.")

        while True:
            file.seek(end_offset)
            found_hint = find_first_backwards(file, bytes_hint)

            if found_hint == -1:
                return -1

            if (end_offset - found_hint) < start_offset:
                logger.debug(
                    "Couldn't find the bytes hint within the start_offset -> end_offset range."
                )
                return -1

            logger.debug(
                f"Trying if the end of the gzip file where we found this hint (0x{end_offset - found_hint:x})."
            )

            file_size = (end_offset - found_hint) - start_offset
            logger.debug(f"Reading 0x{start_offset:x}-0x{start_offset+file_size:x}.")

            file.seek(start_offset)
            gzip_range = io.BytesIO(file.read(file_size))

            try:
                with gzip.open(gzip_range) as g:
                    inside_data = g.read()
                    size = len(inside_data)

                logger.debug(f"Size of the unpacked data will be 0x{size:x}.")
                logger.debug(f"Provisional gzip stream length is 0x{file_size:x}.")

                break

            except gzip.BadGzipFile as gze:
                logger.debug(f'Hit another BadGzipFile error ("{gze}"), continuing.')
                end_offset = end_offset - found_hint - len(bytes_hint)
                continue

            except Exception as err:
                logger.warning(f"Hit an unexpected kind of error here: {err}.")
                end_offset = end_offset - found_hint - len(bytes_hint)
                continue

        # If there's no exception raised, we can assume this is a good gzip chunk and
        # return.
        return file_size

    @staticmethod
    def error_string_to_bytes(error_message: str) -> bytes:
        error_bytes = re.search(r"Not a gzipped file \(b'([^']+)'\)", error_message)

        ret = b""

        for char in re.findall(r"(\\r|\\t|\\n|\\x[\w]{2}|[ -~])", error_bytes.group(1)):
            if char.startswith("\\x"):
                # Strings like "\\x01" etc
                ret += unhexlify(char[2:])
            elif char == "\\t":
                ret += b"\x09"
            elif char == "\\n":
                ret += b"\x0a"
            elif char == "\\r":
                ret += b"\x0d"
            else:
                ret += char.encode()

        return ret

    @staticmethod
    def make_extract_command(inpath: str, outdir: str) -> List[str]:
        return ["7z", "x", "-y", inpath, f"-o{outdir}"]
