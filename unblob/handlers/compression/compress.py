"""Unix compress'ed chunk identification.

We identify the end offset of any identified unix compress'ed chunk by
performing Lempel-Ziv-Welch decompression on a chunk starting from the
identified start offset, and ending at the end of the whole file being
analyzed.

If we reach an invalid code or the stream ends in the middle of a
code, we do not recursively call the decompression with -1 size,
rather just fail on the chunk as we have seen too many false-positives
picked up by this heuristic.

Once the decompression procedure works without errors, that means we
have a valid chunk and can return its current end offset.

We use a small heuristic to return the right end offset.  This
heuristic tends to work well when arbitrary data appended at the end
of the stream is made of random bytes (no repeating letters, no large
set of ASCII letters).

It obviously can be wrong from time to time, leading to a compress'ed
chunk that we can decompress (obviously), but uncompressed data will
contain garbage bytes at the end.

Sadly, there is no way we can identify with 100% probability the end
offset of a compress'ed stream with byte precision if it is followed
by other content.

The good news is that because of this behavior, it's highly unlikely
we will observe compress'ed chunks followed by other chunks in the
wild.  The only ones I observed were followed by null bytes sentinels,
which helps identifying the exact end offset.
"""
import io
from typing import List, Optional

from structlog import get_logger

from unblob.extractors import Command

from ...file_utils import Endian, InvalidInputFormat, convert_int8, convert_int16
from ...models import File, HexString, StructHandler, ValidChunk

logger = get_logger()


class UnixCompressHandler(StructHandler):
    NAME = "compress"

    PATTERNS = [
        # reference: https://fuchsia.googlesource.com/third_party/wuffs/+/HEAD/std/lzw/README.md
        HexString("1f 9d")
    ]

    C_DEFINITIONS = r"""
        struct compress_header {
            char magic[2];              // compress signature/magic number
            uint8 flags;                // blocks = flags&0x80, bits = flags&0x1f
        };
    """
    HEADER_STRUCT = "compress_header"

    EXTRACTOR = Command("7z", "x", "-y", "{inpath}", "-so", stdout="lzw.uncompressed")

    def unlzw(self, file: File, start_offset: int, max_len: int) -> int:  # noqa: C901
        """Calculate the end of a unix compress stream.

        It performs decompression on a stream read from <file> from
        <start_offset> up until <max_len>.

        Adapted from Brandon Owen works
        (https://github.com/umeat/unlzw).

        Adapted from original work by Mark Adler - orginal copyright
        notice below

        Copyright (C) 2014, 2015 Mark Adler This software is provided
        'as-is', without any express or implied warranty.  In no event
        will the authors be held liable for any damages arising from
        the use of this software.  Permission is granted to anyone to
        use this software for any purpose, including commercial
        applications, and to alter it and redistribute it freely,
        subject to the following restrictions:

            1. The origin of this software must not be misrepresented;
               you must not claim that you wrote the original
               software.  If you use this software in a product, an
               acknowledgment in the product documentation would be
               appreciated but is not required.

            2. Altered source versions must be plainly marked as such,
               and must not be misrepresented as being the original
               software.

            3. This notice may not be removed or altered from any
               source distribution.  Mark Adler
               madler@alumni.caltech.edu
        """
        file.seek(start_offset)

        prefix: List[int] = [0] * 65536  # index to LZW prefix string

        header = self.parse_header(file, Endian.LITTLE)

        if header.flags & 0x60:
            raise InvalidInputFormat("Flag & 0x60")

        max_ = header.flags & 0x1F
        if not (9 <= max_ <= 16):
            raise InvalidInputFormat("Invalid max")

        if max_ == 9:
            max_ = 10  # 9 doesn't really mean 9

        block_compressed = header.flags & 0x80
        end = 256 if block_compressed else 255

        # Clear table, start at nine bits per symbol
        bits_per_symbol = 9
        mask = 0x1FF
        code = 0

        # Set up: get the first 9-bit code, which is the first decompressed byte,
        # but don't create a table entry until the next code

        buf = convert_int16(file.read(2), Endian.LITTLE)
        prev = buf & mask  # code
        buf >>= bits_per_symbol
        left = 16 - bits_per_symbol
        if prev > 255:
            raise InvalidInputFormat("Invalid Data: First code must be a literal")

        # Decode codes
        mark = 3  # start of compressed data
        nxt = 5  # consumed five bytes so far
        while nxt < max_len:
            # If the table will be full after this, increment the code size
            if (end >= mask) and (bits_per_symbol < max_):
                # Flush unused input bits and bytes to next 8*bits bit boundary
                # (this is a vestigial aspect of the compressed data format
                # derived from an implementation that made use of a special VAX
                # machine instruction!)
                remaining_bits = (nxt - mark) % bits_per_symbol

                if remaining_bits:
                    remaining_bits = bits_per_symbol - remaining_bits
                    if remaining_bits >= max_len - nxt:
                        break
                    nxt += remaining_bits

                buf = left = 0

                # mark this new location for computing the next flush
                mark = nxt

                # increment the number of bits per symbol
                bits_per_symbol += 1
                mask <<= 1
                mask += 1

            # Get a code of bits bits
            buf += convert_int8(file.read(1), Endian.LITTLE) << left
            nxt += 1
            left += 8
            if left < bits_per_symbol:
                if nxt == max_len:
                    raise InvalidInputFormat(
                        "Invalid Data: Stream ended in the middle of a code",
                    )
                buf += convert_int8(file.read(1), Endian.LITTLE) << left
                nxt += 1

                left += 8
            code = buf & mask
            buf >>= bits_per_symbol
            left -= bits_per_symbol

            # process clear code (256)
            if (code == 256) and block_compressed:
                # Flush unused input bits and bytes to next 8*bits bit boundary
                remaining_bits = (nxt - mark) % bits_per_symbol
                if remaining_bits:
                    remaining_bits = bits_per_symbol - remaining_bits
                    if remaining_bits > max_len - nxt:
                        break
                    nxt += remaining_bits
                buf = left = 0

                # Mark this location for computing the next flush
                mark = nxt

                # Go back to nine bits per symbol
                bits_per_symbol = 9  # initialize bits and mask
                mask = 0x1FF
                end = 255  # empty table
                continue  # get next code

            # Process LZW code
            temp = code  # save the current code

            # Special code to reuse last match
            if code > end:
                # Be picky on the allowed code here, and make sure that the
                # code we drop through (prev) will be a valid index so that
                # random input does not cause an exception
                if (code != end + 1) or (prev > end):
                    raise InvalidInputFormat("Invalid Data: Invalid code detected")
                code = prev

            # Walk through linked list to generate output in reverse order
            while code >= 256:
                code = prefix[code]

            # Link new table entry
            if end < mask:
                end += 1
                prefix[end] = prev

            # Set previous code for next iteration
            prev = temp

        if code == nxt - 1:
            return file.tell()

        return file.tell() - 1

    def calculate_chunk(self, file: File, start_offset: int) -> Optional[ValidChunk]:
        file.seek(0, io.SEEK_END)
        max_len = file.tell()

        end_offset = self.unlzw(file, start_offset, max_len)

        chunk_length = end_offset - start_offset
        if chunk_length <= 5:
            raise InvalidInputFormat("Compressed chunk is too short")

        return ValidChunk(
            start_offset=start_offset,
            end_offset=end_offset,
        )
