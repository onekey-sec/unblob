import pytest

from unblob.handlers.compression._ucl import UCLDecompressor


@pytest.mark.parametrize(
    "compressed,expected_decompressed",
    [
        pytest.param(
            bytes([0x80, 0x41, 0x00, 0x00, 0x00, 0x00, 0x02, 0x40, 0xFF]),
            b"A",
            id="literal-only",
        ),
        pytest.param(
            bytes([0xC0, 0x41, 0x41, 0x00, 0x00, 0x00, 0x00, 0x01, 0x20, 0xFF]),
            b"AA",
            id="decompress-with-match",
        ),
        pytest.param(
            bytes([0x94, 0x41, 0x00, 0x00, 0x00, 0x00, 0x00, 0x12, 0xFF]),
            b"AAA",
            id="decompress-with-repeated-match",
        ),
        pytest.param(
            bytes(
                [
                    0xFF,
                    0x48,
                    0x65,
                    0x6C,
                    0x6C,
                    0x6F,
                    0x20,
                    0x57,
                    0x6F,
                    0xFD,
                    0x72,
                    0x6C,
                    0x64,
                    0x20,
                    0x21,
                    0x20,
                    0x90,
                    0x0D,
                    0x20,
                    0x00,
                    0x00,
                    0x00,
                    0x00,
                    0x00,
                    0x90,
                    0xFF,
                ]
            ),
            b"Hello World ! Hello World ! Hello World !",
            id="decompress-with-repeated-match-complex",
        ),
    ],
)
def test_decompress_success(compressed: bytes, expected_decompressed: bytes):
    assert UCLDecompressor().decompress(compressed) == expected_decompressed


@pytest.mark.parametrize(
    "compressed,error_messsage",
    [
        pytest.param(
            b"",
            "Unexpected end of data",
            id="empty-data",
        ),
        pytest.param(
            bytes(
                [
                    0x00,  # No literals
                    0x60,
                    0x10,  # Match with a large offset that exceeds output size
                    0x00,
                    0xFF,
                    0xFF,
                    0xFF,
                    0xFF,  # End marker
                ]
            ),
            "Invalid match offset",
            id="invalid-match-offset",
        ),
        pytest.param(
            b"\x80",
            "Unexpected end of data",
            id="unexpected-end",
        ),
    ],
)
def test_decompress_failure(compressed, error_messsage):
    with pytest.raises(ValueError, match=error_messsage):
        UCLDecompressor().decompress(compressed)
