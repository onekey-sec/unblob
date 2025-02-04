import pytest

from unblob._rust import math_tools

UNIFORM_DISTRIBUTION = bytes(x for x in range(256))
NON_UNIFORM_DISTRIBUTION = bytes([0] * 256)


@pytest.mark.parametrize(
    "data,entropy",
    [
        pytest.param(b"", 0, id="empty"),
        pytest.param(b"\x00", 0, id="0 bit"),
        pytest.param(b"\x01\x01\x00\x00", 1.0, id="1 bit small"),
        pytest.param(b"\x01\x01\x00\x00" * 1000, 1.0, id="1 bit large"),
        pytest.param(b"\x00\x01\x02\x03", 2.0, id="2 bits"),
    ],
)
def test_shannon_entropy(data: bytes, entropy: float):
    assert math_tools.shannon_entropy(data) == pytest.approx(entropy)


@pytest.mark.parametrize(
    "data,chi_square_value",
    [
        pytest.param(b"", 0, id="empty"),
        pytest.param(UNIFORM_DISTRIBUTION, 1.0, id="uniform distribution"),
        pytest.param(NON_UNIFORM_DISTRIBUTION, 0.0, id="non uniform distribution"),
        pytest.param(
            UNIFORM_DISTRIBUTION + NON_UNIFORM_DISTRIBUTION,
            0.0,
            id="partially uniform distribution",
        ),
    ],
)
def test_chi_square_entropy(data: bytes, chi_square_value: float):
    assert math_tools.chi_square_probability(data) == pytest.approx(
        chi_square_value, abs=1e-4
    )
