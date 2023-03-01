import pytest
from pytest import approx

import unblob._py as python_binding

try:
    import unblob._rust as rust_binding  # type: ignore
except ModuleNotFoundError:
    rust_binding = None


@pytest.fixture(
    params=[
        pytest.param(python_binding, id="Python"),
        pytest.param(
            rust_binding,
            id="Rust",
            marks=pytest.mark.skipif(
                rust_binding is None, reason="Rust binding is not present"
            ),
        ),
    ]
)
def binding(request):
    yield request.param


@pytest.mark.parametrize(
    "data, entropy",
    (
        pytest.param(b"", 0, id="empty"),
        pytest.param(b"\x00", 0, id="0 bit"),
        pytest.param(b"\x01\x01\x00\x00", 1.0, id="1 bit small"),
        pytest.param(b"\x01\x01\x00\x00" * 1000, 1.0, id="1 bit large"),
        pytest.param(b"\x00\x01\x02\x03", 2.0, id="2 bits"),
    ),
)
def test_shannon_entropy(binding, data, entropy):
    assert binding.shannon_entropy(data) == approx(entropy)
