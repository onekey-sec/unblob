import os
import textwrap

BUILD_RUST_EXTENSION = bool(os.environ.get("UNBLOB_BUILD_RUST_EXTENSION", False))
RUST_DEBUG = bool(os.environ.get("UNBLOB_RUST_DEBUG", False))

try:
    from setuptools_rust import Binding, RustExtension
except ModuleNotFoundError:
    if BUILD_RUST_EXTENSION:
        print(
            textwrap.dedent(
                """
                ####################### WARNING ######################
                Required dependency, setuptools-rust cannot be found.
                It can be installed by issuing =poetry install= first.
                ####################### WARNING ######################
                """
            )
        )
        raise


def build(setup_kwargs):
    if not BUILD_RUST_EXTENSION:
        return

    rust_extensions = [
        RustExtension(
            target="unblob._rust",
            debug=RUST_DEBUG,
            path="rust/Cargo.toml",
            binding=Binding.PyO3,
            py_limited_api=True,
            features=["pyo3/abi3-py38", "pyo3/extension-module"],
        )
    ]

    setup_kwargs.update(
        {
            "rust_extensions": rust_extensions,
            "zip_safe": False,  # Extension modules are not ZIP-safe by desing
        }
    )
