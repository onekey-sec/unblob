pub mod math_tools;

use pyo3::prelude::*;

/// Performance-critical functionality
#[pymodule]
fn _native(py: Python, m: &PyModule) -> PyResult<()> {
    math_tools::init_module(py, m)?;

    Ok(())
}
