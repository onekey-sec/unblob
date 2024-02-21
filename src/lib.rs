pub mod math_tools;
pub mod sandbox;

use pyo3::prelude::*;

/// Performance-critical functionality
#[pymodule]
fn _native(py: Python, m: &PyModule) -> PyResult<()> {
    math_tools::init_module(py, m)?;
    sandbox::init_module(py, m)?;

    pyo3_log::init();

    Ok(())
}
