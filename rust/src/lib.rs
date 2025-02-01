pub mod math_tools;
pub mod sandbox;

use pyo3::prelude::*;

/// Performance-critical functionality
#[pymodule]
fn _rust(m: &Bound<'_, PyModule>) -> PyResult<()> {
    math_tools::init_module(m)?;
    sandbox::init_module(m)?;

    pyo3_log::init();

    Ok(())
}
