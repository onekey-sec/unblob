pub(crate) mod math;

use pyo3::prelude::*;

/// Calculates Shannon entropy of data
#[pyfunction(text_signature = "(data)")]
pub fn shannon_entropy(data: &[u8]) -> PyResult<f64> {
    Ok(math::shannon_entropy(data))
}

/// Performance-critical functionality
#[pymodule]
fn _native(py: Python, m: &PyModule) -> PyResult<()> {
    let math_module = PyModule::new(py, "math_tools")?;
    math_module.add_function(wrap_pyfunction!(shannon_entropy, math_module)?)?;

    m.add_submodule(math_module)?;
    Ok(())
}
