pub mod math;

use pyo3::prelude::*;

/// Calculates Shannon entropy of data
#[pyfunction(text_signature = "(data)")]
pub fn shannon_entropy(py: Python, data: &[u8]) -> PyResult<f64> {
    py.allow_threads(|| Ok(math::shannon_entropy(data)))
}

/// Performance-critical functionality
#[pymodule]
fn _native(py: Python, m: &PyModule) -> PyResult<()> {
    let math_module = PyModule::new(py, "math_tools")?;
    math_module.add_function(wrap_pyfunction!(shannon_entropy, math_module)?)?;

    m.add_submodule(math_module)?;
    Ok(())
}
