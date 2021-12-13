pub(crate) mod math;

use pyo3::prelude::*;

/// Calculates Shannon entropy of data
#[pyfunction(text_signature = "(data)")]
pub fn shannon_entropy(data: &[u8]) -> PyResult<f64> {
    Ok(math::shannon_entropy(data))
}

/// Performance sensitive functionality
#[pymodule]
fn _rust(_py: Python, m: &PyModule) -> PyResult<()> {
    m.add_function(wrap_pyfunction!(shannon_entropy, m)?)?;
    Ok(())
}
