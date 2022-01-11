pub(crate) mod bzip2;
pub(crate) mod math;
pub(crate) mod python;

use pyo3::prelude::*;

/// Calculates Shannon entropy of data
#[pyfunction(text_signature = "(data)")]
pub fn shannon_entropy(data: &[u8]) -> PyResult<f64> {
    Ok(math::shannon_entropy(data))
}

/// Get the end of a `bzip2` stream in a file
#[pyfunction(text_signature = "(file)")]
pub fn bzip2_recover(file: python::FileLike, start_offset: u64) -> PyResult<i64> {
    if let Some(end) = bzip2::bzip2_recover(file, start_offset)? {
        Ok(end as i64)
    } else {
        Ok(-1)
    }
}

/// Performance sensitive functionality
#[pymodule]
fn _rust(_py: Python, m: &PyModule) -> PyResult<()> {
    m.add_function(wrap_pyfunction!(shannon_entropy, m)?)?;
    m.add_function(wrap_pyfunction!(bzip2_recover, m)?)?;
    Ok(())
}
