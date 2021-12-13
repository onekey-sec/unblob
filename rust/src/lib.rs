use pyo3::prelude::*;

/// Function defined in Rust
#[pyfunction(text_signature = "(data)")]
pub fn hello_rust(name: &str) -> PyResult<String> {
    Ok(format!("Hello from Rust to you, {}", name))
}

#[pymodule]
fn _rust(_py: Python, m: &PyModule) -> PyResult<()> {
    m.add_function(wrap_pyfunction!(hello_rust, m)?)?;
    Ok(())
}
