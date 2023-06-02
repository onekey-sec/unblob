use pyo3::prelude::*;

pub fn shannon_entropy(data: &[u8]) -> f64 {
    let mut entropy = 0.0;
    let mut counts = [0; 256];

    for &b in data {
        counts[b as usize] += 1;
    }

    for &count in &counts {
        if count == 0 {
            continue;
        }

        let p = count as f64 / data.len() as f64;
        entropy -= p * p.log2();
    }

    entropy
}
/// Calculates Shannon entropy of data
#[pyfunction(text_signature = "(data)", name = "shannon_entropy")]
pub fn py_shannon_entropy(py: Python, data: &[u8]) -> PyResult<f64> {
    py.allow_threads(|| Ok(shannon_entropy(data)))
}

pub fn init_module(py: Python, root_module: &PyModule) -> PyResult<()> {
    let module = PyModule::new(py, "math_tools")?;
    module.add_function(wrap_pyfunction!(py_shannon_entropy, module)?)?;

    root_module.add_submodule(module)?;

    py.import("sys")?
        .getattr("modules")?
        .set_item("unblob_native.math", module)?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use approx::assert_relative_eq;

    use super::*;

    #[test]
    fn test_shannon_entropy() {
        let input = b"000111"; // 50% entropy distribution ~ 1 bit information

        assert_relative_eq!(shannon_entropy(input), 1.0);
    }
}
