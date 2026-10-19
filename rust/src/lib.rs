pub mod math_tools;
pub mod sandbox;

/// Performance-critical functionality
#[pyo3::pymodule]
mod _rust {
    use pyo3::{prelude::*, types::PyDict};

    #[pymodule_export]
    use crate::math_tools::python as math_tools;
    #[pymodule_export]
    use crate::sandbox::python as sandbox;

    #[pymodule_init]
    fn init(m: &Bound<'_, PyModule>) -> PyResult<()> {
        // Needed in order to get `import unblob._rust.<name>` work.
        let sys_modules = m
            .py()
            .import("sys")?
            .getattr("modules")?
            .cast_into::<PyDict>()?;
        for value in m.dict().values() {
            if let Ok(submodule) = value.cast::<PyModule>() {
                sys_modules.set_item(submodule.name()?, submodule)?;
            }
        }
        pyo3_log::init();
        Ok(())
    }
}
