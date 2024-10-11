#[cfg_attr(target_os = "linux", path = "linux.rs")]
#[cfg_attr(not(target_os = "linux"), path = "unsupported.rs")]
mod sandbox_impl;

use pyo3::{create_exception, exceptions::PyException, prelude::*, types::PyTuple};
use std::path::PathBuf;

#[derive(Clone, Debug)]
pub enum AccessFS {
    Read(PathBuf),
    ReadWrite(PathBuf),
    MakeReg(PathBuf),
    MakeDir(PathBuf),
}

/// Enforces access restrictions
#[pyfunction(name = "restrict_access", signature=(*rules))]
fn py_restrict_access(rules: &Bound<'_, PyTuple>) -> PyResult<()> {
    sandbox_impl::restrict_access(
        &rules
            .iter()
            .map(|r| Ok(r.extract::<PyAccessFS>()?.access))
            .collect::<PyResult<Vec<_>>>()?,
    )
    .map_err(|err| SandboxError::new_err(err.to_string()))
}

create_exception!(unblob_native.sandbox, SandboxError, PyException);

#[pyclass(name = "AccessFS", module = "unblob_native.sandbox")]
#[derive(Clone)]
struct PyAccessFS {
    access: AccessFS,
}

impl PyAccessFS {
    fn new(access: AccessFS) -> Self {
        Self { access }
    }
}

#[pymethods]
impl PyAccessFS {
    #[staticmethod]
    fn read(dir: PathBuf) -> Self {
        Self::new(AccessFS::Read(dir))
    }

    #[staticmethod]
    fn read_write(dir: PathBuf) -> Self {
        Self::new(AccessFS::ReadWrite(dir))
    }

    #[staticmethod]
    fn make_reg(dir: PathBuf) -> Self {
        Self::new(AccessFS::MakeReg(dir))
    }

    #[staticmethod]
    fn make_dir(dir: PathBuf) -> Self {
        Self::new(AccessFS::MakeDir(dir))
    }
}

pub fn init_module(root_module: &Bound<'_, PyModule>) -> PyResult<()> {
    let module = PyModule::new_bound(root_module.py(), "sandbox")?;
    module.add_function(wrap_pyfunction!(py_restrict_access, &module)?)?;
    module.add_class::<PyAccessFS>()?;
    module.add(
        "SandboxError",
        root_module.py().get_type_bound::<SandboxError>(),
    )?;

    root_module.add_submodule(&module)?;
    root_module
        .py()
        .import_bound("sys")?
        .getattr("modules")?
        .set_item("unblob_native.sandbox", module)?;

    Ok(())
}
