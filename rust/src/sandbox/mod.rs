#[cfg_attr(target_os = "linux", path = "linux.rs")]
#[cfg_attr(not(target_os = "linux"), path = "unsupported.rs")]
mod sandbox_impl;

use pyo3::{create_exception, exceptions::PyException, prelude::*, types::PyTuple};
use std::path::PathBuf;
use thiserror::Error;

#[derive(Clone, Debug)]
pub enum AccessFS {
    Read(PathBuf),
    ReadWrite(PathBuf),
    MakeReg(PathBuf),
    MakeDir(PathBuf),
    RemoveDir(PathBuf),
    RemoveFile(PathBuf),
}

#[derive(Debug, Error)]
#[non_exhaustive]
pub enum SandboxError {
    #[error("Sandboxing is not implemented on this system")]
    NotImplemented,
    #[error("Could not enforce sandbox restrictions")]
    NotEnforced,
    #[cfg(target_os = "linux")]
    #[error(transparent)]
    LandlockError(#[from] landlock::RulesetError),
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
    .map_err(|err| PySandboxError::new_err((PySandboxErrorKind::from(&err), err.to_string())))
}

create_exception!(unblob_native.sandbox, PySandboxError, PyException);

#[pyclass(eq, eq_int, name = "SandboxErrorKind")]
#[derive(PartialEq)]
enum PySandboxErrorKind {
    NotImplemented,
    NotEnforced,
    Unknown,
}

impl From<&SandboxError> for PySandboxErrorKind {
    fn from(value: &SandboxError) -> Self {
        #[allow(unreachable_patterns)] // There are conditional pattern variants that may not exist
        match value {
            SandboxError::NotImplemented => Self::NotImplemented,
            SandboxError::NotEnforced => Self::NotEnforced,
            _ => Self::Unknown,
        }
    }
}

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

    #[staticmethod]
    fn remove_dir(dir: PathBuf) -> Self {
        Self::new(AccessFS::RemoveDir(dir))
    }

    #[staticmethod]
    fn remove_file(dir: PathBuf) -> Self {
        Self::new(AccessFS::RemoveFile(dir))
    }
}

pub fn init_module(root_module: &Bound<'_, PyModule>) -> PyResult<()> {
    let module = PyModule::new_bound(root_module.py(), "sandbox")?;
    module.add_function(wrap_pyfunction!(py_restrict_access, &module)?)?;
    module.add_class::<PyAccessFS>()?;
    module.add(
        "SandboxError",
        root_module.py().get_type_bound::<PySandboxError>(),
    )?;

    root_module.add_submodule(&module)?;
    root_module
        .py()
        .import_bound("sys")?
        .getattr("modules")?
        .set_item("unblob._rust.sandbox", module)?;

    Ok(())
}
