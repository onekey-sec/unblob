#[cfg_attr(target_os = "linux", path = "linux.rs")]
#[cfg_attr(not(target_os = "linux"), path = "unsupported.rs")]
mod sandbox_impl;

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

#[pyo3::pymodule(submodule, module = "unblob._rust", name = "sandbox")]
pub mod python {
    use pyo3::{prelude::*, types::PyTuple};
    use std::path::PathBuf;

    use super::{sandbox_impl, AccessFS};

    mod exceptions {
        pyo3::create_exception!(
            unblob._rust.sandbox,
            SandboxError,
            pyo3::exceptions::PyException
        );
    }

    #[pymodule_export]
    use self::exceptions::SandboxError;

    /// Enforces access restrictions
    #[pyfunction]
    #[pyo3(signature = (*rules: "AccessFS"))]
    fn restrict_access(rules: &Bound<'_, PyTuple>) -> PyResult<()> {
        sandbox_impl::restrict_access(
            &rules
                .iter()
                .map(|r| Ok(r.extract::<PyAccessFS>()?.access))
                .collect::<PyResult<Vec<_>>>()?,
        )
        .map_err(|err| SandboxError::new_err((SandboxErrorKind::from(&err), err.to_string())))
    }

    #[pyclass(eq, eq_int)]
    #[derive(PartialEq)]
    enum SandboxErrorKind {
        NotImplemented,
        NotEnforced,
        Unknown,
    }

    impl From<&super::SandboxError> for SandboxErrorKind {
        fn from(value: &super::SandboxError) -> Self {
            #[allow(unreachable_patterns)]
            // There are conditional pattern variants that may not exist
            match value {
                super::SandboxError::NotImplemented => Self::NotImplemented,
                super::SandboxError::NotEnforced => Self::NotEnforced,
                _ => Self::Unknown,
            }
        }
    }

    #[pyclass(from_py_object, name = "AccessFS")]
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
}
