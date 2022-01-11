//! # Python interop helpers
//!
//! The Python interop library [PyO3](https://pyo3.rs) has a bunch of
//! helpers to seamlessly transform between Rust and Python data-types
//! but it is far from incomplete.
//!
//! This module contains additional type conversion definitions. As it
//! is impossible to extend externally defined types with externally
//! defined traits, this modue defines wrapper types to circumwent
//! this limitation. These wrappers can be converted to their standard
//! library conterparts.

use pyo3::{exceptions::PyTypeError, ffi, prelude::*};
use std::{
    io::{Error, Read, Seek},
    os::unix::prelude::FromRawFd,
};

/// Encodes arbitrary Python file like objects. If the file-like
/// object represents a real file, then it is converted to an
/// [`std::fs::File`] object providing low-owerhead file IO.
pub enum FileLike<'a> {
    File(std::fs::File),
    Other(PyFileLike<'a>),
}

/// Wraps an arbitrary readable and seekable file-like object
pub struct PyFileLike<'a> {
    read: &'a PyAny,
    seek: &'a PyAny,
}

impl<'a> TryFrom<&'a PyAny> for PyFileLike<'a> {
    type Error = PyErr;

    fn try_from(value: &'a PyAny) -> Result<Self, Self::Error> {
        let read = value.getattr("read")?;
        let seek = value.getattr("seek")?;
        Ok(PyFileLike { read, seek })
    }
}

impl<'a> Read for PyFileLike<'a> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        let result = self.read.call1((buf.len(),))?;
        let bytes: &[u8] = result.extract()?;
        buf[0..bytes.len()].copy_from_slice(bytes);
        Ok(bytes.len())
    }
}

impl<'a> Seek for PyFileLike<'a> {
    fn seek(&mut self, pos: std::io::SeekFrom) -> std::io::Result<u64> {
        let args = match pos {
            std::io::SeekFrom::Start(o) => (o as i64, 0),
            std::io::SeekFrom::Current(o) => (o, 1),
            std::io::SeekFrom::End(o) => (o, 2),
        };

        let result = self.seek.call1(args)?.extract()?;
        Ok(result)
    }
}

impl<'a> FileLike<'a> {
    fn from_other(file_like: &'a PyAny) -> PyResult<Self> {
        Ok(Self::Other(PyFileLike::try_from(file_like)?))
    }

    fn from_fd(fd: i32) -> PyResult<Self> {
        // Duplicate the file descriptor as we cannot transfer
        // ownership of a Python object to a Rust one. `std::fs::File`
        // assumes ownership to the contained fd.
        //
        // Unsafe because conversion is fallible. Returns `-1` on
        // error.
        //
        // F_DUPFD_CLOEXEC is passed to ensure that we don't leek the
        // allocated fd in child processes which would otherwise
        // inherit it.
        //
        // The 3rd argument is the lowest available file descriptor we
        // want. As we don't care about the actual number of the fd,
        // hence the 0.
        //
        // Reference:
        // [https://man7.org/linux/man-pages/man2/fcntl.2.html]
        // [https://www.gnu.org/software/libc/manual/html_node/Duplicating-Descriptors.html]
        let fd = unsafe { libc::fcntl(fd, libc::F_DUPFD_CLOEXEC, 0) };
        if fd == -1 {
            let errno = Error::last_os_error().raw_os_error();
            return Err(PyTypeError::new_err((
                "Dup failed for file descriptor",
                errno,
            )));
        }

        // Unsafe only if the wrapper is not the sole owner of the wrapped fd.
        let std_file = unsafe { std::fs::File::from_raw_fd(fd) };
        Ok(Self::File(std_file))
    }
}

impl<'a> Read for FileLike<'a> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        match self {
            Self::File(f) => f.read(buf),
            Self::Other(f) => f.read(buf),
        }
    }
}

impl<'a> Seek for FileLike<'a> {
    fn seek(&mut self, pos: std::io::SeekFrom) -> std::io::Result<u64> {
        match self {
            Self::File(f) => f.seek(pos),
            Self::Other(f) => f.seek(pos),
        }
    }
}

impl<'a> FromPyObject<'a> for FileLike<'a> {
    fn extract(file: &'a PyAny) -> PyResult<Self> {
        // Unsafe because conversion is fallible. Returns `-1` on error
        // Reference: [https://docs.python.org/3/c-api/file.html#c.PyObject_AsFileDescriptor]
        let fd = unsafe { ffi::PyObject_AsFileDescriptor(file.into_ptr()) };
        if fd != -1 {
            Self::from_fd(fd)
        } else {
            // Ok, let's assume it is not a real file and go-on.
            unsafe { ffi::PyErr_Clear() };
            Self::from_other(file)
        }
    }
}

#[cfg(test)]
mod tests {
    use pyo3::types::{IntoPyDict, PyBytes, PyString};
    use std::{
        error::Error,
        io::{Read, Write},
    };
    use tempfile::NamedTempFile;

    use super::*;

    #[test]
    fn test_rust_file_from_python_file_object() -> Result<(), Box<dyn Error>> {
        // Set up a real file on the file system with some real contents
        let test_file_contents = "Hello from Python!";
        let mut test_file = NamedTempFile::new()?;
        write!(test_file, "{}", test_file_contents)?;

        // Open the file a second time from an embedded Python
        // interpreter and convert it to a Rust file object...
        pyo3::prepare_freethreaded_python();
        Python::with_gil(|py| -> PyResult<()> {
            // Set the path to the test file as a local variable in the Python interpreter
            let locals = [(
                "testfile_path",
                PyString::new(py, test_file.path().to_str().unwrap()),
            )]
            .into_py_dict(py);

            // To get a Python file object...
            py.run(r#"py_fp = open(testfile_path, "rb")"#, None, Some(locals))?;

            // And a reference to it from Rust code...
            let py_fp = locals.get_item("py_fp").unwrap();

            let mut file_like: FileLike = py_fp.extract()?;
            let mut contents = String::new();
            file_like.read_to_string(&mut contents)?;

            assert_eq!(contents, test_file_contents);

            Ok(())
        })?;
        Ok(())
    }

    #[test]
    fn test_rust_file_from_python_bytesio_object() -> Result<(), Box<dyn Error>>
    {
        let test_file_contents = "Hello from Python!";
        pyo3::prepare_freethreaded_python();
        Python::with_gil(|py| -> PyResult<()> {
            // Set the path to the test file as a local variable in the Python interpreter
            let locals = [(
                "test_file_contents",
                PyBytes::new(py, test_file_contents.as_bytes()),
            )]
            .into_py_dict(py);

            // To get a Python file object...
            py.run(
                r#"import io; bytesio = io.BytesIO(test_file_contents)"#,
                None,
                Some(locals),
            )?;

            let bytes_io = locals.get_item("bytesio").unwrap();
            let mut file_like: FileLike = bytes_io.extract()?;
            let mut contents = String::new();
            file_like.read_to_string(&mut contents)?;

            assert_eq!(contents, test_file_contents);

            Ok(())
        })?;
        Ok(())
    }
}
