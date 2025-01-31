use crate::sandbox::{AccessFS, SandboxError};

pub fn restrict_access(_access_rules: &[AccessFS]) -> Result<(), SandboxError> {
    Err(SandboxError::NotImplemented)?
}
