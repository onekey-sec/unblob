use crate::sandbox::AccessFS;

pub fn restrict_access(_access_rules: &[AccessFS]) -> Result<(), Box<dyn std::error::Error>> {
    Err("Sandboxing FS access is unavailable on this system")?
}
