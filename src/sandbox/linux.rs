use landlock::{
    path_beneath_rules, Access, AccessFs, Ruleset, RulesetAttr, RulesetCreatedAttr, RulesetStatus,
    ABI,
};
use log;

use std::path::Path;

use crate::sandbox::{AccessFS, SandboxError};

impl AccessFS {
    fn read(&self) -> Option<&Path> {
        if let Self::Read(path) = self {
            Some(path)
        } else {
            None
        }
    }

    fn read_write(&self) -> Option<&Path> {
        if let Self::ReadWrite(path) = self {
            Some(path)
        } else {
            None
        }
    }

    fn make_reg(&self) -> Option<&Path> {
        if let Self::MakeReg(path) = self {
            Some(path)
        } else {
            None
        }
    }

    fn make_dir(&self) -> Option<&Path> {
        if let Self::MakeDir(path) = self {
            Some(path)
        } else {
            None
        }
    }

    fn remove_dir(&self) -> Option<&Path> {
        if let Self::RemoveDir(path) = self {
            Some(path)
        } else {
            None
        }
    }

    fn remove_file(&self) -> Option<&Path> {
        if let Self::RemoveFile(path) = self {
            Some(path)
        } else {
            None
        }
    }
}

pub fn restrict_access(access_rules: &[AccessFS]) -> Result<(), SandboxError> {
    let abi = ABI::V2;

    let read_only: Vec<&Path> = access_rules.iter().filter_map(AccessFS::read).collect();

    let read_write: Vec<&Path> = access_rules
        .iter()
        .filter_map(AccessFS::read_write)
        .collect();

    let create_file: Vec<&Path> = access_rules.iter().filter_map(AccessFS::make_reg).collect();

    let create_directory: Vec<&Path> = access_rules.iter().filter_map(AccessFS::make_dir).collect();

    let remove_directory: Vec<&Path> = access_rules
        .iter()
        .filter_map(AccessFS::remove_dir)
        .collect();

    let remove_file: Vec<&Path> = access_rules
        .iter()
        .filter_map(AccessFS::remove_file)
        .collect();

    let status = Ruleset::default()
        .handle_access(AccessFs::from_all(abi))?
        .create()?
        .add_rules(path_beneath_rules(read_write, AccessFs::from_all(abi)))?
        .add_rules(path_beneath_rules(create_file, AccessFs::MakeReg))?
        .add_rules(path_beneath_rules(create_directory, AccessFs::MakeDir))?
        .add_rules(path_beneath_rules(read_only, AccessFs::from_read(abi)))?
        .add_rules(path_beneath_rules(remove_directory, AccessFs::RemoveDir))?
        .add_rules(path_beneath_rules(remove_file, AccessFs::RemoveFile))?
        .restrict_self()?;

    if status.ruleset == RulesetStatus::NotEnforced {
        log::error!("Could not enforce restictions");
        return Err(SandboxError::NotEnforced);
    }

    log::info!(
        "Activated FS access restrictions; rules={:?}, status={:?}",
        access_rules,
        status.ruleset
    );

    Ok(())
}
