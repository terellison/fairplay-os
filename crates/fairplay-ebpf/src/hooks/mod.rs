//! One module per LSM hook. Each defines a `#[lsm(hook = "...")]` program
//! and has a matching entry in fairplayd's `LSM_PROGRAMS`.

mod file_ioctl;
mod file_ioctl_compat;
mod file_mprotect;
mod file_permission;
mod mmap_file;
mod ptrace;
