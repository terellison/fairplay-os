//! One module per LSM hook. Each defines a `#[lsm(hook = "...")]` program
//! and has a matching entry in fairplayd's `LSM_PROGRAMS`.

mod bpf;
mod bpf_map;
mod bpf_prog;
mod bprm_check_security;
mod file_ioctl;
mod file_ioctl_compat;
mod file_mprotect;
mod file_open;
mod file_permission;
mod inode_follow_link;
mod mmap_file;
mod ptrace;
mod socket;
mod task_alloc;
mod task_free;
mod task_kill;
mod task_set;
