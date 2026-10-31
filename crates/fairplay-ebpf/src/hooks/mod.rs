//! One module per LSM hook. Each defines a `#[lsm(hook = "...")]` program
//! and has a matching entry in fairplayd's `LSM_PROGRAMS`.

mod bpf;
mod bpf_map;
mod bpf_prog;
mod file_mprotect;
mod mmap_file;
mod ptrace;
mod task_kill;
