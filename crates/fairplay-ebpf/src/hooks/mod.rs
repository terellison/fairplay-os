//! One module per LSM hook. Each defines a `#[lsm(hook = "...")]` program
//! and has a matching entry in fairplayd's `LSM_PROGRAMS`.

mod ptrace;
