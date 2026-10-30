//! Generates `file_path()`, the address of `file->f_path`, for whatever kernel
//! `src/vmlinux.rs` was generated from.
//!
//! The field moved: up to about 6.12 it is a plain member of `struct file`;
//! newer kernels wrap it in an anonymous union, which bindgen names
//! `__bindgen_anon_N`. Without CO-RE the program is built per kernel anyway,
//! so pick the right path at build time.

use std::{env, fs, path::Path};

fn main() {
    println!("cargo:rerun-if-changed=src/vmlinux.rs");
    let src = fs::read_to_string("src/vmlinux.rs")
        .expect("src/vmlinux.rs missing: run `aya-tool generate file > src/vmlinux.rs`");
    let access =
        find_f_path(&src).expect("struct file has no f_path, directly or in an anonymous union");
    let code = format!(
        "/// `&(*f).f_path`, wherever this kernel's `struct file` keeps it.\n\
         #[inline(always)]\n\
         unsafe fn file_path(f: *const file) -> *const vmlinux::path {{\n    \
         unsafe {{ core::ptr::addr_of!((*f).{access}) }}\n}}\n"
    );
    fs::write(
        Path::new(&env::var("OUT_DIR").unwrap()).join("file_path.rs"),
        code,
    )
    .unwrap();
}

/// `f_path` or `__bindgen_anon_N.f_path`.
fn find_f_path(src: &str) -> Option<String> {
    let file = block(src, "pub struct file {")?;
    if file
        .lines()
        .any(|l| l.trim_start().starts_with("pub f_path:"))
    {
        return Some("f_path".into());
    }
    for line in file.lines() {
        let Some(rest) = line.trim().strip_prefix("pub __bindgen_anon_") else {
            continue;
        };
        let (n, ty) = rest.split_once(": ")?;
        let ty = ty.trim_end_matches(',');
        let inner = block(src, &format!("pub union {ty} {{"))
            .or_else(|| block(src, &format!("pub struct {ty} {{")))?;
        if inner
            .lines()
            .any(|l| l.trim_start().starts_with("pub f_path:"))
        {
            return Some(format!("__bindgen_anon_{n}.f_path"));
        }
    }
    None
}

/// The body of the top-level item that starts with `header`.
fn block<'a>(src: &'a str, header: &str) -> Option<&'a str> {
    let start = src.find(&format!("\n{header}"))? + 1;
    let len = src[start..].find("\n}")?;
    Some(&src[start..start + len])
}
