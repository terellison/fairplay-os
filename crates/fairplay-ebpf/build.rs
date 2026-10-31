//! Generates field accessors for whatever kernel `src/vmlinux.rs` was
//! generated from.
//!
//! To name the caller's executable, the program follows
//! `task->mm->exe_file->f_path.dentry->d_name`. Some of those fields sit
//! inside anonymous structs or unions that bindgen names `__bindgen_anon_N`,
//! and which ones moved between kernels (`mm_struct`'s body is wrapped for
//! layout randomization; `file.f_path` went into a union around 6.13).
//! Without CO-RE the program is built per kernel anyway, so find each path at
//! build time. Same approach as `lsm-hello-ebpf/build.rs`.

use std::{env, fs, path::Path};

/// (accessor name, struct, field, field type)
const FIELDS: &[(&str, &str, &str, &str)] = &[
    ("task_mm", "task_struct", "mm", "*mut mm_struct"),
    ("mm_exe_file", "mm_struct", "exe_file", "*mut file"),
    ("file_path", "file", "f_path", "path"),
    ("dentry_name", "dentry", "d_name", "qstr"),
    // Executable-mapping allowlist (hooks/mmap_file.rs, hooks/file_mprotect.rs).
    ("file_inode", "file", "f_inode", "*mut inode"),
    ("vma_file", "vm_area_struct", "vm_file", "*mut file"),
    ("inode_sb", "inode", "i_sb", "*mut super_block"),
    ("inode_ino", "inode", "i_ino", "u64"),
    ("inode_mode", "inode", "i_mode", "u16"),
    ("inode_uid", "inode", "i_uid", "kuid_t"),
    ("inode_generation", "inode", "i_generation", "u32"),
    ("sb_dev", "super_block", "s_dev", "u32"),
    // Readers by exec (readers.rs).
    ("bprm_file", "linux_binprm", "file", "*mut file"),
    // Self-protection (hooks/bpf_map.rs, hooks/bpf_prog.rs).
    ("map_id", "bpf_map", "id", "u32"),
    ("prog_aux", "bpf_prog", "aux", "*mut bpf_prog_aux"),
    ("prog_aux_id", "bpf_prog_aux", "id", "u32"),
];

fn main() {
    println!("cargo:rerun-if-changed=src/vmlinux.rs");
    let src = fs::read_to_string("src/vmlinux.rs")
        .expect("src/vmlinux.rs missing: run `aya-tool generate task_struct > src/vmlinux.rs`");
    let mut code = String::new();
    for &(func, ty, field, field_ty) in FIELDS {
        let access = find_field(&src, ty, field, 3).unwrap_or_else(|| {
            panic!("struct {ty} has no {field}, directly or in an anonymous member")
        });
        code += &format!(
            "/// `&(*p).{field}`, wherever this kernel's `struct {ty}` keeps it.\n\
             #[inline(always)]\n\
             pub(crate) unsafe fn {func}(p: *const {ty}) -> *const {field_ty} {{\n    \
             unsafe {{ core::ptr::addr_of!((*p).{access}) }}\n}}\n"
        );
    }
    fs::write(
        Path::new(&env::var("OUT_DIR").unwrap()).join("fields.rs"),
        code,
    )
    .unwrap();
}

/// `field`, or `__bindgen_anon_N.<...>.field`, searching anonymous members
/// up to `depth` levels down.
fn find_field(src: &str, ty: &str, field: &str, depth: u32) -> Option<String> {
    let body = block(src, &format!("pub struct {ty} {{"))
        .or_else(|| block(src, &format!("pub union {ty} {{")))?;
    let fields = || {
        body.lines()
            .map(str::trim)
            .filter_map(|l| l.strip_prefix("pub "))
    };
    if fields().any(|l| l.starts_with(&format!("{field}:"))) {
        return Some(field.into());
    }
    if depth == 0 {
        return None;
    }
    fields().find_map(|l| {
        let (name, inner) = l.split_once(": ")?;
        if !name.starts_with("__bindgen_anon_") {
            return None;
        }
        let inner = find_field(src, inner.trim_end_matches(','), field, depth - 1)?;
        Some(format!("{name}.{inner}"))
    })
}

/// The body of the top-level item that starts with `header`.
fn block<'a>(src: &'a str, header: &str) -> Option<&'a str> {
    let start = src.find(&format!("\n{header}"))? + 1;
    let len = src[start..].find("\n}")?;
    Some(&src[start..start + len])
}
