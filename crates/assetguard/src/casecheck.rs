//! Finds paths that differ only by case. They are distinct files on Linux but
//! collide on Windows and macOS clients, and in case-insensitive depots.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

/// Groups of two or more paths that are equal ignoring case.
pub fn collisions<I, P>(paths: I) -> Vec<Vec<PathBuf>>
where
    I: IntoIterator<Item = P>,
    P: AsRef<Path>,
{
    let mut by_folded: BTreeMap<String, Vec<PathBuf>> = BTreeMap::new();
    for p in paths {
        let p = p.as_ref();
        by_folded.entry(fold(p)).or_default().push(p.to_path_buf());
    }
    by_folded
        .into_values()
        .filter_map(|mut group| {
            group.sort();
            group.dedup();
            (group.len() > 1).then_some(group)
        })
        .collect()
}

/// Also catches directory collisions: `Art/hero.png` vs `art/hero.png`.
fn fold(p: &Path) -> String {
    p.to_string_lossy().to_lowercase()
}

/// Every file under `root`, relative to it.
pub fn walk(root: &Path) -> std::io::Result<Vec<PathBuf>> {
    let mut out = Vec::new();
    let mut stack = vec![root.to_path_buf()];
    while let Some(dir) = stack.pop() {
        for entry in std::fs::read_dir(&dir)? {
            let entry = entry?;
            let ty = entry.file_type()?;
            let path = entry.path();
            if ty.is_dir() {
                stack.push(path);
            } else {
                out.push(path.strip_prefix(root).unwrap_or(&path).to_path_buf());
            }
        }
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn finds_file_and_directory_collisions() {
        let paths = [
            "Content/Texture.png",
            "Content/texture.png",
            "Art/hero.png",
            "art/hero.png",
            "Source/Main.cpp",
        ];
        let c = collisions(paths);
        assert_eq!(c.len(), 2);
        assert!(c.iter().all(|g| g.len() == 2));
    }

    #[test]
    fn no_collisions_in_clean_tree() {
        assert!(collisions(["a/b.txt", "a/c.txt", "B/b.txt"]).is_empty());
    }
}
