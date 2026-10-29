//! Crash-safe file writes for in-house tools.
//!
//! Every write goes to a temp file in the target's directory, is fsynced, and
//! is then renamed over the target. A crash or kill at any point leaves either
//! the old file or the new file on disk, never a truncated mix. Readers that
//! already hold the old file keep reading the old inode.

use std::fs::{self, File, OpenOptions};
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

static COUNTER: AtomicU64 = AtomicU64::new(0);

/// Write `contents` to `path` atomically.
pub fn write(path: impl AsRef<Path>, contents: impl AsRef<[u8]>) -> io::Result<()> {
    let mut w = AtomicWriter::create(path)?;
    w.write_all(contents.as_ref())?;
    w.commit()
}

/// A file being written atomically. Nothing replaces the target until
/// [`AtomicWriter::commit`]; dropping without committing removes the temp file.
pub struct AtomicWriter {
    target: PathBuf,
    temp: PathBuf,
    file: Option<File>,
}

impl AtomicWriter {
    pub fn create(target: impl AsRef<Path>) -> io::Result<Self> {
        let target = target.as_ref().to_path_buf();
        let dir = parent_dir(&target);
        let name = target
            .file_name()
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "target has no file name"))?
            .to_string_lossy()
            .into_owned();
        let n = COUNTER.fetch_add(1, Ordering::Relaxed);
        let temp = dir.join(format!(".{name}.safewrite.{}.{n}", std::process::id()));
        let file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&temp)?;
        // Keep the target's permissions if it already exists.
        if let Ok(meta) = fs::metadata(&target) {
            fs::set_permissions(&temp, meta.permissions())?;
        }
        Ok(Self {
            target,
            temp,
            file: Some(file),
        })
    }

    /// Flush to disk, rename over the target, then fsync the directory so the
    /// rename itself survives a power loss.
    pub fn commit(mut self) -> io::Result<()> {
        let file = self.file.take().expect("file present until commit");
        file.sync_all()?;
        drop(file);
        fs::rename(&self.temp, &self.target)?;
        sync_dir(&parent_dir(&self.target))
    }
}

impl Write for AtomicWriter {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.file
            .as_mut()
            .expect("file present until commit")
            .write(buf)
    }
    fn flush(&mut self) -> io::Result<()> {
        self.file
            .as_mut()
            .expect("file present until commit")
            .flush()
    }
}

impl Drop for AtomicWriter {
    fn drop(&mut self) {
        if self.file.is_some() {
            let _ = fs::remove_file(&self.temp);
        }
    }
}

fn parent_dir(path: &Path) -> PathBuf {
    match path.parent() {
        Some(p) if !p.as_os_str().is_empty() => p.to_path_buf(),
        _ => PathBuf::from("."),
    }
}

#[cfg(unix)]
fn sync_dir(dir: &Path) -> io::Result<()> {
    File::open(dir)?.sync_all()
}

#[cfg(not(unix))]
fn sync_dir(_dir: &Path) -> io::Result<()> {
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn scratch(name: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!("safewrite-test-{name}-{}", std::process::id()));
        let _ = fs::remove_dir_all(&d);
        fs::create_dir_all(&d).unwrap();
        d
    }

    #[test]
    fn writes_new_file() {
        let d = scratch("new");
        let p = d.join("a.bin");
        write(&p, b"hello").unwrap();
        assert_eq!(fs::read(&p).unwrap(), b"hello");
    }

    #[test]
    fn replaces_existing_file() {
        let d = scratch("replace");
        let p = d.join("a.bin");
        fs::write(&p, b"old").unwrap();
        write(&p, b"new contents").unwrap();
        assert_eq!(fs::read(&p).unwrap(), b"new contents");
    }

    #[test]
    fn uncommitted_write_leaves_old_file_and_no_temp() {
        let d = scratch("abort");
        let p = d.join("a.bin");
        fs::write(&p, b"old").unwrap();
        {
            let mut w = AtomicWriter::create(&p).unwrap();
            w.write_all(b"half writ").unwrap();
            // Dropped without commit, like a tool that errors out mid-write.
        }
        assert_eq!(fs::read(&p).unwrap(), b"old");
        assert_eq!(fs::read_dir(&d).unwrap().count(), 1);
    }

    #[cfg(unix)]
    #[test]
    fn open_reader_keeps_old_inode() {
        use std::io::Read;
        let d = scratch("inode");
        let p = d.join("a.bin");
        fs::write(&p, b"old").unwrap();
        let mut reader = File::open(&p).unwrap();
        write(&p, b"new").unwrap();
        let mut s = String::new();
        reader.read_to_string(&mut s).unwrap();
        assert_eq!(s, "old");
        assert_eq!(fs::read(&p).unwrap(), b"new");
    }
}
