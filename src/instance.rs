use std::{
    fs::{self, File, TryLockError},
    io,
    path::Path,
};

pub struct InstanceLock {
    _file: File,
}

impl InstanceLock {
    /// Holds the process lock until the returned guard is dropped.
    pub fn acquire(path: &Path) -> io::Result<Option<Self>> {
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }
        let file = File::options()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(path)?;
        match file.try_lock() {
            Ok(()) => Ok(Some(Self { _file: file })),
            Err(TryLockError::WouldBlock) => Ok(None),
            Err(TryLockError::Error(error)) => Err(error),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn excludes_another_instance_and_releases_the_lock_on_drop() {
        let path = std::env::temp_dir().join(format!("factr-{}.lock", uuid::Uuid::new_v4()));
        let first = InstanceLock::acquire(&path).unwrap().unwrap();
        assert!(InstanceLock::acquire(&path).unwrap().is_none());
        drop(first);
        let next = InstanceLock::acquire(&path).unwrap().unwrap();
        drop(next);
        fs::remove_file(path).unwrap();
    }
}
