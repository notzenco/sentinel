use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use std::process::Command;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RepositoryContext {
    pub root: PathBuf,
    pub branch: Option<String>,
    pub commit: Option<String>,
    pub is_git_repository: bool,
}

impl RepositoryContext {
    pub fn discover(path: &Path) -> Self {
        let root = git_output(path, &["rev-parse", "--show-toplevel"])
            .map(PathBuf::from)
            .unwrap_or_else(|| path.to_path_buf());

        let branch = git_output(path, &["branch", "--show-current"]);
        let commit = git_output(path, &["rev-parse", "HEAD"]);

        Self {
            root,
            branch,
            commit,
            is_git_repository: git_output(path, &["rev-parse", "--is-inside-work-tree"])
                .map(|value| value == "true")
                .unwrap_or(false),
        }
    }
}

fn git_output(path: &Path, args: &[&str]) -> Option<String> {
    let output = Command::new("git")
        .args(args)
        .current_dir(path)
        .output()
        .ok()?;

    if !output.status.success() {
        return None;
    }

    let value = String::from_utf8_lossy(&output.stdout).trim().to_string();
    if value.is_empty() { None } else { Some(value) }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn returns_non_git_context_for_temp_path() {
        let temp = tempfile::tempdir().unwrap();
        let context = RepositoryContext::discover(temp.path());
        assert!(!context.is_git_repository);
    }
}
