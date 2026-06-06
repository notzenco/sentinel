use anyhow::{Context, Result};
use globset::{Glob, GlobSet, GlobSetBuilder};
use ignore::WalkBuilder;
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::{Path, PathBuf};

pub const MAX_TEXT_FILE_BYTES: u64 = 2 * 1024 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ScanProfile {
    General,
    Claude,
    Cursor,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FileRecord {
    pub path: PathBuf,
    pub relative_path: String,
    pub contents: String,
}

pub fn collect_text_files(root: &Path, profile: ScanProfile) -> Result<Vec<FileRecord>> {
    collect_text_files_with_options(
        root,
        &FileCollectionOptions {
            profile,
            ..FileCollectionOptions::default()
        },
    )
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FileCollectionOptions {
    #[serde(default = "default_profile")]
    pub profile: ScanProfile,
    #[serde(default)]
    pub exclude: Vec<String>,
    #[serde(default)]
    pub max_file_bytes: Option<u64>,
}

impl Default for FileCollectionOptions {
    fn default() -> Self {
        Self {
            profile: ScanProfile::General,
            exclude: Vec::new(),
            max_file_bytes: None,
        }
    }
}

pub fn collect_text_files_with_options(
    root: &Path,
    options: &FileCollectionOptions,
) -> Result<Vec<FileRecord>> {
    let canonical_root = root
        .canonicalize()
        .with_context(|| format!("failed to resolve scan target {}", root.display()))?;
    let exclude_set = build_exclude_set(&options.exclude)?;
    let mut files = Vec::new();

    for entry in WalkBuilder::new(&canonical_root)
        .hidden(false)
        .git_ignore(true)
        .git_global(true)
        .parents(true)
        .build()
    {
        let entry = entry?;
        let path = entry.path();

        if !entry
            .file_type()
            .map(|file_type| file_type.is_file())
            .unwrap_or(false)
        {
            continue;
        }

        let relative_path = path
            .strip_prefix(&canonical_root)
            .unwrap_or(path)
            .to_string_lossy()
            .replace('\\', "/");

        if is_default_excluded_path(&relative_path) {
            continue;
        }

        if exclude_set.is_match(&relative_path) {
            continue;
        }

        if !profile_includes(path, &canonical_root, options.profile) {
            continue;
        }

        let metadata = fs::metadata(path)
            .with_context(|| format!("failed to read metadata for {}", path.display()))?;
        if metadata.len() > options.max_file_bytes.unwrap_or(MAX_TEXT_FILE_BYTES) {
            continue;
        }

        let bytes = fs::read(path).with_context(|| format!("failed to read {}", path.display()))?;
        if bytes.contains(&0) {
            continue;
        }

        let contents = String::from_utf8_lossy(&bytes).to_string();
        files.push(FileRecord {
            path: path.to_path_buf(),
            relative_path,
            contents,
        });
    }

    files.sort_by(|left, right| left.relative_path.cmp(&right.relative_path));
    Ok(files)
}

pub fn line_col_for_offset(contents: &str, offset: usize) -> (usize, usize) {
    let mut line = 1;
    let mut column = 1;

    for (idx, ch) in contents.char_indices() {
        if idx >= offset {
            break;
        }
        if ch == '\n' {
            line += 1;
            column = 1;
        } else {
            column += 1;
        }
    }

    (line, column)
}

pub fn path_has_extension(path: &str, extensions: &[String]) -> bool {
    let extension = Path::new(path)
        .extension()
        .and_then(|value| value.to_str())
        .unwrap_or_default()
        .to_ascii_lowercase();

    extensions.iter().any(|candidate| {
        candidate
            .trim_start_matches('.')
            .eq_ignore_ascii_case(&extension)
    })
}

fn profile_includes(path: &Path, root: &Path, profile: ScanProfile) -> bool {
    match profile {
        ScanProfile::General => true,
        ScanProfile::Claude => {
            let rel = path
                .strip_prefix(root)
                .unwrap_or(path)
                .to_string_lossy()
                .replace('\\', "/")
                .to_ascii_lowercase();
            rel == "claude.md"
                || rel.ends_with("/claude.md")
                || rel.contains(".claude/")
                || rel.contains("/prompts/")
                || rel.contains("/mcp")
        }
        ScanProfile::Cursor => {
            let rel = path
                .strip_prefix(root)
                .unwrap_or(path)
                .to_string_lossy()
                .replace('\\', "/")
                .to_ascii_lowercase();
            rel.contains(".cursor/")
                || rel.ends_with(".mdc")
                || rel.contains("/prompts/")
                || rel.contains("/agents/")
        }
    }
}

fn build_exclude_set(patterns: &[String]) -> Result<GlobSet> {
    let mut builder = GlobSetBuilder::new();
    for raw_pattern in patterns {
        let pattern = normalize_glob(raw_pattern);
        builder.add(
            Glob::new(&pattern)
                .with_context(|| format!("invalid exclude glob pattern `{raw_pattern}`"))?,
        );
    }
    Ok(builder.build()?)
}

fn is_default_excluded_path(relative_path: &str) -> bool {
    let path = relative_path.to_ascii_lowercase();
    path.starts_with(".git/")
        || path.starts_with(".hg/")
        || path.starts_with(".svn/")
        || path.starts_with("target/")
        || path.starts_with("node_modules/")
        || path.starts_with(".next/")
        || path.starts_with("dist/")
        || path.starts_with("build/")
}

fn normalize_glob(pattern: &str) -> String {
    let pattern = pattern.trim().replace('\\', "/");
    if pattern.is_empty() {
        return pattern;
    }
    if pattern.ends_with('/') {
        return format!("{pattern}**");
    }
    pattern
}

fn default_profile() -> ScanProfile {
    ScanProfile::General
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn calculates_line_and_column() {
        assert_eq!(line_col_for_offset("one\ntwo\nthree", 4), (2, 1));
        assert_eq!(line_col_for_offset("one\ntwo", 5), (2, 2));
    }

    #[test]
    fn extension_matching_accepts_dot_or_plain_values() {
        assert!(path_has_extension("prompt.md", &[".md".to_string()]));
        assert!(path_has_extension("prompt.JSON", &["json".to_string()]));
    }

    #[test]
    fn excludes_files_by_glob() {
        let temp = tempfile::tempdir().unwrap();
        fs::create_dir_all(temp.path().join("examples")).unwrap();
        fs::write(temp.path().join("keep.md"), "safe").unwrap();
        fs::write(temp.path().join("examples").join("skip.md"), "unsafe").unwrap();

        let files = collect_text_files_with_options(
            temp.path(),
            &FileCollectionOptions {
                exclude: vec!["examples/**".to_string()],
                ..FileCollectionOptions::default()
            },
        )
        .unwrap();

        assert_eq!(files.len(), 1);
        assert_eq!(files[0].relative_path, "keep.md");
    }

    #[test]
    fn skips_vcs_and_build_metadata_by_default() {
        let temp = tempfile::tempdir().unwrap();
        fs::create_dir_all(temp.path().join(".git").join("objects")).unwrap();
        fs::create_dir_all(temp.path().join(".github").join("workflows")).unwrap();
        fs::create_dir_all(temp.path().join("target")).unwrap();
        fs::write(temp.path().join(".git").join("config"), "secret").unwrap();
        fs::write(temp.path().join("target").join("debug.txt"), "build").unwrap();
        fs::write(
            temp.path().join(".github").join("workflows").join("ci.yml"),
            "name: ci",
        )
        .unwrap();

        let files = collect_text_files(temp.path(), ScanProfile::General).unwrap();

        assert_eq!(files.len(), 1);
        assert_eq!(files[0].relative_path, ".github/workflows/ci.yml");
    }
}
