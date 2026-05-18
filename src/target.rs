use anyhow::{bail, Context, Result};
use dirs::cache_dir;
use regex::Regex;
use serde::Serialize;
use sha1::{Digest, Sha1};
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use url::Url;

#[derive(Debug, Clone)]
pub struct TargetOptions {
    pub keep_temp: bool,
    pub cache_dir: Option<PathBuf>,
    pub branch: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CleanupStatus {
    pub cleaned: bool,
    pub reason: String,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TargetInfo {
    pub input: String,
    #[serde(rename = "type")]
    pub target_type: String,
    pub repository: Option<String>,
    pub web_url: Option<String>,
    pub path: PathBuf,
    pub temporary_clone: bool,
    pub temporary_clone_kept: bool,
    pub cleanup: CleanupStatus,
}

#[derive(Debug, Clone)]
pub struct ResolvedTarget {
    pub info: TargetInfo,
}

impl ResolvedTarget {
    pub fn cleanup(&mut self) {
        if self.info.temporary_clone {
            if self.info.temporary_clone_kept {
                self.info.cleanup = CleanupStatus {
                    cleaned: false,
                    reason: "kept".into(),
                };
            } else if fs::remove_dir_all(&self.info.path).is_ok() {
                self.info.cleanup = CleanupStatus {
                    cleaned: true,
                    reason: "removed".into(),
                };
            } else {
                self.info.cleanup = CleanupStatus {
                    cleaned: false,
                    reason: "remove_failed".into(),
                };
            }
        }
    }
}

pub fn resolve_target(input: &str, options: &TargetOptions) -> Result<ResolvedTarget> {
    let local = Path::new(input);
    if local.is_dir() {
        return Ok(ResolvedTarget {
            info: TargetInfo {
                input: input.into(),
                target_type: "local".into(),
                repository: None,
                web_url: None,
                path: fs::canonicalize(local).unwrap_or_else(|_| local.to_path_buf()),
                temporary_clone: false,
                temporary_clone_kept: false,
                cleanup: CleanupStatus {
                    cleaned: false,
                    reason: "not_required".into(),
                },
            },
        });
    }

    if let Some((owner, repo)) = parse_github_target(input) {
        let repository = format!("{owner}/{repo}");
        let web_url = format!("https://github.com/{repository}");
        let clone_dir = clone_dir_for(&repository, options.cache_dir.as_deref())?;
        if clone_dir.exists() {
            fs::remove_dir_all(&clone_dir)
                .with_context(|| format!("failed to clean {}", clone_dir.display()))?;
        }
        fs::create_dir_all(clone_dir.parent().unwrap())
            .context("failed to create cache directory")?;
        clone_repo(&web_url, &clone_dir, options.branch.as_deref())?;
        return Ok(ResolvedTarget {
            info: TargetInfo {
                input: input.into(),
                target_type: "github".into(),
                repository: Some(repository),
                web_url: Some(web_url),
                path: clone_dir,
                temporary_clone: true,
                temporary_clone_kept: options.keep_temp,
                cleanup: CleanupStatus {
                    cleaned: false,
                    reason: "pending".into(),
                },
            },
        });
    }

    bail!("Target is neither an accessible local directory nor a supported GitHub repository: {input}")
}

fn parse_github_target(input: &str) -> Option<(String, String)> {
    let shorthand = Regex::new(r"^([A-Za-z0-9-]+)/([A-Za-z0-9._-]+?)(?:\.git)?$").unwrap();
    if let Some(caps) = shorthand.captures(input) {
        return Some((caps[1].to_string(), caps[2].to_string()));
    }
    if let Ok(url) = Url::parse(input) {
        if url
            .host_str()
            .map(|h| h.eq_ignore_ascii_case("github.com"))
            .unwrap_or(false)
        {
            let mut segments = url.path_segments()?;
            let owner = segments.next()?.to_string();
            let repo = segments.next()?.trim_end_matches(".git").to_string();
            if !owner.is_empty() && !repo.is_empty() {
                return Some((owner, repo));
            }
        }
    }
    let ssh = Regex::new(r"(?i)^git@github\.com:([^/]+)/(.+?)(?:\.git)?$").unwrap();
    ssh.captures(input)
        .map(|caps| (caps[1].to_string(), caps[2].to_string()))
}

fn clone_dir_for(repository: &str, custom_cache_dir: Option<&Path>) -> Result<PathBuf> {
    let base = custom_cache_dir.map(PathBuf::from).unwrap_or_else(|| {
        cache_dir()
            .unwrap_or_else(std::env::temp_dir)
            .join("leak-hunter")
            .join("repos")
    });
    let mut hasher = Sha1::new();
    hasher.update(repository.as_bytes());
    let hash = hex::encode(&hasher.finalize()[..8]);
    Ok(base.join(format!("{}-{}", repository.replace('/', "-"), hash)))
}

fn clone_repo(web_url: &str, destination: &Path, branch: Option<&str>) -> Result<()> {
    let mut cmd = Command::new("git");
    cmd.arg("clone")
        .arg("--depth")
        .arg("1")
        .arg("--single-branch");
    if let Some(branch) = branch {
        cmd.arg("--branch").arg(branch);
    }
    cmd.arg(web_url).arg(destination);
    cmd.env("GIT_TERMINAL_PROMPT", "0");
    let output = cmd.output().context("failed to run git clone")?;
    if !output.status.success() {
        bail!(
            "Failed to clone GitHub repository {web_url}: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        );
    }
    Ok(())
}
