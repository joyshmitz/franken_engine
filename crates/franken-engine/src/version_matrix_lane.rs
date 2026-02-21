#![allow(dead_code)]

use std::cmp::Ordering;
use std::collections::{BTreeMap, BTreeSet};
use std::error::Error;
use std::fmt;

use serde::{Deserialize, Serialize};

pub const VERSION_MATRIX_SCHEMA: &str = "franken-engine.version-matrix-lane.v1";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct VersionSource {
    pub tags: Vec<String>,
    pub branch_names: Vec<String>,
    pub current_override: Option<String>,
    pub previous_override: Option<String>,
    pub next_override: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PinnedVersionCombination {
    pub local_version: String,
    pub remote_version: String,
    pub reason: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BoundaryMatrixSpec {
    pub boundary_surface: String,
    pub local_repo: String,
    pub remote_repo: String,
    pub local_versions: VersionSource,
    pub remote_versions: VersionSource,
    #[serde(default)]
    pub pinned_combinations: Vec<PinnedVersionCombination>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MatrixLaneKind {
    Current,
    Previous,
    Next,
    Pinned,
}

impl MatrixLaneKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Current => "n_n",
            Self::Previous => "n_n_minus_1",
            Self::Next => "n_n_plus_1",
            Self::Pinned => "pinned",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VersionMatrixCell {
    pub cell_id: String,
    pub boundary_surface: String,
    pub local_repo: String,
    pub remote_repo: String,
    pub local_version: String,
    pub remote_version: String,
    pub lane_kind: MatrixLaneKind,
    pub pinned: bool,
    pub expected_conformance_command: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VersionMatrixPlan {
    pub schema_version: String,
    pub generated_at_utc: String,
    pub cells: Vec<VersionMatrixCell>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VersionSlots {
    pub current: String,
    pub previous: Option<String>,
    pub next: Option<String>,
    pub derivation_notes: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VersionMatrixError {
    MissingCurrentVersion {
        repo: String,
    },
    InvalidPinnedCombination {
        boundary_surface: String,
        reason: String,
    },
}

impl fmt::Display for VersionMatrixError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::MissingCurrentVersion { repo } => {
                write!(f, "cannot derive current version for repo `{repo}`")
            }
            Self::InvalidPinnedCombination {
                boundary_surface,
                reason,
            } => write!(
                f,
                "invalid pinned combination for `{boundary_surface}`: {reason}"
            ),
        }
    }
}

impl Error for VersionMatrixError {}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MatrixOutcome {
    Pass,
    Fail,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MatrixCellResult {
    pub trace_id: String,
    pub decision_id: String,
    pub policy_id: String,
    pub cell_id: String,
    pub boundary_surface: String,
    pub lane_kind: MatrixLaneKind,
    pub outcome: MatrixOutcome,
    pub error_code: Option<String>,
    pub failure_fingerprint: Option<String>,
    pub failure_class: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FailureScopeKind {
    Universal,
    VersionSpecific,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MatrixFailureScope {
    pub boundary_surface: String,
    pub failure_fingerprint: String,
    pub scope: FailureScopeKind,
    pub failing_cells: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MatrixHealthSummary {
    pub total_cells: usize,
    pub passed_cells: usize,
    pub failed_cells: usize,
    pub universal_failures: usize,
    pub version_specific_failures: usize,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ParsedVersion {
    major: u64,
    minor: u64,
    patch: u64,
    prerelease: Option<String>,
}

impl ParsedVersion {
    fn parse(input: &str) -> Option<Self> {
        let trimmed = input.trim().trim_start_matches('v');
        let (core, prerelease) = if let Some((core, pre)) = trimmed.split_once('-') {
            (core, Some(pre.to_string()))
        } else {
            (trimmed, None)
        };
        let mut parts = core.split('.');
        let major = parts.next()?.parse::<u64>().ok()?;
        let minor = parts.next()?.parse::<u64>().ok()?;
        let patch = parts.next()?.parse::<u64>().ok()?;
        if parts.next().is_some() {
            return None;
        }
        Some(Self {
            major,
            minor,
            patch,
            prerelease,
        })
    }

    fn is_prerelease(&self) -> bool {
        self.prerelease.is_some()
    }

    fn bump_patch_next(&self) -> String {
        format!("{}.{}.{}-next", self.major, self.minor, self.patch + 1)
    }

    fn format(&self) -> String {
        if let Some(pre) = &self.prerelease {
            format!("{}.{}.{}-{pre}", self.major, self.minor, self.patch)
        } else {
            format!("{}.{}.{}", self.major, self.minor, self.patch)
        }
    }
}

impl Ord for ParsedVersion {
    fn cmp(&self, other: &Self) -> Ordering {
        (self.major, self.minor, self.patch)
            .cmp(&(other.major, other.minor, other.patch))
            .then_with(|| match (&self.prerelease, &other.prerelease) {
                (None, None) => Ordering::Equal,
                (None, Some(_)) => Ordering::Greater,
                (Some(_), None) => Ordering::Less,
                (Some(lhs), Some(rhs)) => lhs.cmp(rhs),
            })
    }
}

impl PartialOrd for ParsedVersion {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

pub fn derive_version_slots(
    source: &VersionSource,
    repo: &str,
) -> Result<VersionSlots, VersionMatrixError> {
    let parsed = parse_versions_from_tags(&source.tags);
    let mut stable_versions: Vec<ParsedVersion> = parsed
        .iter()
        .filter(|version| !version.is_prerelease())
        .cloned()
        .collect();
    stable_versions.sort();

    let current = if let Some(override_current) = &source.current_override {
        override_current.clone()
    } else if let Some(latest) = stable_versions.last() {
        latest.format()
    } else if let Some(latest_any) = parsed.iter().max() {
        latest_any.format()
    } else {
        return Err(VersionMatrixError::MissingCurrentVersion {
            repo: repo.to_string(),
        });
    };

    let mut notes = Vec::new();
    let previous = if let Some(override_previous) = &source.previous_override {
        Some(override_previous.clone())
    } else {
        let current_parsed = ParsedVersion::parse(&current);
        if let Some(current_parsed) = current_parsed {
            stable_versions
                .iter()
                .filter(|version| {
                    version.major < current_parsed.major
                        || (version.major == current_parsed.major
                            && version.minor < current_parsed.minor)
                        || (version.major == current_parsed.major
                            && version.minor == current_parsed.minor
                            && version.patch < current_parsed.patch)
                })
                .max()
                .map(ParsedVersion::format)
        } else {
            None
        }
    };

    let next = if let Some(override_next) = &source.next_override {
        Some(override_next.clone())
    } else if let Some(prerelease_next) = parsed
        .iter()
        .filter(|version| version.is_prerelease())
        .max()
        .map(ParsedVersion::format)
    {
        notes.push("derived next version from prerelease tag".to_string());
        Some(prerelease_next)
    } else if source.branch_names.iter().any(|branch| {
        let name = branch.to_ascii_lowercase();
        name == "main" || name.contains("next") || name.contains("nightly")
    }) {
        if let Some(current_parsed) = ParsedVersion::parse(&current) {
            notes.push("derived next version from branch convention".to_string());
            Some(current_parsed.bump_patch_next())
        } else {
            None
        }
    } else {
        None
    };

    Ok(VersionSlots {
        current,
        previous,
        next,
        derivation_notes: notes,
    })
}

pub fn derive_version_matrix(
    specs: &[BoundaryMatrixSpec],
) -> Result<VersionMatrixPlan, VersionMatrixError> {
    let mut cells = Vec::new();
    let mut seen = BTreeSet::new();

    for spec in specs {
        let local_slots = derive_version_slots(&spec.local_versions, spec.local_repo.as_str())?;
        let remote_slots = derive_version_slots(&spec.remote_versions, spec.remote_repo.as_str())?;

        let current_cell = build_cell(
            spec,
            MatrixLaneKind::Current,
            local_slots.current.as_str(),
            remote_slots.current.as_str(),
            false,
        );
        if seen.insert(current_cell.cell_id.clone()) {
            cells.push(current_cell);
        }

        if let Some(previous_remote) = remote_slots.previous {
            let previous_cell = build_cell(
                spec,
                MatrixLaneKind::Previous,
                local_slots.current.as_str(),
                previous_remote.as_str(),
                false,
            );
            if seen.insert(previous_cell.cell_id.clone()) {
                cells.push(previous_cell);
            }
        }

        if let Some(next_remote) = remote_slots.next {
            let next_cell = build_cell(
                spec,
                MatrixLaneKind::Next,
                local_slots.current.as_str(),
                next_remote.as_str(),
                false,
            );
            if seen.insert(next_cell.cell_id.clone()) {
                cells.push(next_cell);
            }
        }

        for pinned in &spec.pinned_combinations {
            if pinned.local_version.trim().is_empty() || pinned.remote_version.trim().is_empty() {
                return Err(VersionMatrixError::InvalidPinnedCombination {
                    boundary_surface: spec.boundary_surface.clone(),
                    reason: "local_version and remote_version are required".to_string(),
                });
            }
            let pinned_cell = build_cell(
                spec,
                MatrixLaneKind::Pinned,
                pinned.local_version.as_str(),
                pinned.remote_version.as_str(),
                true,
            );
            if seen.insert(pinned_cell.cell_id.clone()) {
                cells.push(pinned_cell);
            }
        }
    }

    cells.sort_by(|lhs, rhs| {
        lhs.boundary_surface
            .cmp(&rhs.boundary_surface)
            .then(lhs.lane_kind.cmp(&rhs.lane_kind))
            .then(lhs.local_version.cmp(&rhs.local_version))
            .then(lhs.remote_version.cmp(&rhs.remote_version))
    });

    Ok(VersionMatrixPlan {
        schema_version: VERSION_MATRIX_SCHEMA.to_string(),
        generated_at_utc: "1970-01-01T00:00:00Z".to_string(),
        cells,
    })
}

pub fn classify_failure_scopes(
    plan: &VersionMatrixPlan,
    results: &[MatrixCellResult],
) -> Vec<MatrixFailureScope> {
    let mut cells_per_boundary = BTreeMap::new();
    for cell in &plan.cells {
        *cells_per_boundary
            .entry(cell.boundary_surface.clone())
            .or_insert(0usize) += 1;
    }

    let mut grouped = BTreeMap::<(String, String), Vec<String>>::new();
    for result in results {
        if result.outcome == MatrixOutcome::Fail
            && let Some(fingerprint) = &result.failure_fingerprint
        {
            grouped
                .entry((result.boundary_surface.clone(), fingerprint.clone()))
                .or_default()
                .push(result.cell_id.clone());
        }
    }

    let mut scopes = Vec::new();
    for ((boundary, fingerprint), mut failing_cells) in grouped {
        failing_cells.sort();
        let total_cells = cells_per_boundary.get(&boundary).copied().unwrap_or(0);
        let scope = if total_cells > 0 && failing_cells.len() == total_cells {
            FailureScopeKind::Universal
        } else {
            FailureScopeKind::VersionSpecific
        };
        scopes.push(MatrixFailureScope {
            boundary_surface: boundary,
            failure_fingerprint: fingerprint,
            scope,
            failing_cells,
        });
    }

    scopes.sort_by(|lhs, rhs| {
        lhs.boundary_surface
            .cmp(&rhs.boundary_surface)
            .then(lhs.failure_fingerprint.cmp(&rhs.failure_fingerprint))
    });
    scopes
}

pub fn summarize_matrix_health(
    plan: &VersionMatrixPlan,
    results: &[MatrixCellResult],
) -> MatrixHealthSummary {
    let failed_cells = results
        .iter()
        .filter(|result| result.outcome == MatrixOutcome::Fail)
        .count();
    let passed_cells = results
        .iter()
        .filter(|result| result.outcome == MatrixOutcome::Pass)
        .count();
    let scopes = classify_failure_scopes(plan, results);

    MatrixHealthSummary {
        total_cells: plan.cells.len(),
        passed_cells,
        failed_cells,
        universal_failures: scopes
            .iter()
            .filter(|scope| scope.scope == FailureScopeKind::Universal)
            .count(),
        version_specific_failures: scopes
            .iter()
            .filter(|scope| scope.scope == FailureScopeKind::VersionSpecific)
            .count(),
    }
}

fn build_cell(
    spec: &BoundaryMatrixSpec,
    lane_kind: MatrixLaneKind,
    local_version: &str,
    remote_version: &str,
    pinned: bool,
) -> VersionMatrixCell {
    let cell_id = format!(
        "{}::{}::{}::{}",
        spec.boundary_surface,
        lane_kind.as_str(),
        local_version,
        remote_version
    );
    VersionMatrixCell {
        expected_conformance_command: format!(
            "cargo test -p frankenengine-engine --test conformance_assets -- --matrix-cell {cell_id}"
        ),
        cell_id,
        boundary_surface: spec.boundary_surface.clone(),
        local_repo: spec.local_repo.clone(),
        remote_repo: spec.remote_repo.clone(),
        local_version: local_version.to_string(),
        remote_version: remote_version.to_string(),
        lane_kind,
        pinned,
    }
}

fn parse_versions_from_tags(tags: &[String]) -> Vec<ParsedVersion> {
    let mut out = Vec::new();
    for tag in tags {
        for token in tag.split(|ch: char| !(ch.is_ascii_alphanumeric() || ch == '.' || ch == '-')) {
            if let Some(version) = ParsedVersion::parse(token) {
                out.push(version);
            }
        }
    }
    out.sort();
    out.dedup();
    out
}
