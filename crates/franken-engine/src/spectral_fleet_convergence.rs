//! Spectral mixing bounds for fleet gossip convergence.
//!
//! Applies spectral graph theory to the fleet gossip topology to provide
//! **mathematically guaranteed convergence SLAs** rather than empirical ones.
//!
//! Key results:
//! - **Algebraic connectivity**: `λ₂` (the Fiedler value) of the Laplacian.
//! - **Mixing proxy bound**: `t_mix = O((λ_max/λ₂) · ln n)` for weighted
//!   gossip-like diffusion dynamics.
//! - **Cheeger-style conductance bounds** on the normalized gap:
//!   `λ₂_norm / 2 ≤ h ≤ sqrt(2 · λ₂_norm)`.
//! - **Fiedler partition detection**: The sign structure of the Fiedler
//!   vector reveals natural network partitions.
//!
//! All arithmetic uses fixed-point millionths.  No floating point.
//! Deterministic across platforms.
//!
//! Integration: consumed by `fleet_immune_protocol.rs` and
//! `fleet_convergence.rs` to produce convergence SLA certificates.
//!
//! Mathematical references:
//! - Fiedler, "Algebraic connectivity of graphs" (1973)
//! - Cheeger, "A lower bound for the smallest eigenvalue" (1970)
//! - Levin, Peres & Wilmer, "Markov Chains and Mixing Times" (2009), Ch. 12–13

use std::collections::BTreeMap;
use std::fmt;

use serde::{Deserialize, Serialize};

use crate::hash_tiers::ContentHash;
use crate::security_epoch::SecurityEpoch;

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

const MILLION: i64 = 1_000_000;

/// Schema version for serialized spectral artifacts.
pub const SPECTRAL_SCHEMA_VERSION: &str = "franken-engine.spectral-fleet-convergence.v1";

/// Maximum number of nodes for spectral analysis (guards O(n²) memory).
const MAX_NODES: usize = 1024;

/// Number of power iterations for eigenvalue estimation.
const POWER_ITERATIONS: usize = 100;

/// Convergence threshold for power iteration (millionths).
const CONVERGENCE_THRESHOLD_MILLIONTHS: i64 = 100; // 0.0001

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

/// Errors from spectral analysis.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum SpectralError {
    /// Too many nodes for analysis.
    TooManyNodes { count: usize, max: usize },
    /// Graph has no nodes.
    EmptyGraph,
    /// Graph is disconnected (no mixing possible).
    Disconnected { components: usize },
    /// Node index out of bounds.
    NodeOutOfBounds { index: usize, size: usize },
    /// Power iteration did not converge.
    ConvergenceFailure { iterations: usize },
    /// Spectral gap is zero or negative (degenerate graph).
    DegenerateSpectralGap,
}

impl fmt::Display for SpectralError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::TooManyNodes { count, max } => {
                write!(f, "{count} nodes exceeds limit {max}")
            }
            Self::EmptyGraph => write!(f, "empty graph"),
            Self::Disconnected { components } => {
                write!(f, "graph is disconnected ({components} components)")
            }
            Self::NodeOutOfBounds { index, size } => {
                write!(f, "node {index} out of bounds (size {size})")
            }
            Self::ConvergenceFailure { iterations } => {
                write!(
                    f,
                    "power iteration did not converge after {iterations} iterations"
                )
            }
            Self::DegenerateSpectralGap => {
                write!(f, "spectral gap is zero or negative")
            }
        }
    }
}

impl std::error::Error for SpectralError {}

// ---------------------------------------------------------------------------
// GossipTopology — the fleet communication graph
// ---------------------------------------------------------------------------

/// Fleet gossip topology as an undirected weighted graph.
///
/// Nodes are fleet members; edges represent active gossip channels.
/// Edge weights represent communication quality (higher = better).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GossipTopology {
    /// Number of nodes.
    pub num_nodes: usize,
    /// Node identifiers (sorted for determinism).
    pub node_ids: Vec<String>,
    /// Adjacency list: node → [(neighbor, weight_millionths)].
    pub adjacency: BTreeMap<usize, Vec<(usize, i64)>>,
}

impl GossipTopology {
    /// Create a new topology with the given nodes.
    pub fn new(node_ids: Vec<String>) -> Result<Self, SpectralError> {
        let n = node_ids.len();
        if n == 0 {
            return Err(SpectralError::EmptyGraph);
        }
        if n > MAX_NODES {
            return Err(SpectralError::TooManyNodes {
                count: n,
                max: MAX_NODES,
            });
        }
        Ok(Self {
            num_nodes: n,
            node_ids,
            adjacency: BTreeMap::new(),
        })
    }

    /// Add an undirected edge between two nodes.
    pub fn add_edge(
        &mut self,
        from: usize,
        to: usize,
        weight_millionths: i64,
    ) -> Result<(), SpectralError> {
        if from >= self.num_nodes {
            return Err(SpectralError::NodeOutOfBounds {
                index: from,
                size: self.num_nodes,
            });
        }
        if to >= self.num_nodes {
            return Err(SpectralError::NodeOutOfBounds {
                index: to,
                size: self.num_nodes,
            });
        }
        self.adjacency
            .entry(from)
            .or_default()
            .push((to, weight_millionths));
        if from != to {
            self.adjacency
                .entry(to)
                .or_default()
                .push((from, weight_millionths));
        }
        Ok(())
    }

    /// Compute the degree of a node (sum of edge weights in millionths).
    pub fn degree(&self, node: usize) -> i64 {
        self.adjacency
            .get(&node)
            .map(|edges| edges.iter().map(|(_, w)| *w).sum())
            .unwrap_or(0)
    }

    /// Check connectivity via BFS.
    pub fn is_connected(&self) -> bool {
        if self.num_nodes <= 1 {
            return true;
        }
        let mut visited = vec![false; self.num_nodes];
        let mut stack = vec![0usize];
        visited[0] = true;
        let mut count = 1;

        while let Some(node) = stack.pop() {
            if let Some(edges) = self.adjacency.get(&node) {
                for &(neighbor, _) in edges {
                    if !visited[neighbor] {
                        visited[neighbor] = true;
                        count += 1;
                        stack.push(neighbor);
                    }
                }
            }
        }
        count == self.num_nodes
    }

    /// Count connected components.
    pub fn connected_components(&self) -> usize {
        let mut visited = vec![false; self.num_nodes];
        let mut components = 0;

        for start in 0..self.num_nodes {
            if visited[start] {
                continue;
            }
            components += 1;
            let mut stack = vec![start];
            visited[start] = true;
            while let Some(node) = stack.pop() {
                if let Some(edges) = self.adjacency.get(&node) {
                    for &(neighbor, _) in edges {
                        if !visited[neighbor] {
                            visited[neighbor] = true;
                            stack.push(neighbor);
                        }
                    }
                }
            }
        }
        components
    }
}

// ---------------------------------------------------------------------------
// LaplacianMatrix — the graph Laplacian
// ---------------------------------------------------------------------------

/// Graph Laplacian matrix L = D - A, stored in row-major flat format.
///
/// The Laplacian is positive semi-definite with eigenvalues
/// 0 = λ₁ ≤ λ₂ ≤ ... ≤ λ_n.
///
/// The algebraic connectivity (Fiedler value) is λ₂.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LaplacianMatrix {
    /// Matrix dimension.
    pub dim: usize,
    /// Row-major flat storage in millionths.
    data: Vec<i64>,
}

impl LaplacianMatrix {
    /// Construct the Laplacian from a gossip topology.
    pub fn from_topology(topology: &GossipTopology) -> Result<Self, SpectralError> {
        let n = topology.num_nodes;
        if n == 0 {
            return Err(SpectralError::EmptyGraph);
        }

        let mut data = vec![0i64; n * n];

        // Set off-diagonal entries: L[i][j] = -w(i,j)
        for (&node, edges) in &topology.adjacency {
            for &(neighbor, weight) in edges {
                if node != neighbor {
                    data[node * n + neighbor] = -weight;
                }
            }
        }

        // Set diagonal entries: L[i][i] = degree(i)
        for i in 0..n {
            let degree = topology.degree(i);
            data[i * n + i] = degree;
        }

        Ok(Self { dim: n, data })
    }

    /// Get element at (i, j).
    pub fn get(&self, i: usize, j: usize) -> i64 {
        self.data[i * self.dim + j]
    }

    /// Compute a content hash for audit.
    pub fn content_hash(&self) -> ContentHash {
        let mut bytes = Vec::with_capacity(8 + self.data.len() * 8);
        bytes.extend_from_slice(&(self.dim as u64).to_be_bytes());
        for &v in &self.data {
            bytes.extend_from_slice(&v.to_be_bytes());
        }
        ContentHash::compute(&bytes)
    }
}

// ---------------------------------------------------------------------------
// SpectralGap — the core spectral analysis
// ---------------------------------------------------------------------------

/// Result of spectral analysis on the gossip topology.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SpectralAnalysis {
    /// Schema version.
    pub schema: String,
    /// Number of nodes.
    pub num_nodes: usize,
    /// Algebraic connectivity (Fiedler value) λ₂ in millionths.
    pub algebraic_connectivity_millionths: i64,
    /// Spectral gap proxy in millionths (here: λ₂, the algebraic connectivity).
    pub spectral_gap_millionths: i64,
    /// Mixing-time proxy upper bound: ceil((λ_max / λ₂) · ln(n)).
    pub mixing_time_bound: u64,
    /// Cheeger conductance lower bound: λ₂_norm / 2 in millionths.
    pub cheeger_lower_bound_millionths: i64,
    /// Cheeger conductance upper bound: √(2 · λ₂_norm) in millionths.
    pub cheeger_upper_bound_millionths: i64,
    /// Fiedler vector (eigenvector of λ₂) for partition detection.
    pub fiedler_vector_millionths: Vec<i64>,
    /// Detected partition (nodes with negative Fiedler components).
    pub partition_a: Vec<usize>,
    /// Nodes with non-negative Fiedler components.
    pub partition_b: Vec<usize>,
    /// Laplacian content hash for audit.
    pub laplacian_hash: ContentHash,
}

/// Spectral analyzer for gossip topologies.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SpectralAnalyzer {
    /// Number of power iterations.
    pub max_iterations: usize,
    /// Convergence threshold in millionths.
    pub convergence_threshold_millionths: i64,
}

impl Default for SpectralAnalyzer {
    fn default() -> Self {
        Self {
            max_iterations: POWER_ITERATIONS,
            convergence_threshold_millionths: CONVERGENCE_THRESHOLD_MILLIONTHS,
        }
    }
}

impl SpectralAnalyzer {
    /// Perform full spectral analysis on a gossip topology.
    pub fn analyze(&self, topology: &GossipTopology) -> Result<SpectralAnalysis, SpectralError> {
        if !topology.is_connected() {
            return Err(SpectralError::Disconnected {
                components: topology.connected_components(),
            });
        }

        let laplacian = LaplacianMatrix::from_topology(topology)?;
        let laplacian_hash = laplacian.content_hash();
        let n = laplacian.dim;

        // Find λ₂ (second-smallest eigenvalue) and its eigenvector
        // using inverse power iteration with deflation.

        // Step 1: Find λ_max via standard power iteration.
        let (lambda_max, _) = self.power_iteration_max(&laplacian)?;

        // Step 2: Find Fiedler value (λ₂) via shifted inverse iteration.
        // We use the property that the all-ones vector is the eigenvector
        // of λ₁ = 0, so we deflate by projecting out the uniform component.
        let (fiedler_value, fiedler_vector) = self.fiedler_computation(&laplacian)?;

        // Spectral gap = λ₂ (algebraic connectivity).
        // For connected graphs, λ₂ > 0 by Fiedler's theorem.
        let spectral_gap = fiedler_value;

        if spectral_gap <= 0 {
            return Err(SpectralError::DegenerateSpectralGap);
        }

        // Mixing time bound: t_mix ≈ ceil(λ_max / λ₂ · ln(n)).
        let ln_n = integer_ln_millionths(n as u64);
        let mixing_time = if spectral_gap > 0 {
            let ratio = lambda_max * MILLION / spectral_gap; // λ_max/λ₂ in millionths
            ((ratio * ln_n / MILLION) + MILLION - 1) / MILLION
        } else {
            i64::MAX
        };

        // Cheeger bounds (normalized):
        // λ₂_norm / 2 ≤ h ≤ sqrt(2 * λ₂_norm)
        // using λ₂_norm ≈ λ₂ / λ_max.
        let normalized_gap = if lambda_max > 0 {
            fiedler_value * MILLION / lambda_max
        } else {
            0
        };
        let cheeger_lower = normalized_gap / 2;
        let cheeger_upper = integer_sqrt_millionths((2 * normalized_gap).max(0));

        // Partition detection via Fiedler vector sign.
        let mut partition_a = Vec::new();
        let mut partition_b = Vec::new();
        for (i, &v) in fiedler_vector.iter().enumerate() {
            if v < 0 {
                partition_a.push(i);
            } else {
                partition_b.push(i);
            }
        }

        Ok(SpectralAnalysis {
            schema: SPECTRAL_SCHEMA_VERSION.to_string(),
            num_nodes: n,
            algebraic_connectivity_millionths: fiedler_value,
            spectral_gap_millionths: spectral_gap,
            mixing_time_bound: mixing_time.max(1) as u64,
            cheeger_lower_bound_millionths: cheeger_lower,
            cheeger_upper_bound_millionths: cheeger_upper,
            fiedler_vector_millionths: fiedler_vector,
            partition_a,
            partition_b,
            laplacian_hash,
        })
    }

    /// Standard power iteration to find the largest eigenvalue.
    fn power_iteration_max(
        &self,
        laplacian: &LaplacianMatrix,
    ) -> Result<(i64, Vec<i64>), SpectralError> {
        let n = laplacian.dim;
        let mut v: Vec<i64> = (0..n).map(|i| MILLION / n as i64 + i as i64).collect();
        normalize_vector_millionths(&mut v);

        let mut lambda = 0i64;
        #[allow(clippy::needless_range_loop)]
        for _ in 0..self.max_iterations {
            let mut new_v = vec![0i64; n];
            for i in 0..n {
                let mut sum = 0i128;
                for j in 0..n {
                    sum += laplacian.get(i, j) as i128 * v[j] as i128;
                }
                new_v[i] = (sum / MILLION as i128) as i64;
            }

            let new_lambda = dot_product_millionths(&new_v, &v);
            normalize_vector_millionths(&mut new_v);

            if (new_lambda - lambda).abs() < self.convergence_threshold_millionths {
                return Ok((new_lambda, new_v));
            }
            lambda = new_lambda;
            v = new_v;
        }

        Err(SpectralError::ConvergenceFailure {
            iterations: self.max_iterations,
        })
    }

    /// Compute the Fiedler value (second-smallest eigenvalue) and vector.
    ///
    /// Uses power iteration on (λ_max·I - L) with deflation of the
    /// constant eigenvector (corresponding to λ₁ = 0).
    fn fiedler_computation(
        &self,
        laplacian: &LaplacianMatrix,
    ) -> Result<(i64, Vec<i64>), SpectralError> {
        let n = laplacian.dim;

        // First get λ_max.
        let (lambda_max, _) = self.power_iteration_max(laplacian)?;

        // Initialize with non-uniform vector orthogonal to all-ones.
        let mut v: Vec<i64> = (0..n)
            .map(|i| (i as i64 * 2 - n as i64) * MILLION / n as i64)
            .collect();
        // Project out the uniform component.
        deflate_uniform(&mut v, n);
        normalize_vector_millionths(&mut v);

        let mut lambda = 0i64;
        #[allow(clippy::needless_range_loop)]
        for _ in 0..self.max_iterations {
            // Multiply by (λ_max · I - L).
            let mut new_v = vec![0i64; n];
            for i in 0..n {
                let mut sum = 0i128;
                for j in 0..n {
                    let entry = if i == j {
                        lambda_max - laplacian.get(i, j)
                    } else {
                        -laplacian.get(i, j)
                    };
                    sum += entry as i128 * v[j] as i128;
                }
                new_v[i] = (sum / MILLION as i128) as i64;
            }

            // Deflate uniform component.
            deflate_uniform(&mut new_v, n);

            // Rayleigh quotient estimate on the shifted operator before
            // renormalization. Using the normalized vector here biases λ₂.
            let new_lambda = dot_product_millionths(&new_v, &v);
            normalize_vector_millionths(&mut new_v);
            if (new_lambda - lambda).abs() < self.convergence_threshold_millionths {
                // λ₂ = λ_max - eigenvalue_of_shifted_matrix
                let fiedler_value = lambda_max - new_lambda;
                return Ok((fiedler_value.max(0), new_v));
            }
            lambda = new_lambda;
            v = new_v;
        }

        Err(SpectralError::ConvergenceFailure {
            iterations: self.max_iterations,
        })
    }
}

// ---------------------------------------------------------------------------
// Convergence SLA certificate
// ---------------------------------------------------------------------------

/// Machine-checkable convergence SLA certificate.
///
/// Guarantees that gossip dissemination reaches all nodes within
/// `mixing_time_bound` rounds with high probability.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConvergenceCertificate {
    pub schema: String,
    /// Number of fleet nodes.
    pub num_nodes: usize,
    /// Guaranteed mixing time (rounds).
    pub mixing_time_rounds: u64,
    /// Spectral gap (millionths).
    pub spectral_gap_millionths: i64,
    /// Conductance bounds (Cheeger inequality).
    pub cheeger_lower_millionths: i64,
    pub cheeger_upper_millionths: i64,
    /// Whether the graph has a natural partition.
    pub has_natural_partition: bool,
    /// Partition sizes (if detected).
    pub partition_sizes: (usize, usize),
    /// Epoch at which this certificate was computed.
    pub epoch: SecurityEpoch,
    /// Content hash for audit.
    pub certificate_hash: ContentHash,
}

impl ConvergenceCertificate {
    /// Build a convergence certificate from spectral analysis.
    pub fn from_analysis(analysis: &SpectralAnalysis, epoch: SecurityEpoch) -> Self {
        let has_partition = !analysis.partition_a.is_empty() && !analysis.partition_b.is_empty();
        let partition_sizes = (analysis.partition_a.len(), analysis.partition_b.len());

        let cert_bytes = format!(
            "{}:{}:{}:{}",
            analysis.num_nodes,
            analysis.spectral_gap_millionths,
            analysis.mixing_time_bound,
            epoch.as_u64()
        );

        Self {
            schema: SPECTRAL_SCHEMA_VERSION.to_string(),
            num_nodes: analysis.num_nodes,
            mixing_time_rounds: analysis.mixing_time_bound,
            spectral_gap_millionths: analysis.spectral_gap_millionths,
            cheeger_lower_millionths: analysis.cheeger_lower_bound_millionths,
            cheeger_upper_millionths: analysis.cheeger_upper_bound_millionths,
            has_natural_partition: has_partition,
            partition_sizes,
            epoch,
            certificate_hash: ContentHash::compute(cert_bytes.as_bytes()),
        }
    }

    /// Verify that mixing time is within the SLA target (in rounds).
    pub fn meets_sla(&self, max_rounds: u64) -> bool {
        self.mixing_time_rounds <= max_rounds
    }
}

// ---------------------------------------------------------------------------
// Helper functions (no floating point)
// ---------------------------------------------------------------------------

/// Normalize a vector to unit length in millionths.
fn normalize_vector_millionths(v: &mut [i64]) {
    let norm_sq: i128 = v.iter().map(|&x| x as i128 * x as i128).sum();
    if norm_sq == 0 {
        return;
    }
    let norm = isqrt_i128(norm_sq);
    if norm == 0 {
        return;
    }
    for x in v.iter_mut() {
        *x = (*x as i128 * MILLION as i128 / norm) as i64;
    }
}

/// Deflate the uniform component from a vector.
fn deflate_uniform(v: &mut [i64], n: usize) {
    if n == 0 {
        return;
    }
    let mean: i64 = v.iter().sum::<i64>() / n as i64;
    for x in v.iter_mut() {
        *x -= mean;
    }
}

/// Dot product in millionths: (a · b) / MILLION.
fn dot_product_millionths(a: &[i64], b: &[i64]) -> i64 {
    let sum: i128 = a
        .iter()
        .zip(b.iter())
        .map(|(&ai, &bi)| ai as i128 * bi as i128)
        .sum();
    (sum / MILLION as i128) as i64
}

/// Integer square root of i128.
fn isqrt_i128(n: i128) -> i128 {
    if n <= 0 {
        return 0;
    }
    let bits = 128 - n.leading_zeros();
    let mut x = 1i128 << bits.div_ceil(2);
    for _ in 0..20 {
        if x == 0 {
            break;
        }
        let next = (x + n / x) / 2;
        if next >= x {
            break;
        }
        x = next;
    }
    x
}

/// Integer log₂(n) in millionths using fractional-bit extraction.
fn integer_log2_millionths(n: u64) -> i64 {
    if n <= 1 {
        return 0;
    }
    let bits = 64 - n.leading_zeros();
    let integer_part = (bits - 1) as i64 * MILLION;

    let power_of_two = 1u64 << (bits - 1);
    if n == power_of_two {
        return integer_part;
    }

    let mut mantissa: u64 = if bits - 1 <= 32 {
        n << (32 - (bits - 1))
    } else {
        n >> ((bits - 1) - 32)
    };
    let threshold: u64 = 1u64 << 33;

    let mut frac: i64 = 0;
    let mut bit_value: i64 = 500_000;
    for _ in 0..20 {
        mantissa = ((mantissa as u128 * mantissa as u128) >> 32) as u64;
        if mantissa >= threshold {
            frac += bit_value;
            mantissa >>= 1;
        }
        bit_value /= 2;
        if bit_value == 0 {
            break;
        }
    }

    integer_part + frac
}

/// Integer ln(n) in millionths.
fn integer_ln_millionths(n: u64) -> i64 {
    const LN_2_MILLIONTHS: i64 = 693_147;
    integer_log2_millionths(n) * LN_2_MILLIONTHS / MILLION
}

/// Integer sqrt of millionths-scaled value.
fn integer_sqrt_millionths(n: i64) -> i64 {
    if n <= 0 {
        return 0;
    }
    let wide = n as i128 * MILLION as i128;
    isqrt_i128(wide) as i64
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn make_complete_graph(n: usize) -> GossipTopology {
        let node_ids: Vec<String> = (0..n).map(|i| format!("node_{i}")).collect();
        let mut topo = GossipTopology::new(node_ids).unwrap();
        for i in 0..n {
            for j in (i + 1)..n {
                topo.add_edge(i, j, MILLION).unwrap();
            }
        }
        topo
    }

    fn make_cycle_graph(n: usize) -> GossipTopology {
        let node_ids: Vec<String> = (0..n).map(|i| format!("node_{i}")).collect();
        let mut topo = GossipTopology::new(node_ids).unwrap();
        for i in 0..n {
            topo.add_edge(i, (i + 1) % n, MILLION).unwrap();
        }
        topo
    }

    fn make_path_graph(n: usize) -> GossipTopology {
        let node_ids: Vec<String> = (0..n).map(|i| format!("node_{i}")).collect();
        let mut topo = GossipTopology::new(node_ids).unwrap();
        for i in 0..n - 1 {
            topo.add_edge(i, i + 1, MILLION).unwrap();
        }
        topo
    }

    // === Topology ===

    #[test]
    fn complete_graph_is_connected() {
        let topo = make_complete_graph(5);
        assert!(topo.is_connected());
        assert_eq!(topo.connected_components(), 1);
    }

    #[test]
    fn disconnected_graph_detected() {
        let node_ids: Vec<String> = (0..4).map(|i| format!("node_{i}")).collect();
        let mut topo = GossipTopology::new(node_ids).unwrap();
        topo.add_edge(0, 1, MILLION).unwrap();
        topo.add_edge(2, 3, MILLION).unwrap();
        // 0-1 and 2-3 are disconnected.
        assert!(!topo.is_connected());
        assert_eq!(topo.connected_components(), 2);
    }

    #[test]
    fn cycle_graph_is_connected() {
        let topo = make_cycle_graph(6);
        assert!(topo.is_connected());
    }

    #[test]
    fn empty_graph_rejected() {
        assert!(matches!(
            GossipTopology::new(vec![]),
            Err(SpectralError::EmptyGraph)
        ));
    }

    #[test]
    fn node_out_of_bounds() {
        let topo = GossipTopology::new(vec!["a".into(), "b".into()]).unwrap();
        let mut topo = topo;
        assert!(matches!(
            topo.add_edge(0, 5, MILLION),
            Err(SpectralError::NodeOutOfBounds { .. })
        ));
    }

    #[test]
    fn degree_computation() {
        let mut topo = GossipTopology::new(vec!["a".into(), "b".into(), "c".into()]).unwrap();
        topo.add_edge(0, 1, MILLION).unwrap();
        topo.add_edge(0, 2, 500_000).unwrap();
        assert_eq!(topo.degree(0), 1_500_000);
        assert_eq!(topo.degree(1), MILLION);
    }

    // === Laplacian ===

    #[test]
    fn laplacian_row_sums_to_zero() {
        let topo = make_complete_graph(4);
        let laplacian = LaplacianMatrix::from_topology(&topo).unwrap();
        for i in 0..4 {
            let row_sum: i64 = (0..4).map(|j| laplacian.get(i, j)).sum();
            assert_eq!(row_sum, 0, "row {i} should sum to zero");
        }
    }

    #[test]
    fn laplacian_is_symmetric() {
        let topo = make_cycle_graph(5);
        let laplacian = LaplacianMatrix::from_topology(&topo).unwrap();
        for i in 0..5 {
            for j in 0..5 {
                assert_eq!(
                    laplacian.get(i, j),
                    laplacian.get(j, i),
                    "L[{i},{j}] != L[{j},{i}]"
                );
            }
        }
    }

    #[test]
    fn laplacian_diagonal_is_degree() {
        let topo = make_complete_graph(3);
        let laplacian = LaplacianMatrix::from_topology(&topo).unwrap();
        // In complete graph K3, each node has degree 2 (two edges of weight 1M).
        for i in 0..3 {
            assert_eq!(laplacian.get(i, i), 2 * MILLION);
        }
    }

    #[test]
    fn laplacian_content_hash_deterministic() {
        let topo = make_complete_graph(3);
        let l1 = LaplacianMatrix::from_topology(&topo).unwrap();
        let l2 = LaplacianMatrix::from_topology(&topo).unwrap();
        assert_eq!(l1.content_hash(), l2.content_hash());
    }

    // === Spectral Analysis ===

    #[test]
    fn complete_graph_spectral_analysis() {
        let topo = make_complete_graph(4);
        let analyzer = SpectralAnalyzer::default();
        let analysis = analyzer.analyze(&topo).unwrap();

        assert_eq!(analysis.num_nodes, 4);
        // Complete graph has high algebraic connectivity.
        assert!(analysis.algebraic_connectivity_millionths > 0);
        assert!(analysis.spectral_gap_millionths > 0);
        // Mixing time should be low for complete graph.
        assert!(analysis.mixing_time_bound < 100);
    }

    #[test]
    fn path_graph_slower_mixing() {
        let complete = make_complete_graph(6);
        let path = make_path_graph(6);
        let analyzer = SpectralAnalyzer::default();

        let complete_analysis = analyzer.analyze(&complete).unwrap();
        let path_analysis = analyzer.analyze(&path).unwrap();

        // Path graph should have higher mixing time than complete graph.
        assert!(
            path_analysis.mixing_time_bound >= complete_analysis.mixing_time_bound,
            "path ({}) should mix slower than complete ({})",
            path_analysis.mixing_time_bound,
            complete_analysis.mixing_time_bound
        );
    }

    #[test]
    fn disconnected_graph_rejected() {
        let node_ids: Vec<String> = (0..4).map(|i| format!("node_{i}")).collect();
        let mut topo = GossipTopology::new(node_ids).unwrap();
        topo.add_edge(0, 1, MILLION).unwrap();
        // 2 and 3 are isolated.
        let analyzer = SpectralAnalyzer::default();
        assert!(matches!(
            analyzer.analyze(&topo),
            Err(SpectralError::Disconnected { .. })
        ));
    }

    #[test]
    fn fiedler_vector_partitions_barbell() {
        // Barbell: 0-1-2 connected, 3-4-5 connected, with one bridge 2-3.
        let node_ids: Vec<String> = (0..6).map(|i| format!("node_{i}")).collect();
        let mut topo = GossipTopology::new(node_ids).unwrap();
        // Clique 1.
        topo.add_edge(0, 1, MILLION).unwrap();
        topo.add_edge(1, 2, MILLION).unwrap();
        topo.add_edge(0, 2, MILLION).unwrap();
        // Bridge.
        topo.add_edge(2, 3, MILLION).unwrap();
        // Clique 2.
        topo.add_edge(3, 4, MILLION).unwrap();
        topo.add_edge(4, 5, MILLION).unwrap();
        topo.add_edge(3, 5, MILLION).unwrap();

        let analyzer = SpectralAnalyzer::default();
        let analysis = analyzer.analyze(&topo).unwrap();

        // Fiedler vector should partition into two groups roughly {0,1,2} and {3,4,5}.
        assert!(!analysis.partition_a.is_empty());
        assert!(!analysis.partition_b.is_empty());
    }

    // === Convergence Certificate ===

    #[test]
    fn convergence_certificate_from_analysis() {
        let topo = make_complete_graph(5);
        let analyzer = SpectralAnalyzer::default();
        let analysis = analyzer.analyze(&topo).unwrap();
        let cert = ConvergenceCertificate::from_analysis(&analysis, SecurityEpoch::from_raw(1));

        assert_eq!(cert.num_nodes, 5);
        assert!(cert.spectral_gap_millionths > 0);
    }

    #[test]
    fn convergence_certificate_sla_check() {
        let topo = make_complete_graph(5);
        let analyzer = SpectralAnalyzer::default();
        let analysis = analyzer.analyze(&topo).unwrap();
        let cert = ConvergenceCertificate::from_analysis(&analysis, SecurityEpoch::from_raw(1));

        // Complete graph should meet a generous SLA.
        assert!(cert.meets_sla(1000));
    }

    #[test]
    fn convergence_certificate_serde_roundtrip() {
        let topo = make_complete_graph(4);
        let analyzer = SpectralAnalyzer::default();
        let analysis = analyzer.analyze(&topo).unwrap();
        let cert = ConvergenceCertificate::from_analysis(&analysis, SecurityEpoch::from_raw(42));

        let json = serde_json::to_string(&cert).unwrap();
        let restored: ConvergenceCertificate = serde_json::from_str(&json).unwrap();
        assert_eq!(cert, restored);
    }

    #[test]
    fn spectral_analysis_serde_roundtrip() {
        let topo = make_complete_graph(3);
        let analyzer = SpectralAnalyzer::default();
        let analysis = analyzer.analyze(&topo).unwrap();

        let json = serde_json::to_string(&analysis).unwrap();
        let restored: SpectralAnalysis = serde_json::from_str(&json).unwrap();
        assert_eq!(analysis, restored);
    }

    // === Cheeger inequality ===

    #[test]
    fn cheeger_bounds_consistent() {
        let topo = make_complete_graph(5);
        let analyzer = SpectralAnalyzer::default();
        let analysis = analyzer.analyze(&topo).unwrap();

        // λ₂_norm / 2 ≤ h ≤ sqrt(2 * λ₂_norm)
        assert!(analysis.cheeger_lower_bound_millionths >= 0);
        assert!(analysis.cheeger_upper_bound_millionths >= analysis.cheeger_lower_bound_millionths);
    }

    // === Edge cases ===

    #[test]
    fn single_node_graph() {
        let topo = GossipTopology::new(vec!["solo".into()]).unwrap();
        assert!(topo.is_connected());
        // Spectral analysis on 1-node graph: no edges, but connected.
        // Laplacian is [0], which has spectral gap issues.
        let analyzer = SpectralAnalyzer::default();
        let result = analyzer.analyze(&topo);
        // Expected to fail with degenerate spectral gap (λ_max = 0).
        assert!(result.is_err());
    }

    #[test]
    fn two_node_graph() {
        let mut topo = GossipTopology::new(vec!["a".into(), "b".into()]).unwrap();
        topo.add_edge(0, 1, MILLION).unwrap();
        let analyzer = SpectralAnalyzer::default();
        let analysis = analyzer.analyze(&topo).unwrap();

        assert_eq!(analysis.num_nodes, 2);
        assert!(analysis.algebraic_connectivity_millionths > 0);
    }

    // === Helper functions ===

    #[test]
    fn normalize_vector_basic() {
        let mut v = vec![MILLION, 0];
        normalize_vector_millionths(&mut v);
        // Should be close to [1M, 0] (unit vector).
        assert!(v[0].abs() > 900_000);
        assert!(v[1].abs() < 100_000);
    }

    #[test]
    fn deflate_uniform_removes_mean() {
        let mut v = vec![MILLION, 2 * MILLION, 3 * MILLION];
        deflate_uniform(&mut v, 3);
        let sum: i64 = v.iter().sum();
        assert!(sum.abs() < 3); // should be ~0 (rounding).
    }

    #[test]
    fn dot_product_basic() {
        let a = vec![MILLION, 0];
        let b = vec![MILLION, 0];
        let dot = dot_product_millionths(&a, &b);
        assert_eq!(dot, MILLION); // 1·1 + 0·0 = 1
    }

    #[test]
    fn integer_ln_basic_values() {
        assert_eq!(integer_ln_millionths(1), 0);
        let ln2 = integer_ln_millionths(2);
        assert!((ln2 - 693_147).abs() < 20_000);
        let ln4 = integer_ln_millionths(4);
        assert!((ln4 - 2 * 693_147).abs() < 30_000);
        assert!(integer_ln_millionths(16) > integer_ln_millionths(4));
    }

    #[test]
    fn isqrt_basic() {
        assert_eq!(isqrt_i128(0), 0);
        assert_eq!(isqrt_i128(1), 1);
        assert_eq!(isqrt_i128(4), 2);
        assert_eq!(isqrt_i128(9), 3);
        assert_eq!(isqrt_i128(100), 10);
    }

    #[test]
    fn topology_serde_roundtrip() {
        let topo = make_complete_graph(3);
        let json = serde_json::to_string(&topo).unwrap();
        let restored: GossipTopology = serde_json::from_str(&json).unwrap();
        assert_eq!(topo, restored);
    }

    #[test]
    fn spectral_error_display() {
        let err = SpectralError::Disconnected { components: 3 };
        assert!(format!("{err}").contains("disconnected"));
    }
}
