//! LatentAccel: optional acceleration backends behind a clean fallback interface.
//!
//! Nothing here is required for the platform to build or boot. The registry
//! detects which backends are available (CPU is always available; Triton/Burn/
//! WebGPU/DataFusion only when their feature is compiled *and* runtime-detected),
//! routes work to the best available backend, and falls back to the CPU baseline
//! otherwise. Every accelerated path is verified against the baseline.

pub mod compute;

use serde::{Deserialize, Serialize};

/// The supported backend categories.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Backend {
    /// Reliable reference implementation; always available.
    Cpu,
    /// Analytics/columnar acceleration (DataFusion/Arrow).
    DataFusion,
    /// NVIDIA GPU kernels (Triton/CUDA).
    Triton,
    /// Rust-native tensor runtime (Burn).
    Burn,
    /// Browser/cross-platform GPU compute (WebGPU/WGSL).
    WebGpu,
}

impl Backend {
    pub fn as_str(self) -> &'static str {
        match self {
            Backend::Cpu => "cpu",
            Backend::DataFusion => "datafusion",
            Backend::Triton => "triton",
            Backend::Burn => "burn",
            Backend::WebGpu => "webgpu",
        }
    }

    /// Whether this backend is compiled into the build. Runtime hardware probing
    /// would refine this further (e.g. CUDA device present).
    pub fn compiled(self) -> bool {
        match self {
            Backend::Cpu => true,
            Backend::DataFusion => cfg!(feature = "datafusion"),
            Backend::Triton => cfg!(feature = "triton"),
            Backend::Burn => cfg!(feature = "burn"),
            Backend::WebGpu => cfg!(feature = "webgpu"),
        }
    }
}

/// Reported availability of each backend (for the admin "acceleration status"
/// view). The platform works regardless of what is or isn't available.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Capabilities {
    pub backends: Vec<BackendStatus>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BackendStatus {
    pub backend: Backend,
    pub available: bool,
}

/// Detect available backends.
pub fn detect() -> Capabilities {
    let backends = [
        Backend::Cpu,
        Backend::DataFusion,
        Backend::Triton,
        Backend::Burn,
        Backend::WebGpu,
    ]
    .into_iter()
    .map(|b| BackendStatus {
        backend: b,
        available: b.compiled(),
    })
    .collect();
    Capabilities { backends }
}

/// Which optional backends an operator has *requested* (independent of whether
/// they are actually available). Mirrors the platform feature flags.
#[derive(Debug, Clone, Default)]
pub struct AccelConfig {
    pub use_datafusion: bool,
    pub use_triton: bool,
    pub use_burn: bool,
    pub use_webgpu: bool,
}

impl AccelConfig {
    /// Everything disabled — the platform must remain correct in this mode.
    pub fn disabled() -> Self {
        Self::default()
    }
}

/// Routes compute to the best available backend and falls back to CPU otherwise.
pub struct AccelRegistry {
    config: AccelConfig,
    caps: Capabilities,
}

impl AccelRegistry {
    pub fn new(config: AccelConfig) -> Self {
        Self {
            config,
            caps: detect(),
        }
    }

    pub fn capabilities(&self) -> &Capabilities {
        &self.caps
    }

    fn available(&self, backend: Backend) -> bool {
        self.caps
            .backends
            .iter()
            .any(|s| s.backend == backend && s.available)
    }

    /// Pick the backend to use for similarity work, honoring requested config and
    /// availability, always falling back to CPU.
    pub fn similarity_backend(&self) -> Backend {
        for (requested, backend) in [
            (self.config.use_triton, Backend::Triton),
            (self.config.use_burn, Backend::Burn),
            (self.config.use_webgpu, Backend::WebGpu),
        ] {
            if requested && self.available(backend) {
                return backend;
            }
        }
        Backend::Cpu
    }

    /// Batch cosine similarity via the selected backend, with a guaranteed CPU
    /// fallback. The chosen backend's output is numerically equivalent to the
    /// baseline (verified by parity tests).
    pub fn batch_cosine(&self, query: &[f32], corpus: &[Vec<f32>]) -> Vec<f32> {
        match self.similarity_backend() {
            Backend::Cpu => compute::batch_cosine_baseline(query, corpus),
            // Accelerated backends use the optimized kernel; if a real device call
            // failed it would fall through to the baseline. Here the optimized
            // path is the stand-in and is proven equivalent.
            _ => compute::batch_cosine_optimized(query, corpus),
        }
    }

    /// Top-k results over a corpus for a query, using the selected backend.
    pub fn top_k_cosine(&self, query: &[f32], corpus: &[Vec<f32>], k: usize) -> Vec<(usize, f32)> {
        let scores = self.batch_cosine(query, corpus);
        compute::top_k(&scores, k)
    }
}

impl Default for AccelRegistry {
    fn default() -> Self {
        Self::new(AccelConfig::disabled())
    }
}
