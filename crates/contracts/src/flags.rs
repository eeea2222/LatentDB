//! Feature flags.
//!
//! Experimental and optional subsystems are gated here. The defaults encode a
//! key platform rule: **AI and all acceleration are optional**. The core platform
//! must boot and pass its tests with every experimental flag off, falling back to
//! safe baselines (configured AI provider, keyword search, primary-DB analytics, CPU
//! compute).

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FeatureFlags {
    /// Enable AI agents (retrieval, summaries, recommendations). When off, AI
    /// endpoints report `feature_disabled` and the platform is otherwise intact.
    pub enable_ai_agents: bool,
    /// Use semantic/vector search. When off, keyword/full-text fallback is used.
    pub enable_semantic_search: bool,
    /// Accelerate reports with DataFusion/Arrow. When off, primary-DB queries run.
    pub enable_datafusion_reports: bool,
    /// Use Triton CUDA kernels for similarity/scoring. When off, CPU baseline.
    pub enable_triton_accel: bool,
    /// Expose WebGPU-accelerated UI compute. When off, CPU/JS fallback.
    pub enable_webgpu_ui: bool,
    /// Use the Burn tensor runtime for local scoring. When off, simple baseline.
    pub enable_burn_runtime: bool,
    /// Enable the multi-tenant cloud control plane. When off, local/on-prem mode.
    pub enable_cloud_control_plane: bool,
    /// Allow AI agents to *execute* (not just dry-run) approved business actions.
    pub enable_agent_action_execution: bool,
    /// Enable ABAC condition evaluation on top of RBAC.
    pub enable_advanced_permissions: bool,
    /// Track usage meters (API calls, storage, tokens, ...).
    pub enable_usage_metering: bool,
    /// Enforce separation of duties on approvals: the requester of a gated
    /// transition may not decide their own approval. Off by default so
    /// single-admin tenants are not locked out of approval workflows.
    pub enable_approval_separation_of_duties: bool,
}

impl Default for FeatureFlags {
    fn default() -> Self {
        Self {
            // Safe, fully-functional defaults: AI on (provider must be configured),
            // permissions + usage metering on, all hardware acceleration and the
            // cloud control plane off until explicitly enabled.
            enable_ai_agents: true,
            enable_semantic_search: false,
            enable_datafusion_reports: false,
            enable_triton_accel: false,
            enable_webgpu_ui: false,
            enable_burn_runtime: false,
            enable_cloud_control_plane: false,
            enable_agent_action_execution: true,
            enable_advanced_permissions: true,
            enable_usage_metering: true,
            enable_approval_separation_of_duties: false,
        }
    }
}

impl FeatureFlags {
    /// Every optional/experimental subsystem disabled. The platform must remain
    /// correct in this configuration (used by a "flags-off" test).
    pub fn all_off() -> Self {
        Self {
            enable_ai_agents: false,
            enable_semantic_search: false,
            enable_datafusion_reports: false,
            enable_triton_accel: false,
            enable_webgpu_ui: false,
            enable_burn_runtime: false,
            enable_cloud_control_plane: false,
            enable_agent_action_execution: false,
            enable_advanced_permissions: false,
            enable_usage_metering: false,
            enable_approval_separation_of_duties: false,
        }
    }

    /// Load from environment variables (`LATENTDB_ENABLE_*`), falling back to the
    /// value in `Default`.
    pub fn from_env() -> Self {
        let d = Self::default();
        Self {
            enable_ai_agents: env_bool("LATENTDB_ENABLE_AI_AGENTS", d.enable_ai_agents),
            enable_semantic_search: env_bool(
                "LATENTDB_ENABLE_SEMANTIC_SEARCH",
                d.enable_semantic_search,
            ),
            enable_datafusion_reports: env_bool(
                "LATENTDB_ENABLE_DATAFUSION_REPORTS",
                d.enable_datafusion_reports,
            ),
            enable_triton_accel: env_bool("LATENTDB_ENABLE_TRITON_ACCEL", d.enable_triton_accel),
            enable_webgpu_ui: env_bool("LATENTDB_ENABLE_WEBGPU_UI", d.enable_webgpu_ui),
            enable_burn_runtime: env_bool("LATENTDB_ENABLE_BURN_RUNTIME", d.enable_burn_runtime),
            enable_cloud_control_plane: env_bool(
                "LATENTDB_ENABLE_CLOUD_CONTROL_PLANE",
                d.enable_cloud_control_plane,
            ),
            enable_agent_action_execution: env_bool(
                "LATENTDB_ENABLE_AGENT_ACTION_EXECUTION",
                d.enable_agent_action_execution,
            ),
            enable_advanced_permissions: env_bool(
                "LATENTDB_ENABLE_ADVANCED_PERMISSIONS",
                d.enable_advanced_permissions,
            ),
            enable_usage_metering: env_bool(
                "LATENTDB_ENABLE_USAGE_METERING",
                d.enable_usage_metering,
            ),
            enable_approval_separation_of_duties: env_bool(
                "LATENTDB_ENABLE_APPROVAL_SEPARATION_OF_DUTIES",
                d.enable_approval_separation_of_duties,
            ),
        }
    }
}

fn env_bool(key: &str, default: bool) -> bool {
    match std::env::var(key) {
        Ok(v) => matches!(
            v.trim().to_ascii_lowercase().as_str(),
            "1" | "true" | "yes" | "on"
        ),
        Err(_) => default,
    }
}
