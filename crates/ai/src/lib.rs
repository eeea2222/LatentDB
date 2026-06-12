//! LatentAI: providers, permission-aware retrieval, agents, and action safety.
//!
//! The whole AI layer is optional (gated by `enable_ai_agents`). It reads
//! enterprise data only through kernel services, so retrieval cannot bypass
//! permissions, and it mutates only through the dry-run + approval-gated action
//! planner.

pub mod action;
pub mod agents;
pub mod provider;
pub mod retrieval;

pub use action::{dry_run, execute, ActionOp, ActionPlan, AgentAction};
pub use agents::{Agents, AiAnswer};
pub use provider::{
    provider_from_env, AiProvider, Completion, CompletionRequest, OfflineProvider, OpenAiConfig,
    OpenAiProvider, UnconfiguredProvider,
};
pub use retrieval::{retrieve, RetrievedDoc};

/// The AI engine facade carried in application state. Cheap to clone.
#[derive(Clone)]
pub struct AiEngine {
    agents: Agents,
}

impl AiEngine {
    /// Build from environment configuration.
    pub fn from_env() -> Self {
        Self {
            agents: Agents::new(provider_from_env()),
        }
    }

    /// Build with an explicit provider (used in tests).
    pub fn with_provider(provider: std::sync::Arc<dyn AiProvider>) -> Self {
        Self {
            agents: Agents::new(provider),
        }
    }

    pub fn agents(&self) -> &Agents {
        &self.agents
    }
}

impl Default for AiEngine {
    fn default() -> Self {
        Self::from_env()
    }
}
