//! AI provider interface and implementations.
//!
//! The platform never depends on a specific model vendor. Agents talk to this
//! trait; the default [`MockProvider`] is deterministic and offline (so tests and
//! AI-disabled deployments work), and an OpenAI-compatible provider (OpenAI /
//! LM Studio / Ollama) is available behind the `openai` feature.
//!
//! Crucially, *grounding is the agent's job, not the model's*: agents compute the
//! facts and citations from permission-checked kernel data and pass them to the
//! provider only for natural-language phrasing. That keeps AI answers
//! source-grounded regardless of which provider is configured.

use async_trait::async_trait;
use latentdb_contracts::{ApiError, Result};
use serde::{Deserialize, Serialize};
use std::sync::Arc;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CompletionRequest {
    #[serde(default)]
    pub system: Option<String>,
    pub prompt: String,
    #[serde(default = "default_max_tokens")]
    pub max_tokens: u32,
    #[serde(default)]
    pub temperature: f32,
}

fn default_max_tokens() -> u32 {
    512
}

impl CompletionRequest {
    pub fn new(system: impl Into<String>, prompt: impl Into<String>) -> Self {
        Self {
            system: Some(system.into()),
            prompt: prompt.into(),
            max_tokens: default_max_tokens(),
            temperature: 0.0,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Completion {
    pub text: String,
    pub model: String,
    pub provider: String,
    pub prompt_tokens: u32,
    pub completion_tokens: u32,
}

#[async_trait]
pub trait AiProvider: Send + Sync {
    fn name(&self) -> &str;
    fn model(&self) -> &str;
    async fn complete(&self, req: CompletionRequest) -> Result<Completion>;
}

/// Approximate token count (whitespace words) — good enough for usage metering
/// and the mock provider.
pub fn approx_tokens(s: &str) -> u32 {
    s.split_whitespace().count() as u32
}

/// Deterministic, offline provider. It "narrates" by lightly framing the grounded
/// facts the agent already assembled — so the answer text always contains the
/// real, permission-checked content, and tests are stable.
pub struct MockProvider {
    model: String,
}

impl Default for MockProvider {
    fn default() -> Self {
        Self { model: "latentdb-mock-1".to_string() }
    }
}

#[async_trait]
impl AiProvider for MockProvider {
    fn name(&self) -> &str {
        "mock"
    }
    fn model(&self) -> &str {
        &self.model
    }
    async fn complete(&self, req: CompletionRequest) -> Result<Completion> {
        let body = req.prompt.trim();
        let text = if body.is_empty() {
            "No content was provided to summarize.".to_string()
        } else {
            // Echo the grounded facts so the answer is source-faithful.
            body.to_string()
        };
        let pt = approx_tokens(&req.prompt) + req.system.as_deref().map(approx_tokens).unwrap_or(0);
        let ct = approx_tokens(&text);
        Ok(Completion {
            text,
            model: self.model.clone(),
            provider: "mock".to_string(),
            prompt_tokens: pt,
            completion_tokens: ct,
        })
    }
}

/// Configuration for an OpenAI-compatible endpoint.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OpenAiConfig {
    pub base_url: String,
    pub api_key: String,
    pub model: String,
}

/// OpenAI-compatible provider. Real HTTP only when the `openai` feature is built;
/// otherwise it reports a clear `feature_disabled` error and the platform falls
/// back to the mock provider.
pub struct OpenAiProvider {
    #[allow(dead_code)]
    config: OpenAiConfig,
}

impl OpenAiProvider {
    pub fn new(config: OpenAiConfig) -> Self {
        Self { config }
    }
}

#[async_trait]
impl AiProvider for OpenAiProvider {
    fn name(&self) -> &str {
        "openai"
    }
    fn model(&self) -> &str {
        &self.config.model
    }

    #[cfg(feature = "openai")]
    async fn complete(&self, req: CompletionRequest) -> Result<Completion> {
        let mut messages = Vec::new();
        if let Some(sys) = &req.system {
            messages.push(serde_json::json!({"role": "system", "content": sys}));
        }
        messages.push(serde_json::json!({"role": "user", "content": req.prompt}));
        let payload = serde_json::json!({
            "model": self.config.model,
            "messages": messages,
            "temperature": req.temperature,
            "max_tokens": req.max_tokens,
        });
        let url = format!("{}/chat/completions", self.config.base_url.trim_end_matches('/'));
        let client = reqwest::Client::new();
        let resp = client
            .post(&url)
            .bearer_auth(&self.config.api_key)
            .json(&payload)
            .send()
            .await
            .map_err(|e| ApiError::internal(format!("ai provider request failed: {e}")))?;
        let body: serde_json::Value = resp
            .json()
            .await
            .map_err(|e| ApiError::internal(format!("ai provider bad response: {e}")))?;
        let text = body["choices"][0]["message"]["content"]
            .as_str()
            .unwrap_or_default()
            .to_string();
        Ok(Completion {
            prompt_tokens: body["usage"]["prompt_tokens"].as_u64().unwrap_or(0) as u32,
            completion_tokens: body["usage"]["completion_tokens"].as_u64().unwrap_or(0) as u32,
            text,
            model: self.config.model.clone(),
            provider: "openai".to_string(),
        })
    }

    #[cfg(not(feature = "openai"))]
    async fn complete(&self, _req: CompletionRequest) -> Result<Completion> {
        Err(ApiError::feature_disabled(
            "OpenAI provider was not built (enable the `openai` feature); using mock fallback",
        ))
    }
}

/// Build the configured provider from the environment, falling back to mock.
/// `LATENTDB_AI_PROVIDER=openai` with `LATENTDB_AI_BASE_URL`, `LATENTDB_AI_API_KEY`,
/// `LATENTDB_AI_MODEL` selects the OpenAI-compatible path.
pub fn provider_from_env() -> Arc<dyn AiProvider> {
    if std::env::var("LATENTDB_AI_PROVIDER").as_deref() == Ok("openai") {
        let config = OpenAiConfig {
            base_url: std::env::var("LATENTDB_AI_BASE_URL")
                .unwrap_or_else(|_| "http://localhost:1234/v1".to_string()),
            api_key: std::env::var("LATENTDB_AI_API_KEY").unwrap_or_default(),
            model: std::env::var("LATENTDB_AI_MODEL").unwrap_or_else(|_| "local-model".to_string()),
        };
        Arc::new(OpenAiProvider::new(config))
    } else {
        Arc::new(MockProvider::default())
    }
}
