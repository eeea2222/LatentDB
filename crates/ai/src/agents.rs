//! The agent suite: Finance, Procurement, Sales/CX, HR, and BI.
//!
//! Each agent computes its facts and citations from permission-checked kernel
//! data, then asks the provider only to phrase them. Answers therefore always
//! reference real source records the actor is allowed to see.

use crate::provider::{AiProvider, CompletionRequest};
use crate::retrieval::{retrieve, RetrievedDoc};
use latentdb_contracts::{ids, ApiError, AuthContext, RecordFilter};
use latentdb_kernel::Kernel;
use serde::{Deserialize, Serialize};
use std::sync::Arc;

/// A source-grounded answer.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AiAnswer {
    pub text: String,
    /// Source record ids the answer is grounded in (citations).
    pub citations: Vec<String>,
    pub sources: Vec<RetrievedDoc>,
    pub model: String,
    pub provider: String,
    pub used_ai: bool,
    pub prompt_tokens: u32,
    pub completion_tokens: u32,
}

#[derive(Clone)]
pub struct Agents {
    provider: Arc<dyn AiProvider>,
}

impl Agents {
    pub fn new(provider: Arc<dyn AiProvider>) -> Self {
        Self { provider }
    }

    fn guard(kernel: &Kernel) -> latentdb_contracts::Result<()> {
        if kernel.flags().enable_ai_agents {
            Ok(())
        } else {
            Err(ApiError::feature_disabled("AI agents are disabled"))
        }
    }

    /// General permission-aware Q&A over enterprise data.
    pub async fn ask(
        &self,
        kernel: &Kernel,
        ctx: &AuthContext,
        question: &str,
        object_types: &[String],
    ) -> latentdb_contracts::Result<AiAnswer> {
        Self::guard(kernel)?;
        let docs = retrieve(kernel, ctx, question, object_types, 8).await?;
        let facts = render_sources(&docs);
        let prompt = format!(
            "Question: {question}\n\nGrounded source records (cite by id):\n{facts}\n\nAnswer using only the records above and reference their ids."
        );
        self.finish(kernel, ctx, "ai.answer", &prompt, docs).await
    }

    /// Summarize a single record with its relations as grounding.
    pub async fn summarize_record(
        &self,
        kernel: &Kernel,
        ctx: &AuthContext,
        id: &str,
    ) -> latentdb_contracts::Result<AiAnswer> {
        Self::guard(kernel)?;
        let rec = kernel.get_record(ctx, id).await?; // enforces read permission
        let doc = RetrievedDoc {
            source_id: rec.id.clone(),
            object_type: rec.object_type.clone(),
            title: rec.id.clone(),
            snippet: serde_json::to_string(&rec.data).unwrap_or_default(),
            score: 1.0,
        };
        let prompt = format!(
            "Summarize this {} record concisely for a business user:\n{}\n(id: {})",
            rec.object_type,
            serde_json::to_string_pretty(&rec.data).unwrap_or_default(),
            rec.id
        );
        self.finish(kernel, ctx, "ai.answer", &prompt, vec![doc])
            .await
    }

    /// Finance agent — overdue invoices + cashflow risk, grounded in invoice ids.
    pub async fn finance_cashflow_risk(
        &self,
        kernel: &Kernel,
        ctx: &AuthContext,
    ) -> latentdb_contracts::Result<AiAnswer> {
        Self::guard(kernel)?;
        let invoices = self.list(kernel, ctx, "invoice").await;
        let today = today_str();
        let mut overdue = Vec::new();
        let mut overdue_total = 0.0;
        for inv in &invoices {
            let status = str_field(inv, "status");
            let paid = matches!(status.as_deref(), Some("paid"));
            let due = str_field(inv, "due_date");
            let is_overdue = !paid && due.as_deref().map(|d| d < today.as_str()).unwrap_or(false);
            if is_overdue {
                overdue_total += num_field(inv, "amount").unwrap_or(0.0);
                overdue.push(inv.id.clone());
            }
        }
        let facts = format!(
            "Cashflow risk assessment as of {today}:\n- Overdue invoices: {} totaling {} (minor units).\n- Overdue invoice ids: {}\nIf there are many overdue invoices, cashflow is at risk; prioritize collections.",
            overdue.len(),
            overdue_total as i64,
            short_list(&overdue),
        );
        let docs = overdue
            .iter()
            .map(|id| RetrievedDoc {
                source_id: id.clone(),
                object_type: "invoice".into(),
                title: id.clone(),
                snippet: "overdue invoice".into(),
                score: 1.0,
            })
            .collect();
        self.finish(kernel, ctx, "ai.answer", &facts, docs).await
    }

    /// Procurement agent — low-stock products, grounded in product ids.
    pub async fn procurement_low_stock(
        &self,
        kernel: &Kernel,
        ctx: &AuthContext,
    ) -> latentdb_contracts::Result<AiAnswer> {
        Self::guard(kernel)?;
        let products = self.list(kernel, ctx, "product").await;
        let mut low = Vec::new();
        for p in &products {
            let qty = num_field(p, "quantity")
                .or_else(|| num_field(p, "on_hand"))
                .unwrap_or(0.0);
            let reorder = num_field(p, "reorder_point").unwrap_or(0.0);
            if reorder > 0.0 && qty < reorder {
                low.push(p.id.clone());
            }
        }
        let facts = format!(
            "Low-stock assessment:\n- {} products are below their reorder point and should be reordered.\n- Product ids: {}\nA purchase order draft is recommended for these items.",
            low.len(),
            short_list(&low),
        );
        let docs = low
            .iter()
            .map(|id| RetrievedDoc {
                source_id: id.clone(),
                object_type: "product".into(),
                title: id.clone(),
                snippet: "low stock".into(),
                score: 1.0,
            })
            .collect();
        self.finish(kernel, ctx, "ai.answer", &facts, docs).await
    }

    /// Sales agent — deals at risk, grounded in deal ids.
    pub async fn sales_deal_risk(
        &self,
        kernel: &Kernel,
        ctx: &AuthContext,
    ) -> latentdb_contracts::Result<AiAnswer> {
        Self::guard(kernel)?;
        let deals = self.list(kernel, ctx, "deal").await;
        let today = today_str();
        let mut at_risk = Vec::new();
        let mut at_risk_value = 0.0;
        for d in &deals {
            let stage = str_field(d, "stage").unwrap_or_default();
            let closed = matches!(
                stage.as_str(),
                "won" | "lost" | "closed_won" | "closed_lost"
            );
            let close_date = str_field(d, "close_date");
            let overdue = close_date
                .as_deref()
                .map(|c| c < today.as_str())
                .unwrap_or(false);
            if !closed && (stage == "at_risk" || overdue) {
                at_risk_value += num_field(d, "amount").unwrap_or(0.0);
                at_risk.push(d.id.clone());
            }
        }
        let facts = format!(
            "Deal risk assessment as of {today}:\n- {} open deals are at risk, worth {} (minor units).\n- Deal ids: {}",
            at_risk.len(),
            at_risk_value as i64,
            short_list(&at_risk),
        );
        let docs = at_risk
            .iter()
            .map(|id| RetrievedDoc {
                source_id: id.clone(),
                object_type: "deal".into(),
                title: id.clone(),
                snippet: "at-risk deal".into(),
                score: 1.0,
            })
            .collect();
        self.finish(kernel, ctx, "ai.answer", &facts, docs).await
    }

    /// BI agent — natural-language KPI questions, routed to grounded metrics.
    pub async fn bi_answer(
        &self,
        kernel: &Kernel,
        ctx: &AuthContext,
        question: &str,
    ) -> latentdb_contracts::Result<AiAnswer> {
        Self::guard(kernel)?;
        let q = question.to_lowercase();
        if q.contains("revenue") && q.contains("risk") {
            // "Why is revenue at risk?" -> overdue invoices + at-risk deals.
            let fin = self.finance_cashflow_risk(kernel, ctx).await?;
            let sales = self.sales_deal_risk(kernel, ctx).await?;
            let mut citations = fin.citations.clone();
            citations.extend(sales.citations.clone());
            let mut sources = fin.sources.clone();
            sources.extend(sales.sources.clone());
            let facts = format!(
                "Revenue is at risk this period for two reasons:\n1) {}\n2) {}",
                fin.text, sales.text
            );
            return self
                .finish_with(kernel, ctx, &facts, citations, sources)
                .await;
        }
        if q.contains("overdue") || (q.contains("cashflow") || q.contains("cash flow")) {
            return self.finance_cashflow_risk(kernel, ctx).await;
        }
        if q.contains("low") && q.contains("stock") {
            return self.procurement_low_stock(kernel, ctx).await;
        }
        if q.contains("deal") && q.contains("risk") {
            return self.sales_deal_risk(kernel, ctx).await;
        }
        if q.contains("revenue") {
            let revenue = kernel
                .aggregate(
                    ctx,
                    "invoice",
                    latentdb_kernel::analytics::AggOp::Sum,
                    Some("amount"),
                    vec![latentdb_contracts::page::FieldFilter {
                        field: "status".into(),
                        op: latentdb_contracts::ConditionOp::Eq,
                        value: serde_json::json!("paid"),
                    }],
                )
                .await
                .unwrap_or(0.0);
            let facts = format!(
                "Recognized revenue (paid invoices) totals {} minor units.",
                revenue as i64
            );
            return self.finish(kernel, ctx, "ai.answer", &facts, vec![]).await;
        }
        // Fallback to general retrieval-grounded Q&A.
        self.ask(kernel, ctx, question, &[]).await
    }

    // --- internals ---

    async fn list(
        &self,
        kernel: &Kernel,
        ctx: &AuthContext,
        object_type: &str,
    ) -> Vec<latentdb_contracts::Record> {
        let filter = RecordFilter {
            page: latentdb_contracts::Page {
                limit: 500,
                offset: 0,
            },
            ..Default::default()
        };
        kernel
            .list_records(ctx, object_type, &filter)
            .await
            .map(|l| l.items)
            .unwrap_or_default()
    }

    async fn finish(
        &self,
        kernel: &Kernel,
        ctx: &AuthContext,
        _action: &str,
        prompt: &str,
        docs: Vec<RetrievedDoc>,
    ) -> latentdb_contracts::Result<AiAnswer> {
        let citations = docs.iter().map(|d| d.source_id.clone()).collect::<Vec<_>>();
        self.finish_with(kernel, ctx, prompt, citations, docs).await
    }

    async fn finish_with(
        &self,
        kernel: &Kernel,
        ctx: &AuthContext,
        prompt: &str,
        citations: Vec<String>,
        sources: Vec<RetrievedDoc>,
    ) -> latentdb_contracts::Result<AiAnswer> {
        let completion = self
            .provider
            .complete(CompletionRequest::new(
                "You are LatentAI, an enterprise assistant. Use only the provided source records and cite their ids. Never invent data.",
                prompt,
            ))
            .await?;

        // Audit the AI answer with grounding trail + provider metadata.
        let mut ev = latentdb_kernel::audit::event_from_public(
            ctx,
            "ai.answer",
            None,
            None,
            None,
            Some(serde_json::json!({"chars": completion.text.len()})),
        );
        ev.ai_meta = Some(serde_json::json!({
            "provider": completion.provider,
            "model": completion.model,
            "prompt_tokens": completion.prompt_tokens,
            "completion_tokens": completion.completion_tokens,
        }));
        ev.retrieved_source_ids = citations.clone();
        ev.id = ids::new_id();
        let _ = kernel.audit(&ev).await;

        Ok(AiAnswer {
            text: completion.text,
            citations,
            sources,
            model: completion.model,
            provider: completion.provider,
            used_ai: true,
            prompt_tokens: completion.prompt_tokens,
            completion_tokens: completion.completion_tokens,
        })
    }
}

fn render_sources(docs: &[RetrievedDoc]) -> String {
    if docs.is_empty() {
        return "(no accessible records matched)".to_string();
    }
    docs.iter()
        .map(|d| {
            format!(
                "- [{}] {} ({}): {}",
                d.source_id, d.title, d.object_type, d.snippet
            )
        })
        .collect::<Vec<_>>()
        .join("\n")
}

fn str_field(rec: &latentdb_contracts::Record, key: &str) -> Option<String> {
    rec.data
        .get(key)
        .and_then(|v| v.as_str())
        .map(|s| s.to_string())
}

fn num_field(rec: &latentdb_contracts::Record, key: &str) -> Option<f64> {
    rec.data.get(key).and_then(|v| v.as_f64())
}

fn short_list(ids: &[String]) -> String {
    if ids.is_empty() {
        return "(none)".to_string();
    }
    ids.iter().take(10).cloned().collect::<Vec<_>>().join(", ")
}

fn today_str() -> String {
    // Date portion of the current timestamp (YYYY-MM-DD).
    ids::now_rfc3339().chars().take(10).collect()
}
