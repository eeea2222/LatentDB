//! Permission-aware retrieval (RAG grounding).
//!
//! Retrieval goes exclusively through `Kernel::list_records`, which already
//! applies tenant scope, record-level permission, and field-level projection.
//! Because the AI layer has no other way to read data (the kernel pool is
//! private), it is *structurally impossible* for retrieval to surface records or
//! fields the actor cannot access — satisfying the rule that AI retrieval can
//! never expose inaccessible data.

use latentdb_contracts::{AuthContext, RecordFilter};
use latentdb_kernel::Kernel;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RetrievedDoc {
    /// The source record id — used as the citation reference.
    pub source_id: String,
    pub object_type: String,
    pub title: String,
    pub snippet: String,
    pub score: f64,
}

/// Retrieve up to `limit` permission-checked documents matching `query` across
/// the given object types (or all visible object types when none are specified).
pub async fn retrieve(
    kernel: &Kernel,
    ctx: &AuthContext,
    query: &str,
    object_types: &[String],
    limit: usize,
) -> latentdb_contracts::Result<Vec<RetrievedDoc>> {
    let types: Vec<String> = if object_types.is_empty() {
        kernel
            .list_object_types(ctx)
            .await?
            .into_iter()
            .map(|o| o.key)
            .collect()
    } else {
        object_types.to_vec()
    };

    let mut docs = Vec::new();
    for ot in &types {
        // `list_records` is the permission boundary: results are already scoped
        // and field-projected for this actor.
        let filter = RecordFilter {
            search: if query.is_empty() {
                None
            } else {
                Some(query.to_string())
            },
            page: latentdb_contracts::Page {
                limit: limit as i64,
                offset: 0,
            },
            ..Default::default()
        };
        let Ok(list) = kernel.list_records(ctx, ot, &filter).await else {
            continue; // no search permission on this type; skip silently
        };
        let otype = kernel.get_object_type(ctx, ot).await.ok();
        for rec in list.items {
            let title = otype
                .as_ref()
                .and_then(|o| o.display_field.as_ref())
                .and_then(|f| rec.data.get(f))
                .and_then(|v| v.as_str())
                .map(|s| s.to_string())
                .unwrap_or_else(|| format!("{ot}:{}", rec.id));
            let snippet = snippet_of(&rec, otype.as_ref());
            let score = score(query, &title, &snippet);
            docs.push(RetrievedDoc {
                source_id: rec.id,
                object_type: ot.clone(),
                title,
                snippet,
                score,
            });
        }
    }

    docs.sort_by(|a, b| {
        b.score
            .partial_cmp(&a.score)
            .unwrap_or(std::cmp::Ordering::Equal)
    });
    docs.truncate(limit);
    Ok(docs)
}

fn snippet_of(
    rec: &latentdb_contracts::Record,
    object_type: Option<&latentdb_contracts::ObjectTypeDef>,
) -> String {
    let mut parts = Vec::new();
    for (k, v) in &rec.data {
        let Some(field) = object_type.and_then(|ot| ot.field(k)) else {
            continue;
        };
        if !field.ai_visible {
            continue;
        }
        let val = match v {
            serde_json::Value::String(s) => s.clone(),
            serde_json::Value::Null => continue,
            other => other.to_string(),
        };
        parts.push(format!("{k}={val}"));
        if parts.len() >= 8 {
            break;
        }
    }
    parts.join(", ")
}

/// Simple keyword-overlap score; the semantic-search feature flag (Phase 6) can
/// swap this for vector similarity, with this as the fallback.
fn score(query: &str, title: &str, snippet: &str) -> f64 {
    if query.is_empty() {
        return 1.0;
    }
    let haystack = format!("{title} {snippet}").to_lowercase();
    let mut hits = 0.0;
    let terms: Vec<&str> = query.split_whitespace().collect();
    for term in &terms {
        if haystack.contains(&term.to_lowercase()) {
            hits += 1.0;
        }
    }
    if terms.is_empty() {
        1.0
    } else {
        hits / terms.len() as f64
    }
}
