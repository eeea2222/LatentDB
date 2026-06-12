//! Compute kernels with a correctness baseline.
//!
//! The CPU baseline is the reference implementation every other backend must
//! match. The "optimized" variant stands in for what a Triton/Burn/WebGPU/
//! DataFusion adapter would produce (a different code path — precomputed norms,
//! f64 accumulation) and is verified to match the baseline within epsilon by the
//! parity tests. This is how the platform guarantees "accelerated outputs match
//! baseline outputs" while the heavy GPU adapters remain optional.

/// Naive cosine similarity (the reference).
pub fn cosine_baseline(a: &[f32], b: &[f32]) -> f32 {
    let n = a.len().min(b.len());
    let mut dot = 0.0f32;
    let mut na = 0.0f32;
    let mut nb = 0.0f32;
    for i in 0..n {
        dot += a[i] * b[i];
        na += a[i] * a[i];
        nb += b[i] * b[i];
    }
    if na == 0.0 || nb == 0.0 {
        0.0
    } else {
        dot / (na.sqrt() * nb.sqrt())
    }
}

/// Batch cosine of `query` against each row of `corpus` (reference path).
pub fn batch_cosine_baseline(query: &[f32], corpus: &[Vec<f32>]) -> Vec<f32> {
    corpus
        .iter()
        .map(|row| cosine_baseline(query, row))
        .collect()
}

/// Optimized batch cosine: precompute the query norm once and accumulate in f64.
/// Numerically equivalent to the baseline within floating-point epsilon — the
/// stand-in for an accelerated backend kernel.
pub fn batch_cosine_optimized(query: &[f32], corpus: &[Vec<f32>]) -> Vec<f32> {
    let qnorm: f64 = query
        .iter()
        .map(|&x| (x as f64) * (x as f64))
        .sum::<f64>()
        .sqrt();
    if qnorm == 0.0 {
        return vec![0.0; corpus.len()];
    }
    corpus
        .iter()
        .map(|row| {
            let n = query.len().min(row.len());
            let mut dot = 0.0f64;
            let mut rn = 0.0f64;
            for i in 0..n {
                let q = query[i] as f64;
                let r = row[i] as f64;
                dot += q * r;
                rn += r * r;
            }
            let rnorm = rn.sqrt();
            if rnorm == 0.0 {
                0.0
            } else {
                (dot / (qnorm * rnorm)) as f32
            }
        })
        .collect()
}

/// Top-k indices+scores, highest first. Stable on ties by index.
pub fn top_k(scores: &[f32], k: usize) -> Vec<(usize, f32)> {
    let mut idx: Vec<(usize, f32)> = scores.iter().cloned().enumerate().collect();
    idx.sort_by(|a, b| {
        b.1.partial_cmp(&a.1)
            .unwrap_or(std::cmp::Ordering::Equal)
            .then(a.0.cmp(&b.0))
    });
    idx.truncate(k);
    idx
}

/// Dot product (reference).
pub fn dot(a: &[f32], b: &[f32]) -> f32 {
    let n = a.len().min(b.len());
    (0..n).map(|i| a[i] * b[i]).sum()
}
