//! Phase 6 tests: backend availability, accelerated/baseline parity, fallback,
//! and the "all acceleration disabled" guarantee.

use latentdb_accel::compute::{batch_cosine_baseline, batch_cosine_optimized, top_k};
use latentdb_accel::{AccelConfig, AccelRegistry, Backend};

fn corpus() -> Vec<Vec<f32>> {
    vec![
        vec![1.0, 0.0, 0.0],
        vec![0.0, 1.0, 0.0],
        vec![0.9, 0.1, 0.0],
        vec![0.2, 0.2, 0.96],
    ]
}

#[test]
fn cpu_is_always_available() {
    let caps = latentdb_accel::detect();
    assert!(caps
        .backends
        .iter()
        .any(|s| s.backend == Backend::Cpu && s.available));
}

#[test]
fn optimized_matches_baseline_within_epsilon() {
    let q = vec![1.0f32, 0.05, 0.0];
    let base = batch_cosine_baseline(&q, &corpus());
    let opt = batch_cosine_optimized(&q, &corpus());
    assert_eq!(base.len(), opt.len());
    for (b, o) in base.iter().zip(opt.iter()) {
        assert!((b - o).abs() < 1e-5, "parity failed: {b} vs {o}");
    }
}

#[test]
fn all_disabled_uses_cpu_and_is_correct() {
    let reg = AccelRegistry::new(AccelConfig::disabled());
    assert_eq!(reg.similarity_backend(), Backend::Cpu);
    let q = vec![1.0f32, 0.0, 0.0];
    let scores = reg.batch_cosine(&q, &corpus());
    // Row 0 is identical to the query -> cosine 1.0; row 1 orthogonal -> 0.0.
    assert!((scores[0] - 1.0).abs() < 1e-6);
    assert!(scores[1].abs() < 1e-6);
}

#[test]
fn requesting_unavailable_backend_falls_back_to_cpu() {
    // Triton/Burn/WebGPU are not compiled in the default build, so even when
    // requested the registry must fall back to CPU — and still produce correct
    // results.
    let cfg = AccelConfig {
        use_triton: true,
        use_burn: true,
        use_webgpu: true,
        use_datafusion: true,
    };
    let reg = AccelRegistry::new(cfg);
    assert_eq!(
        reg.similarity_backend(),
        Backend::Cpu,
        "must fall back when accel unavailable"
    );
    let q = vec![0.9f32, 0.1, 0.0];
    let got = reg.batch_cosine(&q, &corpus());
    let want = batch_cosine_baseline(&q, &corpus());
    for (g, w) in got.iter().zip(want.iter()) {
        assert!((g - w).abs() < 1e-5);
    }
}

#[test]
fn top_k_returns_best_matches() {
    let reg = AccelRegistry::default();
    let q = vec![1.0f32, 0.0, 0.0];
    let top = reg.top_k_cosine(&q, &corpus(), 2);
    assert_eq!(top.len(), 2);
    // Best match is row 0 (identical), then row 2 (near-parallel).
    assert_eq!(top[0].0, 0);
    assert_eq!(top[1].0, 2);
}

#[test]
fn top_k_is_stable_on_ties() {
    let scores = vec![0.5f32, 0.5, 0.1];
    let top = top_k(&scores, 2);
    assert_eq!(top[0].0, 0);
    assert_eq!(top[1].0, 1);
}
