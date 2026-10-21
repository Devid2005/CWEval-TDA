#!/usr/bin/env python3
"""
Post-analysis for the TDA article.

IMPORTANT:
- This script DOES NOT modify the frozen TDA experiment.
- It only reads the finalized run and writes derived article outputs
  to a separate output directory.
- It adds an exhaustive 2^20 paired sign-flip sensitivity analysis,
  exact paired Betti-curve tests, and article-oriented figures.
"""

from __future__ import annotations

import argparse
from pathlib import Path
import json
import numpy as np
import pandas as pd
import matplotlib.pyplot as plt


PRIMARY_METRICS = [
    "h0_significant_count",
    "h0_mean_persistence",
    "h0_max_persistence",
    "h0_entropy",
    "h0_betti_auc",
    "h1_significant_count",
    "h1_mean_persistence",
    "h1_max_persistence",
    "h1_entropy",
    "h1_betti_auc",
]


def cwe_number(pair_id: str) -> int:
    # pair_id example: cwe_079_0_flask
    return int(pair_id.split("_")[1])


def benjamini_hochberg(pvalues):
    pvalues = np.asarray(pvalues, dtype=float)
    n = len(pvalues)
    order = np.argsort(pvalues)
    q = np.empty(n, dtype=float)
    running = 1.0
    for reverse_rank, idx in enumerate(order[::-1], start=1):
        rank = n - reverse_rank + 1
        running = min(running, pvalues[idx] * n / rank)
        q[idx] = min(running, 1.0)
    return q


def exact_signflip_p_from_diff(diff: np.ndarray, stat_fn=None, chunk_size=32768):
    """
    Exact two-sided paired sign-flip test over all 2^n label swaps.

    Default statistic = abs(mean(diff)).
    """
    diff = np.asarray(diff, dtype=np.float64)
    n = len(diff)
    if stat_fn is None:
        observed = abs(float(np.mean(diff)))
        def batch_stat(signs):
            return np.abs(np.mean(signs * diff[None, :], axis=1))
    else:
        observed = float(stat_fn(diff))
        def batch_stat(signs):
            return stat_fn(signs * diff[None, :], batched=True)

    if n == 0 or np.allclose(diff, 0.0):
        return 1.0, observed

    total = 1 << n
    extreme = 0

    bit_positions = np.arange(n, dtype=np.uint32)
    for start in range(0, total, chunk_size):
        stop = min(start + chunk_size, total)
        values = np.arange(start, stop, dtype=np.uint32)
        bits = ((values[:, None] >> bit_positions) & 1).astype(np.int8)
        signs = bits * 2 - 1
        stats = batch_stat(signs)
        extreme += int(np.count_nonzero(stats >= observed - 1e-15))

    return extreme / total, observed


def exact_scalar_tests(metrics: pd.DataFrame) -> pd.DataFrame:
    pair_ids = sorted(metrics["pair_id"].unique(), key=cwe_number)
    rows = []

    for metric in PRIMARY_METRICS:
        pivot = metrics.pivot(index="pair_id", columns="class", values=metric).loc[pair_ids]
        secure = pivot["secure"].to_numpy(dtype=float)
        vulnerable = pivot["vulnerable"].to_numpy(dtype=float)
        diff = vulnerable - secure

        p_exact, observed = exact_signflip_p_from_diff(diff)

        rows.append({
            "metric": metric,
            "pair_count": len(diff),
            "secure_mean": float(np.mean(secure)),
            "vulnerable_mean": float(np.mean(vulnerable)),
            "mean_difference_vulnerable_minus_secure": float(np.mean(diff)),
            "exact_signflip_p": p_exact,
            "observed_abs_mean_difference": observed,
            "secure_greater_pairs": int(np.sum(secure > vulnerable)),
            "vulnerable_greater_pairs": int(np.sum(vulnerable > secure)),
            "equal_pairs": int(np.sum(vulnerable == secure)),
        })

    out = pd.DataFrame(rows)
    out["exact_bh_q_primary"] = benjamini_hochberg(out["exact_signflip_p"].to_numpy())
    out["exact_significant_fdr_0_05"] = out["exact_bh_q_primary"] < 0.05
    return out


def exact_betti_test(run_dir: Path, metrics: pd.DataFrame, dim: int):
    pair_ids = sorted(metrics["pair_id"].unique(), key=cwe_number)
    by_pair = {}
    for _, row in metrics.iterrows():
        by_pair.setdefault(row["pair_id"], {})[row["class"]] = row["sample_id"]

    paired = []
    for pair_id in pair_ids:
        secure_id = by_pair[pair_id]["secure"]
        vulnerable_id = by_pair[pair_id]["vulnerable"]

        secure_curve = np.load(run_dir / "topology" / f"{secure_id}_H{dim}_betti.npy")
        vulnerable_curve = np.load(run_dir / "topology" / f"{vulnerable_id}_H{dim}_betti.npy")
        paired.append(vulnerable_curve - secure_curve)

    paired = np.vstack(paired)

    def rms_stat(x, batched=False):
        if batched:
            # x: permutations x pairs x epsilon
            mean_curves = np.mean(x, axis=1)
            return np.sqrt(np.mean(mean_curves ** 2, axis=1))
        mean_curve = np.mean(x, axis=0)
        return float(np.sqrt(np.mean(mean_curve ** 2)))

    # Exact enumeration, but signs must act at PAIR level and across the whole curve.
    n = paired.shape[0]
    observed = rms_stat(paired)
    total = 1 << n
    extreme = 0
    chunk_size = 16384
    bit_positions = np.arange(n, dtype=np.uint32)

    for start in range(0, total, chunk_size):
        stop = min(start + chunk_size, total)
        values = np.arange(start, stop, dtype=np.uint32)
        bits = ((values[:, None] >> bit_positions) & 1).astype(np.int8)
        signs = (bits * 2 - 1).astype(np.float64)
        permuted = signs[:, :, None] * paired[None, :, :]
        stats = rms_stat(permuted, batched=True)
        extreme += int(np.count_nonzero(stats >= observed - 1e-15))

    return {
        "homology_dimension": dim,
        "pair_count": n,
        "statistic": "RMS distance between mean paired Betti curves",
        "observed": observed,
        "exact_signflip_p": extreme / total,
        "exact_permutations": total,
    }


def add_regression_line(ax, x, y):
    if len(x) >= 2 and np.std(x) > 0:
        coef = np.polyfit(x, y, 1)
        grid = np.linspace(np.min(x), np.max(x), 100)
        ax.plot(grid, coef[0] * grid + coef[1], linestyle="--", linewidth=1.4)


def make_length_topology_figures(metrics: pd.DataFrame, out_dir: Path):
    for metric, label in [
        ("h0_mean_persistence", "H0 mean persistence"),
        ("h0_betti_auc", "H0 Betti-curve area"),
    ]:
        fig, ax = plt.subplots(figsize=(8, 6))

        for cls, marker in [("secure", "o"), ("vulnerable", "s")]:
            part = metrics[metrics["class"] == cls]
            ax.scatter(
                part["source_token_count"],
                part[metric],
                label=cls,
                marker=marker,
                alpha=0.8,
            )

        x = metrics["source_token_count"].to_numpy(dtype=float)
        y = metrics[metric].to_numpy(dtype=float)
        add_regression_line(ax, x, y)

        ax.set_xlabel("CodeBERT source token count")
        ax.set_ylabel(label)
        ax.set_title(f"Source length vs {label}")
        ax.legend()
        fig.tight_layout()
        fig.savefig(out_dir / f"tokens_vs_{metric}.png", dpi=220)
        plt.close(fig)


def make_classifier_figure(run_dir: Path, out_dir: Path):
    path = run_dir / "statistics" / "exploratory_classification.csv"
    df = pd.read_csv(path)

    pivot = df.pivot(index="feature_set", columns="model", values="balanced_accuracy")
    preferred_order = [x for x in ["length_only", "topology_only", "topology_plus_length"] if x in pivot.index]
    pivot = pivot.loc[preferred_order]

    ax = pivot.plot(kind="bar", figsize=(9, 6))
    ax.axhline(0.5, linestyle="--", linewidth=1.2)
    ax.set_ylim(0.0, 1.0)
    ax.set_ylabel("Balanced accuracy")
    ax.set_xlabel("Feature set")
    ax.set_title("Exploratory discrimination by feature set")
    ax.legend(title="Model")
    plt.xticks(rotation=0)
    plt.tight_layout()
    plt.savefig(out_dir / "classification_feature_sets.png", dpi=220)
    plt.close()


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--run-dir", required=True, type=Path)
    parser.add_argument("--output-dir", required=True, type=Path)
    args = parser.parse_args()

    run_dir = args.run_dir.resolve()
    out_dir = args.output_dir.resolve()
    out_dir.mkdir(parents=True, exist_ok=True)

    metrics = pd.read_csv(run_dir / "topology" / "topological_metrics.csv")

    exact_scalar = exact_scalar_tests(metrics)
    exact_scalar.to_csv(out_dir / "exact_scalar_signflip_tests.csv", index=False)

    betti_rows = [
        exact_betti_test(run_dir, metrics, 0),
        exact_betti_test(run_dir, metrics, 1),
    ]
    pd.DataFrame(betti_rows).to_csv(out_dir / "exact_betti_curve_tests.csv", index=False)

    make_length_topology_figures(metrics, out_dir)
    make_classifier_figure(run_dir, out_dir)

    summary = {
        "run_dir": str(run_dir),
        "exact_scalar_tests": exact_scalar.to_dict(orient="records"),
        "exact_betti_tests": betti_rows,
        "note": (
            "These are post-analysis sensitivity checks. "
            "The original frozen 50,000-permutation analysis remains the primary analysis."
        ),
    }
    with open(out_dir / "article_post_analysis_summary.json", "w", encoding="utf-8") as f:
        json.dump(summary, f, indent=2)

    print("=" * 72)
    print("ARTICLE POST-ANALYSIS COMPLETE")
    print("Output:", out_dir)
    print()
    print(exact_scalar[
        ["metric", "exact_signflip_p", "exact_bh_q_primary", "exact_significant_fdr_0_05"]
    ].to_string(index=False))
    print()
    print(pd.DataFrame(betti_rows).to_string(index=False))
    print("=" * 72)


if __name__ == "__main__":
    main()
