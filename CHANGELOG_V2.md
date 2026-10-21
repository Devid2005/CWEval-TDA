# v2 correction summary

This version supersedes the pilot implementation identified by schema `tda-statistical-experiment-v1`.
A new pilot run is required; do not continue the old v1 run with this code.

Corrections:

1. `ripser` now receives an explicit symmetric Euclidean distance matrix with
   `distance_matrix=True`. The underlying geometry is unchanged, but the 16 x 768
   feature-matrix transpose warning is eliminated and the intended geometry is explicit.
2. Pilot viability is based on persistence-filtered H1 (`significant_count > 0`). Raw H1
   non-emptiness is reported separately. The prespecified viability threshold remains 40%.
3. Source-length/complexity sensitivity is added without changing the primary representation:
   paired token/character/unit-count comparisons, token-topology Spearman correlations, paired
   delta correlations, and length-only vs topology-only vs topology+length classification.
4. Share bundles now include point clouds, package embeddings, window definitions, persistence
   diagrams, normalized controls, validation evidence and exact implementation/config snapshots.
5. The known Transformers warning emitted before safe chunking is suppressed without changing
   token IDs, chunking or model inputs.
6. Raw H0 count remains supplementary. With 16 points, the finite raw H0 interval count is
   structurally 15; the article should not interpret that raw count as independent discriminative evidence.
