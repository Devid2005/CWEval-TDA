# TDA Statistical Experiment v2

Independent matched-pair experiment over the 20 Python/Flask CWEval secure/unsafe controls.
All generated data is written under `tda_statistical_experiment/runs/`; the original MITACS
formal experiment is read-only and is never modified.

## What changed from v1

1. Persistent homology now receives an explicit Euclidean distance matrix (`distance_matrix=True`)
   rather than a 16 x 768 feature matrix directly. This is mathematically the same Vietoris-Rips
   construction used in v1 but removes the ambiguous ripser transpose warning.
2. Pilot viability is based on **persistence-filtered H1**, not merely raw non-empty H1. Both raw
   and filtered H1 counts are still reported. The threshold remains 40% and does not inspect
   secure-vulnerable separation.
3. Source-length/complexity sensitivity is prespecified. Token count, character count and function
   unit count are recorded. The full analysis tests paired source-size differences, correlations
   between token length and topology, and compares length-only, topology-only and topology+length
   classifiers under the same group-wise CWE cross-validation.
4. Share bundles include the numerical artifacts required for independent audit: package embeddings,
   all 16 x 768 point clouds, window indexes, pilot persistence diagrams, final persistence diagrams,
   Betti arrays, source code controls, provenance snapshots and statistical outputs.
5. The schema is now `tda-statistical-experiment-v2`; a v1 pilot run cannot be continued with this
   script. Start a new pilot run.

## Frozen scientific design

- 20 matched CWEval Flask pairs = 40 samples.
- Class truth comes from validated CWEval secure/unsafe controls, never from TDA.
- Five formal-project CWEs (79, 306, 639, 862, 915) are used only for the representation-viability pilot.
- CodeBERT local representation: 16 deterministic windows x 32 source tokens per program.
- Each local vector is L2-normalized and has 768 dimensions for the supplied CodeBERT model.
- Geometry: explicit pairwise Euclidean distance matrix.
- Vietoris-Rips persistent homology: H0 and H1.
- Primary scalar metrics: significant interval count, mean persistence, maximum persistence,
  persistence entropy and Betti-curve AUC for H0 and H1.
- Paired inference: Wilcoxon, paired sign-flip permutation, bootstrap CI, effect sizes and
  Benjamini-Hochberg FDR over the 10 prespecified scalar metrics.
- Bottleneck/Wasserstein distances, full Betti-curve tests and class-level TDA are supplementary.
- Source-length analyses are sensitivity/confound checks; they do not alter the primary representation.
- Exploratory classifiers use GroupKFold by CWE pair to prevent the secure/vulnerable members of the
  same task from being split across training and test folds.

## ARC: no sudo and no executable permission required

Do **not** use `sudo`. The recommended commands call Python directly.

From the project root, for the new pilot:

```bash
cd ~/mitacs_4

"$HOME/envs/cweval/bin/python" \
  tda_statistical_experiment/run_experiment.py \
  --stage pilot \
  --model-path "$HOME/models/codebert-base" \
  --device auto
```

If you prefer the helper shell script, execute it through Bash even when the file is not executable:

```bash
PYTHON_BIN="$HOME/envs/cweval/bin/python" \
MODEL_PATH="$HOME/models/codebert-base" \
bash tda_statistical_experiment/run_pilot.sh
```

The new pilot must report 20/20 validated pairs and will create a new directory such as:

```text
tda_statistical_experiment/runs/run_YYYYMMDD_HHMMSS/
```

Upload `pilot_results_to_share.zip` from that **v2** run before the full analysis if you want it audited.

## Continue the same frozen v2 run

After the pilot is accepted, run:

```bash
cd ~/mitacs_4

"$HOME/envs/cweval/bin/python" \
  tda_statistical_experiment/run_experiment.py \
  --stage analyze \
  --run-dir tda_statistical_experiment/runs/run_YYYYMMDD_HHMMSS
```

or:

```bash
PYTHON_BIN="$HOME/envs/cweval/bin/python" \
bash tda_statistical_experiment/run_full.sh \
  tda_statistical_experiment/runs/run_YYYYMMDD_HHMMSS
```

The analysis stage refuses to continue if `run_experiment.py` changed after the pilot or if the
persistence-filtered H1 pilot viability criterion failed.

## Main outputs

Pilot bundle includes normalized secure/vulnerable code, validation evidence, CodeBERT package
embeddings, all point clouds, local-window definitions, persistence diagrams and provenance.

Full analysis additionally produces:

- `topology/topological_metrics.csv`
- `topology/betti_curves.csv`
- `topology/diagrams/*.npz`
- `topology/pairwise_diagram_distances.csv`
- `statistics/scalar_statistical_tests.csv`
- `statistics/betti_curve_global_tests.csv`
- `statistics/group_level_tda_permutation.csv`
- `statistics/exploratory_classification.csv`
- `confounds/source_feature_paired_tests.csv`
- `confounds/source_length_topology_correlations.csv`
- `confounds/length_complexity_confound_summary.json`
- figures and final reports
- `results_to_share.zip`

## Interpretation guardrails

A non-significant result is insufficient evidence of a systematic topological difference; it is not
proof of equality. A significant result does not by itself prove that topology is detecting a security
property, because source length and implementation complexity can differ systematically. That is why
v2 reports the length/complexity sensitivity analyses alongside the primary paired TDA results.
