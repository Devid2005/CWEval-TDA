# CWEval-TDA: Persistent Homology for Python/Flask Code Security

**A matched-pair study of secure and vulnerable Python/Flask code using CodeBERT embeddings and Topological Data Analysis (TDA).**

**Author:** David Santiago Hernández Hernández  
**Institution:** Universidad del Rosario, Bogotá, Colombia  
**Research context:** Mitacs research project  
**Computing infrastructure:** Advanced Research Computing (ARC), University of Calgary, Canada  
**Status:** Research artifact — not a production vulnerability scanner.

## Overview

I developed this research to investigate whether persistent-homology descriptors derived from CodeBERT representations can distinguish secure from vulnerable implementations of the same Python/Flask programming task.

The study builds on CWEval, an evaluation framework designed to examine both the functionality and security of code. I used adapted and extended Python/Flask CWEval tasks to establish a controlled set of matched secure/vulnerable implementations.

The central objective was not to develop another vulnerability detector, but to determine whether the topology of learned code representations contains statistically significant and predictively useful information about software vulnerabilities.

The experiment addresses three questions:

1. Do the persistent-homology descriptors of secure and vulnerable programs differ within matched CWE tasks?
2. Can these descriptors predict security labels when matched implementations remain together during cross-validation?
3. To what extent is the observed topological signal associated with source-code length?

## Research methodology

The experiment uses 40 Python/Flask implementations organized into 20 matched secure/vulnerable pairs. All 20 pairs were validated using functionality and security checks.

Each implementation undergoes the following procedure:

1. Extract and validate secure/vulnerable reference implementations.
2. Normalize code using abstract syntax tree processing.
3. Extract 16 deterministic local CodeBERT representations using windows of 32 tokenizer tokens.
4. Construct a 16 × 16 Euclidean distance matrix from L2-normalized embeddings of dimension 768.
5. Compute Vietoris–Rips persistent homology in dimensions H0 and H1 using Ripser.py.
6. Extract topological features and Betti curves.
7. Perform paired statistical inference and multiple-comparison correction.
8. Evaluate source-length associations and group-aware classification.

The primary metrics include significant interval count, mean persistence, maximum persistence, persistence entropy, and Betti-curve area in H0 and H1.

The main statistical analysis uses 50,000 paired sign-flip permutations and Benjamini–Hochberg correction. A separate post-analysis enumerates all 2^20 possible sign configurations as an exact sensitivity check.

Predictive performance is evaluated using logistic regression and linear SVM classifiers under five-fold GroupKFold cross-validation, ensuring that both members of each CWE pair remain in the same training or test fold.

## Main findings

| Metric | Result |
|---|---|
| Programs analyzed | 40 |
| Matched CWE tasks | 20 |
| H0 mean persistence, secure | 0.1757 |
| H0 mean persistence, vulnerable | 0.1664 |
| H0 Betti area, secure | 7.9510 |
| H0 Betti area, vulnerable | 7.5815 |
| Main Monte Carlo adjusted q | 0.0502 |
| Exact permutation adjusted q | 0.0469 |
| Logistic regression, topology only | 0.575 balanced accuracy |
| Linear SVM, topology only | 0.500 balanced accuracy |
| Length only | 0.750 balanced accuracy |

The analysis identified partial differences in H0, but these did not provide robust predictive discrimination between secure and vulnerable code.

H1 did not show statistically supported separation under the evaluated configuration. Source-code length was also associated with some of the topological characteristics that exhibited differences between classes.

The results suggest that persistent homology may provide complementary geometric information, but should not be used alone to determine software security.

## Repository structure

The complete research repository should contain:

```text
CWEval-TDA/
├── README.md
├── .gitignore
├── CITATION.cff
├── CWEval/
│   └── benchmark/
│       ├── task_catalog.json
│       └── core/py/
├── code_generation/
│   └── security_pipeline/
│       ├── code_embeddings.py
│       ├── code_representation.py
│       └── reference_validator.py
├── tda_statistical_experiment/
│   ├── README.md
│   ├── CHANGELOG_V2.md
│   ├── config.json
│   ├── requirements.txt
│   ├── run_experiment.py
│   ├── run_pilot.sh
│   ├── run_full.sh
│   ├── article_post_analysis.py
│   └── runs/
└── docs/
    └── RELEASE_CHECKLIST.md
```

The full execution requires the adapted CWEval benchmark and the supporting security-pipeline modules. The standalone TDA scripts are not sufficient to reconstruct a new experiment without these components.

## Installation

The original experiments were executed in a Linux research-computing environment.

Python dependencies are declared in `tda_statistical_experiment/requirements.txt`. A typical environment can be prepared with:

```bash
python -m venv .venv
source .venv/bin/activate

python -m pip install --upgrade pip
python -m pip install -r tda_statistical_experiment/requirements.txt
python -m pip install pandas
```

The full adapted benchmark may require additional dependencies for validating its functional and security test cases.

CodeBERT model files must be available locally. The frozen experimental configuration disables automatic model downloading.

## Running the experiment

The following commands assume that the complete adapted benchmark and supporting modules are available at the expected paths.

### Stage 1 — Pilot and validation

```bash
python tda_statistical_experiment/run_experiment.py \
  --stage pilot \
  --model-path "$HOME/models/codebert-base" \
  --device auto
```

The pilot extracts the 20 task pairs, validates reference implementations, creates CodeBERT representations, and checks the viability of the selected topological configuration.

A successful pilot reports 20 validated pairs and creates a directory such as:

```text
tda_statistical_experiment/runs/run_YYYYMMDD_HHMMSS/
```

### Stage 2 — Full statistical analysis

After successful pilot validation, continue the same frozen run:

```bash
python tda_statistical_experiment/run_experiment.py \
  --stage analyze \
  --run-dir tda_statistical_experiment/runs/run_YYYYMMDD_HHMMSS
```

The analysis generates topological metrics, persistence diagrams, Betti curves, statistical tests, classifier results, confound analyses, and figures.

### Stage 3 — Exact post-analysis for the article

The recorded experiment is identified as:

```text
run_20261006_230230
```

When its complete numerical artifacts are available, the additional article analysis can be executed with:

```bash
python tda_statistical_experiment/article_post_analysis.py \
  --run-dir tda_statistical_experiment/runs/run_20261006_230230 \
  --output-dir tda_statistical_experiment/article_outputs_run_20261006_230230
```

This step reads the saved experiment results rather than running CodeBERT inference again.

Its outputs include exact paired sign-flip tests, exact Betti-curve comparisons, statistical summaries, and additional figures for the scientific article.

## Advanced Research Computing — University of Calgary

I performed the computational experiments using the **Advanced Research Computing (ARC)** infrastructure operated by Research Computing Services at the **University of Calgary, Canada**.

ARC provided the research-computing environment used to execute the Python-based analyses, process CodeBERT representations, compute persistent homology, and generate experimental results.

The original project used a user-managed Python environment and locally stored model files. These locations are specific to the research environment and should be adapted when reproducing the experiment elsewhere.

ARC supports CPU- and GPU-based research workloads and managed HPC job scheduling.

Official documentation:  
https://it.ucalgary.ca/research-computing-services/our-resources/high-performance-computing-hpc/advanced-research-computing-arc

Acknowledging the use of ARC does not imply institutional authorship or endorsement of this repository.

## Relationship to CWEval

This research builds upon the original CWEval framework:

J. Peng, L. Cui, K. Huang, J. Yang, and B. Ray, *CWEval: Outcome-driven Evaluation on Functionality and Security of LLM Code Generation*, IEEE/ACM LLM4Code, 2025.

Original repository:  
https://github.com/Co1lin/CWEval

DOI:  
https://doi.org/10.1109/LLM4Code66737.2025.00009

The research environment adapted and extended the Python/Flask task collection while retaining the distinction between functionality and security validation.

The topological experiment, statistical analyses, controlled comparisons, and evaluation of source-length sensitivity constitute the research documented in this repository.

This repository is not the official CWEval distribution. Original authorship, license notices, and third-party acknowledgments must be preserved.

## Limitations

The experiment analyzes a limited set of 20 matched CWE tasks, so the results should not be generalized to all software systems or vulnerabilities.

The choice of CodeBERT representations, 16 local embedding points, Euclidean distance, and selected persistent-homology descriptors affects the resulting topological structures.

The study identified partial H0 differences and weak classification performance. Consequently, the observed geometric differences should not be interpreted as direct evidence of security guarantees.

Intentionally vulnerable implementations are included solely for controlled security research and should not be deployed as production applications.

## Reproducibility and research artifacts

The recorded experiment contains dataset manifests, source-code controls, validation evidence, embeddings, persistence diagrams, numerical metrics, statistical results, figures, and provenance information.

These artifacts allow reported results to be audited independently of the original article.

Before public release, execution logs, credentials, personal paths, and environment-specific metadata must be reviewed and any sensitive information removed.

The original experiment contains `PACKAGE_SHA256SUMS.txt`, which records hashes for its packaged source files. Modified distributions should generate a new integrity manifest.

## Citation

If you use this research software, data, or experimental results, please acknowledge this repository and cite the original CWEval publication.

Repository citation information is provided in `CITATION.cff`.

The accompanying scientific manuscript should be cited using its final publication information when available.

## Acknowledgments

I acknowledge **Universidad del Rosario** for my academic training, **Mitacs** as part of the research context, and **Advanced Research Computing (ARC) at the University of Calgary** for the computational infrastructure used in the experiments.

I also acknowledge the authors and maintainers of CWEval, CodeBERT, Ripser.py, and the open-source libraries used throughout this research.

## Author

**David Santiago Hernández Hernández**  
Applied Mathematics and Computer Science  
Universidad del Rosario  
Bogotá, Colombia  
davids.hernandez@urosario.edu.co
