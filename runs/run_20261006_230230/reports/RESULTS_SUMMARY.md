# TDA Statistical Experiment - Results Summary

Generated: 2026-10-07T05:22:36+00:00

## Dataset
- 20 matched Flask CWE pairs = 40 samples (20 secure + 20 vulnerable).
- Validated pairs: 20/20.
- All reference controls valid: True.

## Pilot
- Raw H1 non-empty: 10/10 formal-subset samples.
- Persistence-filtered H1 non-empty: 7/10 formal-subset samples.
- H1 viability flag (based on persistence-filtered H1): True.

## Primary scalar tests
- Primary metrics tested: 10.
- Significant after Benjamini-Hochberg FDR 0.05: 0.
- Metrics: none.

## Source-length / complexity sensitivity
- Secure mean token count: 552.550.
- Vulnerable mean token count: 387.200.
- Mean vulnerable-secure token difference: -165.350.
- Paired token-length permutation p: 0.000259995.
- Classification results below explicitly compare length-only, topology-only, and topology+length feature sets.

## Betti curve global tests
- H0: statistic=0.716789, p=0.00749985
- H1: statistic=0.0978734, p=0.189576

## Group-level TDA permutation
- H0: observed bottleneck=0.0184947, p=0.835582
- H1: observed bottleneck=0.0054393, p=0.665167

## Exploratory topology-only classification
- logistic_regression [length_only]: balanced_accuracy=0.7500, F1=0.7500, permutation_p=0.002997
- linear_svm [length_only]: balanced_accuracy=0.7500, F1=0.7500, permutation_p=0.000999001
- logistic_regression [topology_only]: balanced_accuracy=0.5750, F1=0.5143, permutation_p=0.235764
- linear_svm [topology_only]: balanced_accuracy=0.5000, F1=0.4118, permutation_p=0.547453
- logistic_regression [topology_plus_length]: balanced_accuracy=0.5750, F1=0.5405, permutation_p=0.236763
- linear_svm [topology_plus_length]: balanced_accuracy=0.5500, F1=0.5263, permutation_p=0.344655

## Guardrail
A non-significant result means insufficient evidence of a systematic topological difference under this representation and dataset; it does not prove equality or security.
Raw H0 interval count is structurally determined by the fixed 16-point cloud (15 finite H0 intervals); it is supplementary rather than discriminative evidence.
Source-length results are treated as a sensitivity/confound analysis and do not alter the prespecified primary TDA representation.

Upload results_to_share.zip for interpretation and article drafting.
