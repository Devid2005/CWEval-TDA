#!/usr/bin/env python3
from __future__ import annotations

import argparse
import ast
import csv
import hashlib
import json
import logging
import math
import os
import shutil
import sys
import time
import traceback
import zipfile
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable, Sequence

import numpy as np

# -----------------------------------------------------------------------------
# Project imports. This file lives at <project>/tda_statistical_experiment/.
# The original project is READ ONLY for this experiment: every artifact generated
# by this script is written below tda_statistical_experiment/runs/.
# -----------------------------------------------------------------------------
SCRIPT_DIR = Path(__file__).resolve().parent
PROJECT_ROOT = SCRIPT_DIR.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from code_generation.security_pipeline.code_embeddings import (  # noqa: E402
    CODE_EMBEDDINGS_IMPLEMENTATION_ID,
    CodeEmbedder,
    fingerprint_local_model,
)
from code_generation.security_pipeline.code_representation import (  # noqa: E402
    canonicalize_node,
    direct_nested_functions,
    find_top_level_function,
    function_unit_records,
    parse_file,
    route_specs_in_factory,
    sha256_text,
)
from code_generation.security_pipeline.reference_validator import (  # noqa: E402
    validate_reference_controls,
)


EXPERIMENT_SCHEMA = "tda-statistical-experiment-v2"
PRIMARY_FORMAL_CWES = {79, 306, 639, 862, 915}
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
SUPPLEMENTARY_METRICS = [
    "h0_total_persistence",
    "h1_total_persistence",
    "h0_raw_count",
    "h1_raw_count",
]


def utc_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def write_json(path: Path, payload: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")


def read_json(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


def sha256_file(path: Path, chunk_size: int = 1024 * 1024) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        while True:
            chunk = handle.read(chunk_size)
            if not chunk:
                break
            digest.update(chunk)
    return digest.hexdigest()


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def safe_float(value: Any) -> float | None:
    try:
        out = float(value)
    except (TypeError, ValueError):
        return None
    return out if math.isfinite(out) else None


def cwe_number(task_id: str) -> int:
    parts = task_id.split("_")
    if len(parts) < 2 or parts[0].lower() != "cwe":
        raise ValueError(f"Cannot parse CWE number from task_id={task_id!r}")
    return int(parts[1])


def setup_logging(run_dir: Path) -> logging.Logger:
    run_dir.mkdir(parents=True, exist_ok=True)
    logger = logging.getLogger("tda_statistical_experiment")
    logger.setLevel(logging.INFO)
    logger.handlers.clear()
    formatter = logging.Formatter("%(asctime)s | %(levelname)s | %(message)s")
    fh = logging.FileHandler(run_dir / "execution.log", encoding="utf-8")
    fh.setFormatter(formatter)
    sh = logging.StreamHandler(sys.stdout)
    sh.setFormatter(formatter)
    logger.addHandler(fh)
    logger.addHandler(sh)
    return logger


def write_csv(path: Path, rows: Sequence[dict[str, Any]], fieldnames: Sequence[str] | None = None) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    rows = list(rows)
    if fieldnames is None:
        keys: list[str] = []
        for row in rows:
            for key in row:
                if key not in keys:
                    keys.append(key)
        fieldnames = keys
    with path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=list(fieldnames), extrasaction="ignore")
        writer.writeheader()
        writer.writerows(rows)


def read_csv(path: Path) -> list[dict[str, str]]:
    with path.open("r", newline="", encoding="utf-8") as handle:
        return list(csv.DictReader(handle))


def discover_flask_tasks(repo_root: Path) -> list[dict[str, Any]]:
    catalog_path = repo_root / "CWEval" / "benchmark" / "task_catalog.json"
    catalog = read_json(catalog_path)
    tasks = [
        dict(item)
        for item in catalog
        if str(item.get("source_file", "")).endswith("_flask_task.py")
    ]
    tasks.sort(key=lambda row: (cwe_number(str(row["task_id"])), str(row["task_id"])))
    if len(tasks) != 20:
        raise RuntimeError(
            f"Expected 20 Python/Flask CWEval tasks from the supplied project, found {len(tasks)}. "
            "Stop rather than silently changing the analysis population."
        )
    return tasks


def find_unsafe_factory(tree: ast.Module, factory_name: str) -> ast.FunctionDef | ast.AsyncFunctionDef:
    expected = f"{factory_name}_unsafe"
    try:
        return find_top_level_function(tree, expected)
    except KeyError:
        candidates = [
            node
            for node in tree.body
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
            and node.name.startswith(factory_name)
            and node.name.endswith("_unsafe")
        ]
        if len(candidates) == 1:
            return candidates[0]
        raise KeyError(
            f"Could not identify exactly one unsafe factory for {factory_name!r}; "
            f"candidates={[node.name for node in candidates]}"
        )


@dataclass
class ExtractionResult:
    reference_manifest: dict[str, Any]
    samples: list[dict[str, Any]]


def extract_all_pairs(repo_root: Path, run_dir: Path, logger: logging.Logger) -> ExtractionResult:
    tasks = discover_flask_tasks(repo_root)
    dataset_dir = run_dir / "dataset"
    pairs_dir = dataset_dir / "pairs"
    controls_root = repo_root / "CWEval" / "benchmark" / "core" / "py"
    pairs_dir.mkdir(parents=True, exist_ok=True)

    manifest_tasks: dict[str, Any] = {}
    all_units: list[dict[str, Any]] = []
    samples: list[dict[str, Any]] = []

    logger.info("Extracting 20 secure/vulnerable Flask pairs from CWEval...")
    for task in tasks:
        task_id = str(task["task_id"])
        factory_name = str(task["function_name"])
        number = cwe_number(task_id)
        pair_dir = pairs_dir / task_id
        pair_dir.mkdir(parents=True, exist_ok=True)

        secure_path = controls_root / f"{task_id}_task.py"
        test_path = controls_root / f"{task_id}_test.py"
        if not secure_path.is_file() or not test_path.is_file():
            raise FileNotFoundError(f"Missing CWEval source/test file for {task_id}")

        secure_tree = parse_file(secure_path)
        test_tree = parse_file(test_path)
        secure_factory = find_top_level_function(secure_tree, factory_name)
        unsafe_factory = find_unsafe_factory(test_tree, factory_name)

        # Same leakage controls used by the original project: comments disappear
        # through ast.unparse; docstrings are stripped; outer names become build_app.
        secure_source = canonicalize_node(secure_factory, rename_function="build_app")
        unsafe_source = canonicalize_node(unsafe_factory, rename_function="build_app")

        secure_out = pair_dir / "secure.py"
        vulnerable_out = pair_dir / "vulnerable.py"
        secure_out.write_text(secure_source, encoding="utf-8")
        vulnerable_out.write_text(unsafe_source, encoding="utf-8")

        # Sanity check normalized sources.
        ast.parse(secure_source, filename=str(secure_out))
        ast.parse(unsafe_source, filename=str(vulnerable_out))

        secure_units = function_unit_records(secure_factory, task_id=task_id, variant="secure")
        unsafe_units = function_unit_records(unsafe_factory, task_id=task_id, variant="unsafe")
        all_units.extend(secure_units)
        all_units.extend(unsafe_units)
        secure_routes = [spec.to_dict() for spec in route_specs_in_factory(secure_factory)]
        unsafe_routes = [spec.to_dict() for spec in route_specs_in_factory(unsafe_factory)]

        manifest_tasks[task_id] = {
            "task_id": task_id,
            "cwe": f"CWE-{number}",
            "factory_name": factory_name,
            "secure": {
                "source_file": str(secure_path.resolve()),
                "normalized_file": str(secure_out.resolve()),
                "sha256": sha256_text(secure_source),
                "routes": secure_routes,
                "nested_functions": [node.name for node in direct_nested_functions(secure_factory)],
                "unit_ids": [unit["unit_id"] for unit in secure_units],
            },
            "unsafe": {
                "source_file": str(test_path.resolve()),
                "factory_name": unsafe_factory.name,
                "normalized_file": str(vulnerable_out.resolve()),
                "sha256": sha256_text(unsafe_source),
                "routes": unsafe_routes,
                "nested_functions": [node.name for node in direct_nested_functions(unsafe_factory)],
                "unit_ids": [unit["unit_id"] for unit in unsafe_units],
            },
            "route_contract_consistent": {
                (item["normalized_path"], tuple(item["methods"])) for item in secure_routes
            }
            == {
                (item["normalized_path"], tuple(item["methods"])) for item in unsafe_routes
            },
        }

        common = {
            "task_id": task_id,
            "pair_id": task_id,
            "cwe": f"CWE-{number}",
            "cwe_number": number,
            "language": "Python",
            "framework": "Flask",
            "formal_project_subset": number in PRIMARY_FORMAL_CWES,
            "factory_name": factory_name,
            "route_contract_consistent": manifest_tasks[task_id]["route_contract_consistent"],
        }
        samples.append(
            common
            | {
                "sample_id": f"{task_id}__secure",
                "class": "secure",
                "class_binary": 0,
                "normalized_file": str(secure_out.resolve()),
                "source_sha256": sha256_text(secure_source),
                "source_chars": len(secure_source),
                "unit_count": len(secure_units),
            }
        )
        samples.append(
            common
            | {
                "sample_id": f"{task_id}__vulnerable",
                "class": "vulnerable",
                "class_binary": 1,
                "normalized_file": str(vulnerable_out.resolve()),
                "source_sha256": sha256_text(unsafe_source),
                "source_chars": len(unsafe_source),
                "unit_count": len(unsafe_units),
            }
        )
        logger.info("Extracted %s (%s): secure + vulnerable", task_id, f"CWE-{number}")

    manifest = {
        "schema_version": "2.0",
        "experiment_schema": EXPERIMENT_SCHEMA,
        "method": "all_flask_cweval_secure_and_unsafe_control_extraction",
        "created_at_utc": utc_now(),
        "label_leakage_controls": {
            "comments_removed": True,
            "docstrings_removed": True,
            "outer_factory_name_normalized": "build_app",
            "unsafe_suffix_excluded_from_embedding_text": True,
        },
        "task_count": len(manifest_tasks),
        "sample_count": len(samples),
        "tasks": manifest_tasks,
        "units": all_units,
    }
    write_json(dataset_dir / "reference_manifest.json", manifest)
    write_json(dataset_dir / "dataset_manifest.json", samples)
    write_csv(dataset_dir / "dataset_manifest.csv", samples)
    return ExtractionResult(reference_manifest=manifest, samples=samples)


def validate_pairs(repo_root: Path, run_dir: Path, samples: list[dict[str, Any]], logger: logging.Logger, timeout: int) -> dict[str, Any]:
    dataset_manifest = read_json(run_dir / "dataset" / "reference_manifest.json")
    validation_root = run_dir / "validation"
    validation_root.mkdir(parents=True, exist_ok=True)
    task_results: dict[str, Any] = {}

    logger.info("Validating each of the 20 secure/vulnerable CWEval pairs...")
    for task_id in sorted(dataset_manifest["tasks"], key=lambda t: cwe_number(t)):
        mini_manifest = {
            "schema_version": "1.0",
            "tasks": {task_id: dataset_manifest["tasks"][task_id]},
        }
        mini_path = validation_root / task_id / "reference_manifest.json"
        write_json(mini_path, mini_manifest)
        report = validate_reference_controls(
            repo_root=repo_root,
            reference_manifest_path=mini_path,
            output_dir=validation_root / task_id,
            timeout=timeout,
        )
        task_results[task_id] = report
        logger.info(
            "Validation %s: %s (secure=%s unsafe=%s)",
            task_id,
            report["status"],
            report["secure_references"]["passed"],
            report["unsafe_controls"]["passed"],
        )

    all_valid = all(bool(report.get("all_reference_controls_valid")) for report in task_results.values())
    valid_count = sum(bool(report.get("all_reference_controls_valid")) for report in task_results.values())
    summary = {
        "schema_version": "2.0",
        "experiment_schema": EXPERIMENT_SCHEMA,
        "created_at_utc": utc_now(),
        "task_count": len(task_results),
        "valid_task_count": valid_count,
        "all_reference_controls_valid": all_valid,
        "tasks": {
            task_id: {
                "status": report["status"],
                "valid": bool(report["all_reference_controls_valid"]),
                "secure_passed": bool(report["secure_references"]["passed"]),
                "unsafe_meta_tests_passed": bool(report["unsafe_controls"]["passed"]),
                "secure_results": report["secure_references"]["results"],
                "unsafe_results": report["unsafe_controls"]["results"],
            }
            for task_id, report in task_results.items()
        },
    }
    write_json(validation_root / "validation_summary.json", summary)

    valid_by_task = {task_id: bool(data["valid"]) for task_id, data in summary["tasks"].items()}
    updated = []
    for row in samples:
        copy = dict(row)
        copy["validation_status"] = "pass" if valid_by_task.get(row["task_id"], False) else "fail"
        updated.append(copy)
    write_json(run_dir / "dataset" / "dataset_manifest.json", updated)
    write_csv(run_dir / "dataset" / "dataset_manifest.csv", updated)
    return summary


def model_window_vector(embedder: CodeEmbedder, token_ids: list[int]) -> np.ndarray:
    encoded = embedder._model_inputs(token_ids)  # Uses the same model-input logic as the project.
    with embedder.torch.inference_mode():
        output = embedder.model(**encoded).last_hidden_state
    mask = encoded["attention_mask"].unsqueeze(-1).to(output.dtype)
    summed = (output * mask).sum(dim=1)
    count = mask.sum(dim=1).clamp(min=1.0)
    vector = (summed / count).squeeze(0).detach().cpu().numpy().astype(np.float32)
    norm = float(np.linalg.norm(vector))
    if not math.isfinite(norm) or norm <= 0:
        raise RuntimeError("Local window embedding has a zero or non-finite norm")
    return (vector / norm).astype(np.float32)


def fixed_local_windows(
    embedder: CodeEmbedder,
    text: str,
    *,
    points_per_sample: int,
    window_tokens: int,
) -> tuple[np.ndarray, list[dict[str, Any]], int]:
    token_ids = embedder._raw_token_ids(text)
    n_tokens = len(token_ids)
    if n_tokens < points_per_sample + 8:
        raise RuntimeError(
            f"Source has only {n_tokens} model tokens, insufficient for "
            f"{points_per_sample} distinct local windows."
        )

    # Force enough distinct start positions while respecting the preregistered
    # maximum local-window length. This keeps the point count constant across all
    # 40 samples and prevents raw H0 count from becoming a code-length proxy.
    effective_window = min(window_tokens, n_tokens - points_per_sample + 1)
    effective_window = max(8, effective_window)
    if effective_window > embedder.max_tokens - int(embedder.tokenizer.num_special_tokens_to_add(pair=False)):
        raise RuntimeError("Configured local window exceeds the embedding model capacity")

    max_start = n_tokens - effective_window
    if max_start < points_per_sample - 1:
        raise RuntimeError("Cannot construct the requested number of distinct window starts")
    starts = np.rint(np.linspace(0, max_start, num=points_per_sample)).astype(int)
    if len(set(int(x) for x in starts)) != points_per_sample:
        # Deterministic repair that does not inspect labels or topological outcomes.
        starts = np.arange(points_per_sample, dtype=int)
        starts = np.rint(starts * max_start / max(1, points_per_sample - 1)).astype(int)
    if len(set(int(x) for x in starts)) != points_per_sample:
        raise RuntimeError("Failed to create distinct deterministic local windows")

    vectors: list[np.ndarray] = []
    index: list[dict[str, Any]] = []
    for point_index, start in enumerate(starts.tolist()):
        stop = start + effective_window
        chunk = token_ids[start:stop]
        vector = model_window_vector(embedder, chunk)
        vectors.append(vector)
        index.append(
            {
                "point_index": point_index,
                "start_token": int(start),
                "stop_token": int(stop),
                "token_count": len(chunk),
            }
        )
    matrix = np.vstack(vectors).astype(np.float32)
    if matrix.shape != (points_per_sample, embedder.dimension):
        raise RuntimeError(f"Unexpected point-cloud shape: {matrix.shape}")
    return matrix, index, n_tokens


def generate_all_embeddings(
    run_dir: Path,
    samples: list[dict[str, Any]],
    *,
    model_path: str,
    device: str,
    max_tokens: int,
    overlap_tokens: int,
    points_per_sample: int,
    window_tokens: int,
    allow_download: bool,
    logger: logging.Logger,
) -> dict[str, Any]:
    embeddings_dir = run_dir / "embeddings"
    pointcloud_dir = embeddings_dir / "pointclouds"
    pointcloud_dir.mkdir(parents=True, exist_ok=True)

    logger.info("Loading CodeBERT/tokenizer from %s", model_path)
    embedder = CodeEmbedder(
        model_path,
        device=device,
        max_tokens=max_tokens,
        overlap_tokens=overlap_tokens,
        local_files_only=not allow_download,
    )
    # The project chunks long inputs before model execution.  Transformers may
    # nevertheless emit a pre-chunking length warning while tokenizing raw text.
    # Mark only that known warning as already handled; this changes no token IDs,
    # chunks, model inputs, or embeddings.
    deprecation_warnings = getattr(embedder.tokenizer, "deprecation_warnings", None)
    if isinstance(deprecation_warnings, dict):
        deprecation_warnings["sequence-length-is-longer-than-the-specified-maximum"] = True
    model_meta = embedder.metadata()
    model_meta["raw_token_length_warning_suppressed_after_safe_prechunking"] = True
    fingerprint = model_meta.get("model_artifact_fingerprint") or {}
    if not fingerprint.get("available"):
        raise RuntimeError("The local embedding model could not be fingerprinted")

    package_vectors: list[np.ndarray] = []
    package_index: list[dict[str, Any]] = []
    pointcloud_index: list[dict[str, Any]] = []
    token_counts: dict[str, int] = {}

    for idx, sample in enumerate(samples, start=1):
        path = Path(sample["normalized_file"])
        source = path.read_text(encoding="utf-8")
        if sha256_text(source) != sample["source_sha256"]:
            raise RuntimeError(f"Dataset source changed after extraction: {path}")

        logger.info("Embedding %02d/%02d %s", idx, len(samples), sample["sample_id"])
        package_vector = embedder.embed(source)
        package_vectors.append(package_vector)
        package_index.append(
            {
                "row": idx - 1,
                "sample_id": sample["sample_id"],
                "pair_id": sample["pair_id"],
                "task_id": sample["task_id"],
                "cwe": sample["cwe"],
                "class": sample["class"],
                "source_sha256": sample["source_sha256"],
            }
        )

        cloud, windows, n_tokens = fixed_local_windows(
            embedder,
            source,
            points_per_sample=points_per_sample,
            window_tokens=window_tokens,
        )
        cloud_path = pointcloud_dir / f"{sample['sample_id']}.npy"
        np.save(cloud_path, cloud)
        write_json(pointcloud_dir / f"{sample['sample_id']}_windows.json", windows)
        token_counts[sample["sample_id"]] = n_tokens
        pointcloud_index.append(
            {
                "sample_id": sample["sample_id"],
                "pair_id": sample["pair_id"],
                "task_id": sample["task_id"],
                "cwe": sample["cwe"],
                "class": sample["class"],
                "pointcloud_file": str(cloud_path.resolve()),
                "shape": list(cloud.shape),
                "source_token_count": n_tokens,
                "points_per_sample": points_per_sample,
                "requested_window_tokens": window_tokens,
                "effective_window_tokens": windows[0]["token_count"] if windows else None,
            }
        )

    package_matrix = np.vstack(package_vectors).astype(np.float32)
    np.save(embeddings_dir / "package_embeddings.npy", package_matrix)
    write_json(embeddings_dir / "package_embedding_index.json", package_index)
    write_json(embeddings_dir / "pointcloud_index.json", pointcloud_index)
    write_json(embeddings_dir / "model_fingerprint.json", fingerprint)

    metadata = {
        "schema_version": "2.0",
        "experiment_schema": EXPERIMENT_SCHEMA,
        "created_at_utc": utc_now(),
        "embedding_implementation_id": CODE_EMBEDDINGS_IMPLEMENTATION_ID,
        "model": model_meta,
        "package_embeddings": {
            "shape": list(package_matrix.shape),
            "path": str((embeddings_dir / "package_embeddings.npy").resolve()),
            "index_path": str((embeddings_dir / "package_embedding_index.json").resolve()),
        },
        "per_sample_pointcloud": {
            "method": "fixed_count_overlapping_local_codebert_windows",
            "points_per_sample": points_per_sample,
            "requested_window_tokens": window_tokens,
            "distance_metric": "euclidean_on_l2_normalized_codebert_vectors",
            "pointcloud_index": str((embeddings_dir / "pointcloud_index.json").resolve()),
        },
        "label_leakage_controls": {
            "comments_removed": True,
            "docstrings_removed": True,
            "outer_factory_name_normalized": "build_app",
            "unsafe_suffix_excluded_from_embedding_text": True,
        },
        "source_token_counts": token_counts,
    }
    write_json(embeddings_dir / "embedding_metadata.json", metadata)
    return metadata


def write_source_length_manifest(
    run_dir: Path,
    samples: list[dict[str, Any]],
    logger: logging.Logger,
) -> list[dict[str, Any]]:
    """Persist code-size/complexity covariates before inferential analysis.

    These covariates are not used to alter the TDA representation.  They are
    retained so the final analysis can test whether apparent topological signal
    is associated with systematic secure-vulnerable differences in source size.
    """
    cloud_index = {
        row["sample_id"]: row
        for row in read_json(run_dir / "embeddings" / "pointcloud_index.json")
    }
    rows: list[dict[str, Any]] = []
    for sample in samples:
        point = cloud_index[sample["sample_id"]]
        rows.append(
            {
                "sample_id": sample["sample_id"],
                "pair_id": sample["pair_id"],
                "cwe": sample["cwe"],
                "class": sample["class"],
                "source_token_count": int(point["source_token_count"]),
                "source_chars": int(sample.get("source_chars", 0)),
                "unit_count": int(sample.get("unit_count", 0)),
                "points_per_sample": int(point["points_per_sample"]),
                "effective_window_tokens": int(point["effective_window_tokens"]),
            }
        )
    confound_dir = run_dir / "confounds"
    confound_dir.mkdir(parents=True, exist_ok=True)
    write_csv(confound_dir / "source_length_manifest.csv", rows)
    write_json(confound_dir / "source_length_manifest.json", rows)
    logger.info("Recorded source-length/complexity covariates for %d samples", len(rows))
    return rows


def euclidean_distance_matrix(points: np.ndarray) -> np.ndarray:
    """Return an explicit Euclidean distance matrix for a point cloud.

    Persistent homology in this experiment is defined over pairwise Euclidean
    distances between L2-normalized CodeBERT vectors.  Supplying the distance
    matrix explicitly makes the geometry unambiguous when n_points << n_features
    (16 x 768 for the per-program clouds) and avoids ripser's transpose warning.
    """
    points = np.asarray(points, dtype=np.float64)
    if points.ndim != 2 or len(points) < 2:
        raise ValueError(f"Expected a 2D point cloud with at least two points, got {points.shape}")
    diff = points[:, None, :] - points[None, :, :]
    distances = np.sqrt(np.sum(diff * diff, axis=2, dtype=np.float64))
    distances = 0.5 * (distances + distances.T)
    np.fill_diagonal(distances, 0.0)
    if not np.isfinite(distances).all():
        raise RuntimeError("Pairwise distance matrix contains non-finite values")
    return distances


def compute_diagrams(points: np.ndarray, maxdim: int) -> list[np.ndarray]:
    try:
        from ripser import ripser
    except ImportError as exc:
        raise RuntimeError("ripser is required. Install tda_statistical_experiment/requirements.txt") from exc
    distances = euclidean_distance_matrix(points)
    result = ripser(distances, maxdim=maxdim, distance_matrix=True)
    return [np.asarray(dgm, dtype=np.float64) for dgm in result["dgms"]]


def finite_lifetimes(diagram: np.ndarray) -> tuple[np.ndarray, np.ndarray]:
    if diagram.size == 0:
        return np.empty((0, 2), dtype=np.float64), np.empty((0,), dtype=np.float64)
    finite = diagram[np.isfinite(diagram[:, 1])]
    if finite.size == 0:
        return finite.reshape((0, 2)), np.empty((0,), dtype=np.float64)
    lifetimes = np.maximum(0.0, finite[:, 1] - finite[:, 0])
    return finite, lifetimes


def persistence_summary(
    diagram: np.ndarray,
    *,
    minimum_persistence_absolute: float,
    minimum_persistence_fraction: float,
) -> dict[str, Any]:
    finite, lifetimes = finite_lifetimes(diagram)
    raw_count = int(len(lifetimes))
    if raw_count == 0:
        return {
            "raw_count": 0,
            "significant_count": 0,
            "threshold": float(minimum_persistence_absolute),
            "total_persistence": 0.0,
            "mean_persistence": 0.0,
            "max_persistence": 0.0,
            "entropy": 0.0,
            "finite_birth_max": 0.0,
            "finite_death_max": 0.0,
        }
    max_lifetime = float(np.max(lifetimes))
    threshold = max(
        float(minimum_persistence_absolute),
        float(minimum_persistence_fraction) * max_lifetime,
    )
    significant = lifetimes[lifetimes >= threshold]
    total = float(np.sum(significant)) if len(significant) else 0.0
    mean = float(np.mean(significant)) if len(significant) else 0.0
    maximum = float(np.max(significant)) if len(significant) else 0.0
    if total > 0:
        probabilities = significant / total
        entropy = float(-np.sum(probabilities * np.log(probabilities + 1e-15)))
    else:
        entropy = 0.0
    return {
        "raw_count": raw_count,
        "significant_count": int(len(significant)),
        "threshold": float(threshold),
        "total_persistence": total,
        "mean_persistence": mean,
        "max_persistence": maximum,
        "entropy": entropy,
        "finite_birth_max": float(np.max(finite[:, 0])) if len(finite) else 0.0,
        "finite_death_max": float(np.max(finite[:, 1])) if len(finite) else 0.0,
    }


def betti_curve(diagram: np.ndarray, epsilon_grid: np.ndarray) -> np.ndarray:
    if diagram.size == 0:
        return np.zeros_like(epsilon_grid, dtype=np.float64)
    births = diagram[:, 0]
    deaths = diagram[:, 1]
    curve = np.zeros_like(epsilon_grid, dtype=np.float64)
    for i, eps in enumerate(epsilon_grid):
        curve[i] = float(np.sum((births <= eps) & ((deaths > eps) | np.isinf(deaths))))
    return curve


def normalized_auc(x: np.ndarray, y: np.ndarray) -> float:
    if len(x) < 2 or float(x[-1] - x[0]) <= 0:
        return 0.0
    try:
        area = float(np.trapezoid(y, x))
    except AttributeError:
        area = float(np.trapz(y, x))
    return area / float(x[-1] - x[0])


def safe_diagram_distance(a: np.ndarray, b: np.ndarray, method: str) -> float:
    try:
        from persim import bottleneck, wasserstein
    except ImportError as exc:
        raise RuntimeError("persim is required. Install tda_statistical_experiment/requirements.txt") from exc

    a = np.asarray(a, dtype=float)
    b = np.asarray(b, dtype=float)
    a = a[np.isfinite(a).all(axis=1)] if a.size else np.empty((0, 2))
    b = b[np.isfinite(b).all(axis=1)] if b.size else np.empty((0, 2))
    if len(a) == 0 and len(b) == 0:
        return 0.0
    if method == "bottleneck":
        return float(bottleneck(a, b))
    if method == "wasserstein":
        return float(wasserstein(a, b))
    raise ValueError(method)


def save_diagrams_npz(path: Path, diagrams: list[np.ndarray]) -> None:
    payload = {f"H{dim}": diagram for dim, diagram in enumerate(diagrams)}
    np.savez_compressed(path, **payload)


def pilot_topology(
    run_dir: Path,
    samples: list[dict[str, Any]],
    *,
    maxdim: int,
    min_persistence_abs: float,
    min_persistence_fraction: float,
    significant_viability_threshold: float,
    logger: logging.Logger,
) -> dict[str, Any]:
    pilot_dir = run_dir / "pilot"
    pilot_dir.mkdir(parents=True, exist_ok=True)
    cloud_index = {row["sample_id"]: row for row in read_json(run_dir / "embeddings" / "pointcloud_index.json")}
    selected = [sample for sample in samples if int(sample["cwe_number"]) in PRIMARY_FORMAL_CWES]
    records: list[dict[str, Any]] = []
    h1_raw_nonempty = 0
    h1_significant_nonempty = 0

    logger.info("Running topology pilot on the five formal-project CWEs (10 samples)...")
    for sample in selected:
        cloud = np.load(cloud_index[sample["sample_id"]]["pointcloud_file"])
        diagrams = compute_diagrams(cloud, maxdim=maxdim)
        h0 = persistence_summary(
            diagrams[0],
            minimum_persistence_absolute=min_persistence_abs,
            minimum_persistence_fraction=min_persistence_fraction,
        )
        h1_dgm = diagrams[1] if len(diagrams) > 1 else np.empty((0, 2))
        h1 = persistence_summary(
            h1_dgm,
            minimum_persistence_absolute=min_persistence_abs,
            minimum_persistence_fraction=min_persistence_fraction,
        )
        raw_nonempty = h1["raw_count"] > 0
        significant_nonempty = h1["significant_count"] > 0
        h1_raw_nonempty += int(raw_nonempty)
        h1_significant_nonempty += int(significant_nonempty)
        save_diagrams_npz(pilot_dir / f"{sample['sample_id']}_diagrams.npz", diagrams)
        records.append(
            {
                "sample_id": sample["sample_id"],
                "cwe": sample["cwe"],
                "class": sample["class"],
                "source_token_count": int(cloud_index[sample["sample_id"]]["source_token_count"]),
                "h0_raw_count": h0["raw_count"],
                "h0_significant_count": h0["significant_count"],
                "h1_raw_count": h1["raw_count"],
                "h1_significant_count": h1["significant_count"],
                "h1_raw_nonempty": raw_nonempty,
                "h1_significant_nonempty": significant_nonempty,
            }
        )

    raw_fraction = h1_raw_nonempty / len(records) if records else 0.0
    significant_fraction = h1_significant_nonempty / len(records) if records else 0.0
    # The decision is based on persistence-filtered H1, not merely any raw cycle.
    # It still uses no secure-vulnerable separation statistic and therefore cannot
    # tune the representation toward the study hypothesis.
    h1_viability = significant_fraction >= significant_viability_threshold
    report = {
        "schema_version": "2.0",
        "experiment_schema": EXPERIMENT_SCHEMA,
        "created_at_utc": utc_now(),
        "pilot_sample_count": len(records),
        "pilot_cwes": sorted(PRIMARY_FORMAL_CWES),
        "h1_raw_nonempty_count": h1_raw_nonempty,
        "h1_raw_nonempty_fraction": raw_fraction,
        "h1_significant_nonempty_count": h1_significant_nonempty,
        "h1_significant_nonempty_fraction": significant_fraction,
        "h1_significant_viability_threshold": significant_viability_threshold,
        "h1_viable_for_primary_interpretation": h1_viability,
        "geometry": {
            "distance": "pairwise Euclidean on L2-normalized CodeBERT local-window vectors",
            "ripser_input": "precomputed distance matrix",
        },
        "decision_rule_note": (
            "The pilot viability decision uses only whether persistence-filtered H1 is non-empty. "
            "It does not test or inspect secure-vulnerable separation. No representation parameter "
            "is selected according to class outcomes."
        ),
        "records": records,
    }
    write_json(pilot_dir / "pilot_report.json", report)
    write_csv(pilot_dir / "pilot_metrics.csv", records)
    logger.info(
        "Pilot complete: raw H1 non-empty %d/%d (%.1f%%); significant H1 non-empty %d/%d (%.1f%%); viability=%s",
        h1_raw_nonempty, len(records), 100 * raw_fraction,
        h1_significant_nonempty, len(records), 100 * significant_fraction, h1_viability,
    )
    return report

def compute_all_topology(
    run_dir: Path,
    samples: list[dict[str, Any]],
    *,
    maxdim: int,
    min_persistence_abs: float,
    min_persistence_fraction: float,
    betti_grid_points: int,
    logger: logging.Logger,
) -> tuple[list[dict[str, Any]], dict[str, dict[int, np.ndarray]], np.ndarray]:
    topology_dir = run_dir / "topology"
    diagram_dir = topology_dir / "diagrams"
    diagram_dir.mkdir(parents=True, exist_ok=True)
    cloud_index = {row["sample_id"]: row for row in read_json(run_dir / "embeddings" / "pointcloud_index.json")}

    diagrams_by_sample: dict[str, dict[int, np.ndarray]] = {}
    preliminary: list[dict[str, Any]] = []
    max_finite_death = 0.0

    logger.info("Computing per-sample persistent homology for all 40 codes...")
    for idx, sample in enumerate(samples, start=1):
        cloud = np.load(cloud_index[sample["sample_id"]]["pointcloud_file"])
        diagrams = compute_diagrams(cloud, maxdim=maxdim)
        save_diagrams_npz(diagram_dir / f"{sample['sample_id']}.npz", diagrams)
        dim_map: dict[int, np.ndarray] = {}
        row: dict[str, Any] = {
            "sample_id": sample["sample_id"],
            "pair_id": sample["pair_id"],
            "task_id": sample["task_id"],
            "cwe": sample["cwe"],
            "cwe_number": sample["cwe_number"],
            "class": sample["class"],
            "class_binary": sample["class_binary"],
            "formal_project_subset": sample["formal_project_subset"],
            "source_token_count": int(cloud_index[sample["sample_id"]]["source_token_count"]),
            "source_chars": int(sample.get("source_chars", 0)),
            "unit_count": int(sample.get("unit_count", 0)),
        }
        for dim in range(maxdim + 1):
            diagram = diagrams[dim] if dim < len(diagrams) else np.empty((0, 2))
            dim_map[dim] = diagram
            finite, _ = finite_lifetimes(diagram)
            if len(finite):
                max_finite_death = max(max_finite_death, float(np.max(finite[:, 1])))
            summary = persistence_summary(
                diagram,
                minimum_persistence_absolute=min_persistence_abs,
                minimum_persistence_fraction=min_persistence_fraction,
            )
            for key, value in summary.items():
                row[f"h{dim}_{key}"] = value
        diagrams_by_sample[sample["sample_id"]] = dim_map
        preliminary.append(row)
        logger.info("Topology %02d/%02d %s", idx, len(samples), sample["sample_id"])

    if max_finite_death <= 0:
        max_finite_death = 1.0
    epsilon_grid = np.linspace(0.0, max_finite_death * 1.05, num=betti_grid_points, dtype=np.float64)
    np.save(topology_dir / "betti_epsilon_grid.npy", epsilon_grid)

    betti_rows: list[dict[str, Any]] = []
    for row in preliminary:
        sample_id = row["sample_id"]
        for dim in range(maxdim + 1):
            curve = betti_curve(diagrams_by_sample[sample_id][dim], epsilon_grid)
            np.save(topology_dir / f"{sample_id}_H{dim}_betti.npy", curve)
            row[f"h{dim}_betti_auc"] = normalized_auc(epsilon_grid, curve)
            row[f"h{dim}_betti_max"] = float(np.max(curve)) if len(curve) else 0.0
            for grid_index, (eps, beta) in enumerate(zip(epsilon_grid.tolist(), curve.tolist())):
                betti_rows.append(
                    {
                        "sample_id": sample_id,
                        "pair_id": row["pair_id"],
                        "cwe": row["cwe"],
                        "class": row["class"],
                        "homology_dimension": dim,
                        "grid_index": grid_index,
                        "epsilon": eps,
                        "betti": beta,
                    }
                )

    write_json(topology_dir / "topological_metrics.json", preliminary)
    write_csv(topology_dir / "topological_metrics.csv", preliminary)
    write_csv(topology_dir / "betti_curves.csv", betti_rows)
    return preliminary, diagrams_by_sample, epsilon_grid


def paired_diagram_distances(
    run_dir: Path,
    samples: list[dict[str, Any]],
    diagrams_by_sample: dict[str, dict[int, np.ndarray]],
    *,
    maxdim: int,
    logger: logging.Logger,
) -> list[dict[str, Any]]:
    by_pair: dict[str, dict[str, dict[str, Any]]] = {}
    for sample in samples:
        by_pair.setdefault(sample["pair_id"], {})[sample["class"]] = sample
    rows: list[dict[str, Any]] = []
    for pair_id in sorted(by_pair, key=cwe_number):
        pair = by_pair[pair_id]
        secure = pair["secure"]
        vulnerable = pair["vulnerable"]
        row: dict[str, Any] = {
            "pair_id": pair_id,
            "cwe": secure["cwe"],
            "formal_project_subset": secure["formal_project_subset"],
        }
        for dim in range(maxdim + 1):
            a = diagrams_by_sample[secure["sample_id"]][dim]
            b = diagrams_by_sample[vulnerable["sample_id"]][dim]
            row[f"h{dim}_bottleneck"] = safe_diagram_distance(a, b, "bottleneck")
            row[f"h{dim}_wasserstein"] = safe_diagram_distance(a, b, "wasserstein")
        rows.append(row)
    write_csv(run_dir / "topology" / "pairwise_diagram_distances.csv", rows)
    write_json(run_dir / "topology" / "pairwise_diagram_distances.json", rows)
    logger.info("Computed secure-vulnerable diagram distances for %d CWE pairs", len(rows))
    return rows


def group_level_topology(
    run_dir: Path,
    samples: list[dict[str, Any]],
    *,
    maxdim: int,
    min_persistence_abs: float,
    min_persistence_fraction: float,
    logger: logging.Logger,
) -> dict[str, Any]:
    matrix = np.load(run_dir / "embeddings" / "package_embeddings.npy")
    index = read_json(run_dir / "embeddings" / "package_embedding_index.json")
    row_by_sample = {row["sample_id"]: int(row["row"]) for row in index}
    secure_points = np.vstack([matrix[row_by_sample[s["sample_id"]]] for s in samples if s["class"] == "secure"])
    vulnerable_points = np.vstack([matrix[row_by_sample[s["sample_id"]]] for s in samples if s["class"] == "vulnerable"])
    secure_dgms = compute_diagrams(secure_points, maxdim=maxdim)
    vuln_dgms = compute_diagrams(vulnerable_points, maxdim=maxdim)
    group_dir = run_dir / "topology" / "group_level"
    group_dir.mkdir(parents=True, exist_ok=True)
    save_diagrams_npz(group_dir / "secure_group_diagrams.npz", secure_dgms)
    save_diagrams_npz(group_dir / "vulnerable_group_diagrams.npz", vuln_dgms)
    result: dict[str, Any] = {
        "secure_point_count": int(len(secure_points)),
        "vulnerable_point_count": int(len(vulnerable_points)),
        "dimensions": {},
    }
    for dim in range(maxdim + 1):
        secure_summary = persistence_summary(
            secure_dgms[dim],
            minimum_persistence_absolute=min_persistence_abs,
            minimum_persistence_fraction=min_persistence_fraction,
        )
        vuln_summary = persistence_summary(
            vuln_dgms[dim],
            minimum_persistence_absolute=min_persistence_abs,
            minimum_persistence_fraction=min_persistence_fraction,
        )
        result["dimensions"][f"H{dim}"] = {
            "secure": secure_summary,
            "vulnerable": vuln_summary,
            "bottleneck": safe_diagram_distance(secure_dgms[dim], vuln_dgms[dim], "bottleneck"),
            "wasserstein": safe_diagram_distance(secure_dgms[dim], vuln_dgms[dim], "wasserstein"),
        }
    write_json(group_dir / "group_level_topology.json", result)
    logger.info("Computed class-level TDA on 20 secure vs 20 vulnerable package embeddings")
    return result


def paired_arrays(metrics: list[dict[str, Any]], metric: str) -> tuple[np.ndarray, np.ndarray, list[str]]:
    by_pair: dict[str, dict[str, float]] = {}
    for row in metrics:
        value = safe_float(row.get(metric))
        if value is None:
            continue
        by_pair.setdefault(str(row["pair_id"]), {})[str(row["class"])] = value
    pairs = [pair_id for pair_id, values in by_pair.items() if {"secure", "vulnerable"} <= set(values)]
    pairs.sort(key=cwe_number)
    secure = np.asarray([by_pair[p]["secure"] for p in pairs], dtype=np.float64)
    vulnerable = np.asarray([by_pair[p]["vulnerable"] for p in pairs], dtype=np.float64)
    return secure, vulnerable, pairs


def paired_permutation_pvalue(diff: np.ndarray, *, rng: np.random.Generator, permutations: int) -> float:
    diff = np.asarray(diff, dtype=np.float64)
    observed = abs(float(np.mean(diff)))
    if len(diff) == 0 or np.allclose(diff, 0.0):
        return 1.0
    batch = 5000
    extreme = 0
    done = 0
    while done < permutations:
        n = min(batch, permutations - done)
        signs = rng.choice(np.asarray([-1.0, 1.0]), size=(n, len(diff)), replace=True)
        stats = np.abs(np.mean(signs * diff[None, :], axis=1))
        extreme += int(np.sum(stats >= observed - 1e-15))
        done += n
    return float((extreme + 1) / (permutations + 1))


def bootstrap_mean_diff_ci(diff: np.ndarray, *, rng: np.random.Generator, resamples: int) -> tuple[float, float]:
    diff = np.asarray(diff, dtype=np.float64)
    if len(diff) == 0:
        return (math.nan, math.nan)
    batch = 2000
    values: list[np.ndarray] = []
    done = 0
    while done < resamples:
        n = min(batch, resamples - done)
        indices = rng.integers(0, len(diff), size=(n, len(diff)))
        values.append(np.mean(diff[indices], axis=1))
        done += n
    boot = np.concatenate(values)
    lo, hi = np.percentile(boot, [2.5, 97.5])
    return float(lo), float(hi)


def paired_rank_biserial(diff: np.ndarray) -> float:
    try:
        from scipy.stats import rankdata
    except ImportError as exc:
        raise RuntimeError("scipy is required") from exc
    diff = np.asarray(diff, dtype=np.float64)
    nonzero = diff[np.abs(diff) > 1e-15]
    if len(nonzero) == 0:
        return 0.0
    ranks = rankdata(np.abs(nonzero), method="average")
    pos = float(np.sum(ranks[nonzero > 0]))
    neg = float(np.sum(ranks[nonzero < 0]))
    denom = pos + neg
    return (pos - neg) / denom if denom else 0.0


def benjamini_hochberg(pvalues: list[float]) -> list[float]:
    m = len(pvalues)
    if m == 0:
        return []
    order = np.argsort(np.asarray(pvalues, dtype=float))
    adjusted = np.empty(m, dtype=float)
    previous = 1.0
    for rank_from_end, index in enumerate(order[::-1], start=1):
        rank = m - rank_from_end + 1
        raw = float(pvalues[index])
        value = min(previous, raw * m / rank)
        adjusted[index] = min(1.0, value)
        previous = value
    return adjusted.tolist()


def _safe_wilcoxon(vulnerable: np.ndarray, secure: np.ndarray) -> tuple[float, float]:
    try:
        from scipy.stats import wilcoxon
    except ImportError as exc:
        raise RuntimeError("scipy is required") from exc
    diff = np.asarray(vulnerable, dtype=float) - np.asarray(secure, dtype=float)
    if len(diff) == 0 or np.allclose(diff, 0.0):
        return 0.0, 1.0
    try:
        test = wilcoxon(vulnerable, secure, alternative="two-sided", zero_method="wilcox", method="auto")
        return float(test.statistic), float(test.pvalue)
    except ValueError:
        return 0.0, 1.0


def length_complexity_confound_analysis(
    run_dir: Path,
    metrics: list[dict[str, Any]],
    *,
    permutations: int,
    bootstrap_resamples: int,
    seed: int,
    logger: logging.Logger,
) -> dict[str, Any]:
    """Quantify source-size imbalance and its association with topology.

    This is a prespecified sensitivity/confound analysis.  It does not replace
    the paired topological tests and does not change the representation after
    observing class outcomes.
    """
    try:
        from scipy.stats import spearmanr
    except ImportError as exc:
        raise RuntimeError("scipy is required") from exc

    confound_dir = run_dir / "confounds"
    confound_dir.mkdir(parents=True, exist_ok=True)
    source_features = ["source_token_count", "source_chars", "unit_count"]
    paired_rows: list[dict[str, Any]] = []

    for feature_index, feature in enumerate(source_features):
        secure, vulnerable, pairs = paired_arrays(metrics, feature)
        diff = vulnerable - secure
        rng_perm = np.random.default_rng(seed + 40001 + feature_index * 101)
        rng_boot = np.random.default_rng(seed + 50001 + feature_index * 101)
        stat, p_w = _safe_wilcoxon(vulnerable, secure)
        p_perm = paired_permutation_pvalue(diff, rng=rng_perm, permutations=permutations)
        ci_lo, ci_hi = bootstrap_mean_diff_ci(diff, rng=rng_boot, resamples=bootstrap_resamples)
        sd = float(np.std(diff, ddof=1)) if len(diff) > 1 else 0.0
        paired_rows.append(
            {
                "feature": feature,
                "pair_count": len(pairs),
                "secure_mean": float(np.mean(secure)),
                "secure_median": float(np.median(secure)),
                "vulnerable_mean": float(np.mean(vulnerable)),
                "vulnerable_median": float(np.median(vulnerable)),
                "mean_difference_vulnerable_minus_secure": float(np.mean(diff)),
                "median_difference_vulnerable_minus_secure": float(np.median(diff)),
                "vulnerable_greater_pair_count": int(np.sum(diff > 0)),
                "secure_greater_pair_count": int(np.sum(diff < 0)),
                "equal_pair_count": int(np.sum(np.isclose(diff, 0.0))),
                "bootstrap_95ci_low": ci_lo,
                "bootstrap_95ci_high": ci_hi,
                "wilcoxon_statistic": stat,
                "wilcoxon_p": p_w,
                "paired_permutation_p": p_perm,
                "paired_cohen_dz": float(np.mean(diff) / sd) if sd > 0 else 0.0,
                "paired_rank_biserial": paired_rank_biserial(diff),
            }
        )

    correlation_rows: list[dict[str, Any]] = []
    token_values = np.asarray([float(row["source_token_count"]) for row in metrics], dtype=float)
    for metric in PRIMARY_METRICS:
        metric_values = np.asarray([float(row.get(metric, 0.0) or 0.0) for row in metrics], dtype=float)
        if np.allclose(token_values, token_values[0]) or np.allclose(metric_values, metric_values[0]):
            rho_all, p_all = 0.0, 1.0
        else:
            result = spearmanr(token_values, metric_values)
            rho_all, p_all = float(result.statistic), float(result.pvalue)

        s_tok, v_tok, pairs_tok = paired_arrays(metrics, "source_token_count")
        s_metric, v_metric, pairs_metric = paired_arrays(metrics, metric)
        if pairs_tok != pairs_metric:
            raise RuntimeError(f"Pair mismatch while computing length sensitivity for {metric}")
        delta_tokens = v_tok - s_tok
        delta_metric = v_metric - s_metric
        if np.allclose(delta_tokens, delta_tokens[0]) or np.allclose(delta_metric, delta_metric[0]):
            rho_delta, p_delta = 0.0, 1.0
        else:
            result_delta = spearmanr(delta_tokens, delta_metric)
            rho_delta, p_delta = float(result_delta.statistic), float(result_delta.pvalue)
        correlation_rows.append(
            {
                "metric": metric,
                "sample_count": len(metrics),
                "pair_count": len(pairs_tok),
                "spearman_rho_tokens_vs_metric_all_samples": rho_all,
                "spearman_p_tokens_vs_metric_all_samples": p_all,
                "spearman_rho_paired_delta_tokens_vs_delta_metric": rho_delta,
                "spearman_p_paired_delta_tokens_vs_delta_metric": p_delta,
                "interpretation": "exploratory sensitivity analysis; not part of the primary FDR family",
            }
        )

    # Provide FDR-adjusted correlation p-values as descriptive safeguards while
    # keeping them outside the primary hypothesis-test family.
    q_all = benjamini_hochberg([float(r["spearman_p_tokens_vs_metric_all_samples"]) for r in correlation_rows])
    q_delta = benjamini_hochberg([float(r["spearman_p_paired_delta_tokens_vs_delta_metric"]) for r in correlation_rows])
    for row, qa, qd in zip(correlation_rows, q_all, q_delta):
        row["bh_q_tokens_vs_metric_all_samples"] = qa
        row["bh_q_paired_delta_tokens_vs_delta_metric"] = qd

    write_csv(confound_dir / "source_feature_paired_tests.csv", paired_rows)
    write_json(confound_dir / "source_feature_paired_tests.json", paired_rows)
    write_csv(confound_dir / "source_length_topology_correlations.csv", correlation_rows)
    write_json(confound_dir / "source_length_topology_correlations.json", correlation_rows)

    token_row = next(row for row in paired_rows if row["feature"] == "source_token_count")
    summary = {
        "schema_version": "2.0",
        "experiment_schema": EXPERIMENT_SCHEMA,
        "created_at_utc": utc_now(),
        "purpose": (
            "Sensitivity analysis for systematic source-length/complexity differences. "
            "These covariates do not alter the primary TDA representation or labels."
        ),
        "paired_source_feature_tests": paired_rows,
        "token_length_summary": token_row,
        "topology_correlations_with_token_length": correlation_rows,
    }
    write_json(confound_dir / "length_complexity_confound_summary.json", summary)
    logger.info("Completed source-length/complexity confound analysis")
    return summary


def scalar_statistics(
    run_dir: Path,
    metrics: list[dict[str, Any]],
    *,
    permutations: int,
    bootstrap_resamples: int,
    seed: int,
    logger: logging.Logger,
) -> list[dict[str, Any]]:
    try:
        from scipy.stats import shapiro, wilcoxon
    except ImportError as exc:
        raise RuntimeError("scipy is required") from exc

    rows: list[dict[str, Any]] = []
    for metric_index, metric in enumerate(PRIMARY_METRICS + SUPPLEMENTARY_METRICS):
        secure, vulnerable, pairs = paired_arrays(metrics, metric)
        diff = vulnerable - secure
        rng_perm = np.random.default_rng(seed + metric_index * 1009 + 1)
        rng_boot = np.random.default_rng(seed + metric_index * 1009 + 2)
        if len(diff) == 0:
            continue
        if np.allclose(diff, 0.0):
            wilcoxon_stat, wilcoxon_p = 0.0, 1.0
        else:
            try:
                test = wilcoxon(vulnerable, secure, alternative="two-sided", zero_method="wilcox", method="auto")
                wilcoxon_stat, wilcoxon_p = float(test.statistic), float(test.pvalue)
            except ValueError:
                wilcoxon_stat, wilcoxon_p = 0.0, 1.0
        permutation_p = paired_permutation_pvalue(diff, rng=rng_perm, permutations=permutations)
        ci_low, ci_high = bootstrap_mean_diff_ci(diff, rng=rng_boot, resamples=bootstrap_resamples)
        sd = float(np.std(diff, ddof=1)) if len(diff) > 1 else 0.0
        dz = float(np.mean(diff) / sd) if sd > 0 else 0.0
        shapiro_p = None
        if 3 <= len(diff) <= 5000 and not np.allclose(diff, diff[0]):
            try:
                shapiro_p = float(shapiro(diff).pvalue)
            except Exception:
                shapiro_p = None
        rows.append(
            {
                "metric": metric,
                "primary_metric": metric in PRIMARY_METRICS,
                "pair_count": len(pairs),
                "secure_mean": float(np.mean(secure)),
                "secure_median": float(np.median(secure)),
                "vulnerable_mean": float(np.mean(vulnerable)),
                "vulnerable_median": float(np.median(vulnerable)),
                "mean_difference_vulnerable_minus_secure": float(np.mean(diff)),
                "median_difference_vulnerable_minus_secure": float(np.median(diff)),
                "bootstrap_95ci_low": ci_low,
                "bootstrap_95ci_high": ci_high,
                "wilcoxon_statistic": wilcoxon_stat,
                "wilcoxon_p": wilcoxon_p,
                "paired_permutation_p": permutation_p,
                "paired_cohen_dz": dz,
                "paired_rank_biserial": paired_rank_biserial(diff),
                "shapiro_p_on_paired_differences_descriptive_only": shapiro_p,
            }
        )

    primary_indices = [i for i, row in enumerate(rows) if row["primary_metric"]]
    corrected = benjamini_hochberg([rows[i]["paired_permutation_p"] for i in primary_indices])
    for i, q in zip(primary_indices, corrected):
        rows[i]["bh_q_primary_permutation"] = q
        rows[i]["significant_at_fdr_0_05"] = bool(q < 0.05)
    for i, row in enumerate(rows):
        if i not in primary_indices:
            row["bh_q_primary_permutation"] = None
            row["significant_at_fdr_0_05"] = None

    stats_dir = run_dir / "statistics"
    stats_dir.mkdir(parents=True, exist_ok=True)
    write_csv(stats_dir / "scalar_statistical_tests.csv", rows)
    write_json(stats_dir / "scalar_statistical_tests.json", rows)
    logger.info("Completed paired statistics for %d topological metrics", len(rows))
    return rows


def betti_global_tests(
    run_dir: Path,
    metrics: list[dict[str, Any]],
    diagrams_by_sample: dict[str, dict[int, np.ndarray]],
    epsilon_grid: np.ndarray,
    *,
    maxdim: int,
    permutations: int,
    seed: int,
    logger: logging.Logger,
) -> list[dict[str, Any]]:
    by_pair: dict[str, dict[str, str]] = {}
    for row in metrics:
        by_pair.setdefault(str(row["pair_id"]), {})[str(row["class"])] = str(row["sample_id"])
    pair_ids = sorted([p for p, v in by_pair.items() if {"secure", "vulnerable"} <= set(v)], key=cwe_number)
    results = []
    for dim in range(maxdim + 1):
        secure_curves = []
        vuln_curves = []
        for pair_id in pair_ids:
            secure_curves.append(betti_curve(diagrams_by_sample[by_pair[pair_id]["secure"]][dim], epsilon_grid))
            vuln_curves.append(betti_curve(diagrams_by_sample[by_pair[pair_id]["vulnerable"]][dim], epsilon_grid))
        secure_arr = np.vstack(secure_curves)
        vuln_arr = np.vstack(vuln_curves)
        paired_diff = vuln_arr - secure_arr
        mean_diff_curve = np.mean(paired_diff, axis=0)
        observed = float(np.sqrt(np.mean(mean_diff_curve ** 2)))
        rng = np.random.default_rng(seed + 7001 * (dim + 1))
        extreme = 0
        batch = 2000
        done = 0
        while done < permutations:
            n = min(batch, permutations - done)
            signs = rng.choice(np.asarray([-1.0, 1.0]), size=(n, len(pair_ids), 1), replace=True)
            perm_mean = np.mean(signs * paired_diff[None, :, :], axis=1)
            perm_stats = np.sqrt(np.mean(perm_mean ** 2, axis=1))
            extreme += int(np.sum(perm_stats >= observed - 1e-15))
            done += n
        p = float((extreme + 1) / (permutations + 1))
        results.append(
            {
                "homology_dimension": dim,
                "pair_count": len(pair_ids),
                "statistic": "RMS distance between mean paired Betti curves",
                "observed": observed,
                "paired_signflip_permutation_p": p,
                "permutations": permutations,
            }
        )
    write_csv(run_dir / "statistics" / "betti_curve_global_tests.csv", results)
    write_json(run_dir / "statistics" / "betti_curve_global_tests.json", results)
    logger.info("Completed global paired permutation tests for Betti curves")
    return results


def group_level_permutation_test(
    run_dir: Path,
    samples: list[dict[str, Any]],
    *,
    maxdim: int,
    permutations: int,
    seed: int,
    logger: logging.Logger,
) -> list[dict[str, Any]]:
    matrix = np.load(run_dir / "embeddings" / "package_embeddings.npy")
    index = read_json(run_dir / "embeddings" / "package_embedding_index.json")
    row_by_sample = {row["sample_id"]: int(row["row"]) for row in index}
    by_pair: dict[str, dict[str, str]] = {}
    for sample in samples:
        by_pair.setdefault(sample["pair_id"], {})[sample["class"]] = sample["sample_id"]
    pair_ids = sorted(by_pair, key=cwe_number)
    secure = np.vstack([matrix[row_by_sample[by_pair[p]["secure"]]] for p in pair_ids])
    vulnerable = np.vstack([matrix[row_by_sample[by_pair[p]["vulnerable"]]] for p in pair_ids])
    observed_secure = compute_diagrams(secure, maxdim=maxdim)
    observed_vuln = compute_diagrams(vulnerable, maxdim=maxdim)
    observed = [safe_diagram_distance(observed_secure[d], observed_vuln[d], "bottleneck") for d in range(maxdim + 1)]

    rng = np.random.default_rng(seed + 99991)
    extreme = [0 for _ in range(maxdim + 1)]
    for permutation_index in range(permutations):
        swaps = rng.integers(0, 2, size=len(pair_ids), dtype=np.int8)
        a_rows = []
        b_rows = []
        for i, pair_id in enumerate(pair_ids):
            s = matrix[row_by_sample[by_pair[pair_id]["secure"]]]
            v = matrix[row_by_sample[by_pair[pair_id]["vulnerable"]]]
            if swaps[i]:
                a_rows.append(v); b_rows.append(s)
            else:
                a_rows.append(s); b_rows.append(v)
        a_dgms = compute_diagrams(np.vstack(a_rows), maxdim=maxdim)
        b_dgms = compute_diagrams(np.vstack(b_rows), maxdim=maxdim)
        for dim in range(maxdim + 1):
            stat = safe_diagram_distance(a_dgms[dim], b_dgms[dim], "bottleneck")
            if stat >= observed[dim] - 1e-15:
                extreme[dim] += 1
        if (permutation_index + 1) % max(1, permutations // 10) == 0:
            logger.info("Group-level TDA permutation progress: %d/%d", permutation_index + 1, permutations)

    results = [
        {
            "homology_dimension": dim,
            "statistic": "bottleneck distance between 20-point secure and vulnerable package-embedding clouds",
            "observed_bottleneck": observed[dim],
            "paired_label_swap_permutation_p": float((extreme[dim] + 1) / (permutations + 1)),
            "permutations": permutations,
            "pair_count": len(pair_ids),
        }
        for dim in range(maxdim + 1)
    ]
    write_csv(run_dir / "statistics" / "group_level_tda_permutation.csv", results)
    write_json(run_dir / "statistics" / "group_level_tda_permutation.json", results)
    logger.info("Completed group-level paired-label permutation test")
    return results


def exploratory_classifier(
    run_dir: Path,
    metrics: list[dict[str, Any]],
    *,
    seed: int,
    permutations: int,
    logger: logging.Logger,
) -> list[dict[str, Any]]:
    try:
        from sklearn.base import clone
        from sklearn.linear_model import LogisticRegression
        from sklearn.metrics import accuracy_score, balanced_accuracy_score, f1_score, roc_auc_score
        from sklearn.model_selection import GroupKFold
        from sklearn.pipeline import make_pipeline
        from sklearn.preprocessing import StandardScaler
        from sklearn.svm import SVC
    except ImportError as exc:
        raise RuntimeError("scikit-learn is required for the exploratory classifier") from exc

    rows = sorted(metrics, key=lambda r: (cwe_number(str(r["pair_id"])), str(r["class"])))
    y = np.asarray([1 if row["class"] == "vulnerable" else 0 for row in rows], dtype=int)
    groups = np.asarray([row["pair_id"] for row in rows], dtype=object)
    unique_groups = sorted(set(groups.tolist()), key=cwe_number)
    if len(unique_groups) < 5:
        raise RuntimeError("Need at least five CWE pairs for group-wise cross-validation")

    splitter = GroupKFold(n_splits=5)
    # Folds depend only on CWE pair identities, never on labels or feature values.
    fold_indices = list(splitter.split(np.zeros((len(rows), 1)), y, groups))

    feature_sets = {
        "length_only": ["source_token_count"],
        "topology_only": list(PRIMARY_METRICS),
        "topology_plus_length": [*PRIMARY_METRICS, "source_token_count"],
    }
    model_builders = {
        "logistic_regression": lambda: make_pipeline(
            StandardScaler(),
            LogisticRegression(max_iter=5000, random_state=seed),
        ),
        "linear_svm": lambda: make_pipeline(
            StandardScaler(),
            SVC(kernel="linear", C=1.0),
        ),
    }

    pair_to_indices: dict[str, list[int]] = {}
    for i, group in enumerate(groups.tolist()):
        pair_to_indices.setdefault(str(group), []).append(i)
    if any(len(indices) != 2 for indices in pair_to_indices.values()):
        raise RuntimeError("Every CWE pair must contain exactly one secure and one vulnerable sample")

    def matrix_for(features: list[str]) -> np.ndarray:
        matrix = np.asarray(
            [[float(row.get(feature, 0.0) or 0.0) for feature in features] for row in rows],
            dtype=float,
        )
        if not np.isfinite(matrix).all():
            raise RuntimeError(f"Non-finite classifier features detected: {features}")
        return matrix

    def cv_predictions(model: Any, X: np.ndarray, labels: np.ndarray) -> tuple[np.ndarray, np.ndarray]:
        preds = np.zeros(len(labels), dtype=int)
        scores = np.zeros(len(labels), dtype=float)
        for train_idx, test_idx in fold_indices:
            fitted = clone(model)
            fitted.fit(X[train_idx], labels[train_idx])
            preds[test_idx] = fitted.predict(X[test_idx])
            if hasattr(fitted, "decision_function"):
                scores[test_idx] = np.asarray(fitted.decision_function(X[test_idx]), dtype=float).reshape(-1)
            elif hasattr(fitted, "predict_proba"):
                scores[test_idx] = fitted.predict_proba(X[test_idx])[:, 1]
            else:
                scores[test_idx] = preds[test_idx]
        return preds, scores

    results: list[dict[str, Any]] = []
    combo_index = 0
    for feature_set_name, features in feature_sets.items():
        X = matrix_for(features)
        for model_name, builder in model_builders.items():
            combo_index += 1
            model = builder()
            preds, scores = cv_predictions(model, X, y)
            observed_bal = float(balanced_accuracy_score(y, preds))
            result = {
                "model": model_name,
                "feature_set": feature_set_name,
                "features": features,
                "cross_validation": (
                    "5-fold GroupKFold by CWE pair; secure and vulnerable member of each pair stay in the same fold"
                ),
                "accuracy": float(accuracy_score(y, preds)),
                "balanced_accuracy": observed_bal,
                "f1": float(f1_score(y, preds, zero_division=0)),
                "roc_auc": float(roc_auc_score(y, scores)) if len(np.unique(y)) == 2 else None,
            }
            rng = np.random.default_rng(seed + 777 + combo_index * 1009)
            extreme = 0
            for _ in range(permutations):
                perm_y = y.copy()
                for indices in pair_to_indices.values():
                    if rng.integers(0, 2):
                        perm_y[indices] = perm_y[indices[::-1]]
                p_preds, _ = cv_predictions(model, X, perm_y)
                stat = float(balanced_accuracy_score(perm_y, p_preds))
                if stat >= observed_bal - 1e-15:
                    extreme += 1
            result["paired_label_swap_permutation_p_balanced_accuracy"] = float(
                (extreme + 1) / (permutations + 1)
            )
            result["classifier_permutations"] = permutations
            result["role"] = (
                "confound_baseline" if feature_set_name == "length_only"
                else "primary_exploratory_topology" if feature_set_name == "topology_only"
                else "exploratory_sensitivity_topology_plus_length"
            )
            results.append(result)

    write_json(run_dir / "statistics" / "exploratory_classification.json", results)
    write_csv(
        run_dir / "statistics" / "exploratory_classification.csv",
        [
            {
                k: (json.dumps(v) if isinstance(v, (list, dict)) else v)
                for k, v in row.items()
            }
            for row in results
        ],
    )
    logger.info("Completed exploratory classification: length-only, topology-only, and topology+length")
    return results

def make_figures(
    run_dir: Path,
    metrics: list[dict[str, Any]],
    diagrams_by_sample: dict[str, dict[int, np.ndarray]],
    epsilon_grid: np.ndarray,
    *,
    maxdim: int,
    logger: logging.Logger,
) -> None:
    try:
        import matplotlib.pyplot as plt
    except ImportError as exc:
        raise RuntimeError("matplotlib is required for figures") from exc

    figures_dir = run_dir / "figures"
    figures_dir.mkdir(parents=True, exist_ok=True)

    # Paired plots for the 10 prespecified primary scalar metrics.
    for metric in PRIMARY_METRICS:
        secure, vulnerable, pairs = paired_arrays(metrics, metric)
        fig, ax = plt.subplots(figsize=(7.0, 4.8))
        for i, pair_id in enumerate(pairs):
            ax.plot([0, 1], [secure[i], vulnerable[i]], marker="o", alpha=0.55)
        ax.set_xticks([0, 1], ["Secure", "Vulnerable"])
        ax.set_ylabel(metric)
        ax.set_title(f"Paired CWE comparison: {metric}")
        ax.grid(axis="y", alpha=0.25)
        fig.tight_layout()
        fig.savefig(figures_dir / f"paired_{metric}.png", dpi=180)
        plt.close(fig)

    # Mean Betti curves, one figure per homology dimension.
    by_class = {"secure": [], "vulnerable": []}
    for row in metrics:
        by_class[str(row["class"])].append(str(row["sample_id"]))
    for dim in range(maxdim + 1):
        fig, ax = plt.subplots(figsize=(7.0, 4.8))
        for label in ["secure", "vulnerable"]:
            curves = np.vstack([betti_curve(diagrams_by_sample[sample_id][dim], epsilon_grid) for sample_id in by_class[label]])
            mean = curves.mean(axis=0)
            ax.plot(epsilon_grid, mean, label=label)
        ax.set_xlabel("Filtration scale ε")
        ax.set_ylabel(f"Mean β{dim}(ε)")
        ax.set_title(f"Mean Betti curve H{dim}")
        ax.legend()
        ax.grid(alpha=0.25)
        fig.tight_layout()
        fig.savefig(figures_dir / f"mean_betti_H{dim}.png", dpi=180)
        plt.close(fig)

    # Representative persistence diagrams for the five formal-project CWEs.
    for cwe in sorted(PRIMARY_FORMAL_CWES):
        pair_id = next((row["pair_id"] for row in metrics if int(row["cwe_number"]) == cwe), None)
        if pair_id is None:
            continue
        pair_rows = {row["class"]: row for row in metrics if row["pair_id"] == pair_id}
        for dim in range(maxdim + 1):
            fig, ax = plt.subplots(figsize=(5.6, 5.2))
            max_axis = 0.0
            for label in ["secure", "vulnerable"]:
                dgm = diagrams_by_sample[pair_rows[label]["sample_id"]][dim]
                finite = dgm[np.isfinite(dgm[:, 1])] if dgm.size else np.empty((0, 2))
                if len(finite):
                    ax.scatter(finite[:, 0], finite[:, 1], label=label, alpha=0.75)
                    max_axis = max(max_axis, float(np.max(finite)))
            max_axis = max(max_axis, 1e-3)
            ax.plot([0, max_axis], [0, max_axis], linestyle="--", linewidth=1)
            ax.set_xlabel("Birth")
            ax.set_ylabel("Death")
            ax.set_title(f"{pair_rows['secure']['cwe']} persistence diagram H{dim}")
            ax.legend()
            ax.grid(alpha=0.2)
            fig.tight_layout()
            fig.savefig(figures_dir / f"{pair_id}_H{dim}_persistence.png", dpi=180)
            plt.close(fig)

    # Paired source-token-count plot for the prespecified confound sensitivity analysis.
    secure_len, vulnerable_len, length_pairs = paired_arrays(metrics, "source_token_count")
    fig, ax = plt.subplots(figsize=(7.0, 4.8))
    for i, pair_id in enumerate(length_pairs):
        ax.plot([0, 1], [secure_len[i], vulnerable_len[i]], marker="o", alpha=0.55)
    ax.set_xticks([0, 1], ["Secure", "Vulnerable"])
    ax.set_ylabel("CodeBERT source token count")
    ax.set_title("Paired source-length comparison by CWE")
    ax.grid(axis="y", alpha=0.25)
    fig.tight_layout()
    fig.savefig(figures_dir / "paired_source_token_count.png", dpi=180)
    plt.close(fig)

    logger.info("Generated analysis figures in %s", figures_dir)


def summarize_results(
    run_dir: Path,
    validation: dict[str, Any],
    pilot: dict[str, Any],
    scalar_tests: list[dict[str, Any]],
    betti_tests: list[dict[str, Any]],
    group_tests: list[dict[str, Any]],
    classification: list[dict[str, Any]],
    group_topology: dict[str, Any],
    confound_analysis: dict[str, Any],
    logger: logging.Logger,
) -> dict[str, Any]:
    primary = [row for row in scalar_tests if row["primary_metric"]]
    significant = [row for row in primary if row.get("significant_at_fdr_0_05")]
    summary = {
        "schema_version": "2.0",
        "experiment_schema": EXPERIMENT_SCHEMA,
        "created_at_utc": utc_now(),
        "dataset": {
            "pairs": 20,
            "samples": 40,
            "secure": 20,
            "vulnerable": 20,
            "all_controls_valid": validation.get("all_reference_controls_valid"),
            "valid_pairs": validation.get("valid_task_count"),
        },
        "pilot": pilot,
        "primary_scalar_tests": {
            "count": len(primary),
            "fdr_significant_count": len(significant),
            "fdr_significant_metrics": [row["metric"] for row in significant],
        },
        "betti_curve_global_tests": betti_tests,
        "group_level_tda_permutation": group_tests,
        "exploratory_classification": classification,
        "group_level_topology": group_topology,
        "length_complexity_confound_analysis": confound_analysis,
        "interpretation_guardrail": (
            "This file reports computed evidence only. A non-significant p-value is not proof that secure and vulnerable code are identical; "
            "TDA remains complementary to the authoritative CWEval secure/unsafe control labels."
        ),
    }
    report_dir = run_dir / "reports"
    report_dir.mkdir(parents=True, exist_ok=True)
    write_json(report_dir / "analysis_summary.json", summary)

    lines = [
        "# TDA Statistical Experiment - Results Summary",
        "",
        f"Generated: {summary['created_at_utc']}",
        "",
        "## Dataset",
        f"- 20 matched Flask CWE pairs = 40 samples (20 secure + 20 vulnerable).",
        f"- Validated pairs: {validation.get('valid_task_count')}/20.",
        f"- All reference controls valid: {validation.get('all_reference_controls_valid')}.",
        "",
        "## Pilot",
        f"- Raw H1 non-empty: {pilot.get('h1_raw_nonempty_count')}/{pilot.get('pilot_sample_count')} formal-subset samples.",
        f"- Persistence-filtered H1 non-empty: {pilot.get('h1_significant_nonempty_count')}/{pilot.get('pilot_sample_count')} formal-subset samples.",
        f"- H1 viability flag (based on persistence-filtered H1): {pilot.get('h1_viable_for_primary_interpretation')}.",
        "",
        "## Primary scalar tests",
        f"- Primary metrics tested: {len(primary)}.",
        f"- Significant after Benjamini-Hochberg FDR 0.05: {len(significant)}.",
        f"- Metrics: {', '.join(row['metric'] for row in significant) if significant else 'none'}.",
        "",
        "## Source-length / complexity sensitivity",
        f"- Secure mean token count: {confound_analysis['token_length_summary']['secure_mean']:.3f}.",
        f"- Vulnerable mean token count: {confound_analysis['token_length_summary']['vulnerable_mean']:.3f}.",
        f"- Mean vulnerable-secure token difference: {confound_analysis['token_length_summary']['mean_difference_vulnerable_minus_secure']:.3f}.",
        f"- Paired token-length permutation p: {confound_analysis['token_length_summary']['paired_permutation_p']:.6g}.",
        "- Classification results below explicitly compare length-only, topology-only, and topology+length feature sets.",
        "",
        "## Betti curve global tests",
    ]
    for row in betti_tests:
        lines.append(
            f"- H{row['homology_dimension']}: statistic={row['observed']:.6g}, p={row['paired_signflip_permutation_p']:.6g}"
        )
    lines += ["", "## Group-level TDA permutation"]
    for row in group_tests:
        lines.append(
            f"- H{row['homology_dimension']}: observed bottleneck={row['observed_bottleneck']:.6g}, p={row['paired_label_swap_permutation_p']:.6g}"
        )
    lines += ["", "## Exploratory topology-only classification"]
    for row in classification:
        lines.append(
            f"- {row['model']} [{row['feature_set']}]: balanced_accuracy={row['balanced_accuracy']:.4f}, "
            f"F1={row['f1']:.4f}, permutation_p={row['paired_label_swap_permutation_p_balanced_accuracy']:.6g}"
        )
    lines += [
        "",
        "## Guardrail",
        "A non-significant result means insufficient evidence of a systematic topological difference under this representation and dataset; it does not prove equality or security.",
        "Raw H0 interval count is structurally determined by the fixed 16-point cloud (15 finite H0 intervals); it is supplementary rather than discriminative evidence.",
        "Source-length results are treated as a sensitivity/confound analysis and do not alter the prespecified primary TDA representation.",
        "",
        "Upload results_to_share.zip for interpretation and article drafting.",
    ]
    (report_dir / "RESULTS_SUMMARY.md").write_text("\n".join(lines) + "\n", encoding="utf-8")
    logger.info("Wrote final summary report")
    return summary


def build_share_bundle(run_dir: Path, logger: logging.Logger, *, pilot_only: bool = False) -> Path:
    """Build an auditable share bundle including the numerical TDA artifacts.

    The v1 pilot bundle contained only summaries.  v2 intentionally includes the
    point clouds, package embeddings and persistence diagrams required to
    recompute/inspect the reported topological quantities independently.
    """
    bundle = run_dir / ("pilot_results_to_share.zip" if pilot_only else "results_to_share.zip")

    paths: list[Path] = [
        run_dir / "experiment_config.json",
        run_dir / "provenance",
        run_dir / "dataset" / "dataset_manifest.csv",
        run_dir / "dataset" / "dataset_manifest.json",
        run_dir / "dataset" / "reference_manifest.json",
        run_dir / "dataset" / "pairs",
        run_dir / "validation",
        run_dir / "embeddings" / "embedding_metadata.json",
        run_dir / "embeddings" / "model_fingerprint.json",
        run_dir / "embeddings" / "package_embeddings.npy",
        run_dir / "embeddings" / "package_embedding_index.json",
        run_dir / "embeddings" / "pointcloud_index.json",
        run_dir / "embeddings" / "pointclouds",
        run_dir / "confounds" / "source_length_manifest.csv",
        run_dir / "confounds" / "source_length_manifest.json",
        run_dir / "pilot",
        run_dir / "execution.log",
    ]
    if not pilot_only:
        paths.extend(
            [
                run_dir / "topology",
                run_dir / "statistics",
                run_dir / "confounds",
                run_dir / "figures",
                run_dir / "reports",
            ]
        )

    files: dict[str, Path] = {}
    for path in paths:
        if path.is_file():
            files[path.relative_to(run_dir).as_posix()] = path
        elif path.is_dir():
            for child in sorted(path.rglob("*")):
                if child.is_file() and child.resolve() != bundle.resolve():
                    files[child.relative_to(run_dir).as_posix()] = child

    with zipfile.ZipFile(bundle, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        for arcname in sorted(files):
            archive.write(files[arcname], arcname=arcname)
    logger.info("Created auditable share bundle with %d files: %s", len(files), bundle)
    return bundle

def default_config() -> dict[str, Any]:
    return {
        "schema_version": "2.0",
        "experiment_schema": EXPERIMENT_SCHEMA,
        "dataset": {
            "population": "all 20 Python/Flask tasks in the supplied CWEval task catalog",
            "pairing": "secure reference vs unsafe control within the same CWEval task",
            "formal_project_subset_cwes": sorted(PRIMARY_FORMAL_CWES),
        },
        "embedding": {
            "model_path": str(Path.home() / "models" / "codebert-base"),
            "device": "auto",
            "max_tokens": 512,
            "overlap_tokens": 64,
            "allow_download": False,
        },
        "point_cloud": {
            "primary_method": "fixed_count_overlapping_local_codebert_windows",
            "points_per_sample": 16,
            "window_tokens": 32,
            "reason": (
                "Each program must yield its own equally sized point cloud. A fixed point count controls the direct dependence of H0 interval count on code length."
            ),
        },
        "topology": {
            "complex": "Vietoris-Rips via ripser",
            "distance": "Explicit pairwise Euclidean distance matrix on L2-normalized CodeBERT local-window vectors",
            "ripser_input": "precomputed distance matrix (distance_matrix=True)",
            "maxdim": 1,
            "minimum_persistence_absolute": 0.01,
            "minimum_persistence_fraction": 0.05,
            "betti_grid_points": 101,
            "pilot_h1_significant_viability_threshold": 0.40,
        },
        "statistics": {
            "paired_permutations": 50000,
            "bootstrap_resamples": 10000,
            "group_level_tda_permutations": 2000,
            "classifier_permutations": 1000,
            "random_seed": 20261006,
            "multiple_testing": "Benjamini-Hochberg FDR on 10 prespecified scalar metrics",
            "primary_metrics": PRIMARY_METRICS,
            "confound_sensitivity": {
                "source_features": ["source_token_count", "source_chars", "unit_count"],
                "classifier_feature_sets": ["length_only", "topology_only", "topology_plus_length"],
                "role": "secondary sensitivity analysis; does not alter the primary TDA representation",
            },
        },
    }


def load_config(path: Path) -> dict[str, Any]:
    cfg = read_json(path)
    if cfg.get("experiment_schema") != EXPERIMENT_SCHEMA:
        raise RuntimeError(f"Unexpected experiment schema in {path}")
    return cfg


def create_run_dir(base: Path) -> Path:
    stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    run_dir = base / "runs" / f"run_{stamp}"
    run_dir.mkdir(parents=True, exist_ok=False)
    return run_dir


def copy_and_freeze_config(config_path: Path, run_dir: Path, overrides: dict[str, Any]) -> dict[str, Any]:
    config = load_config(config_path)
    if overrides.get("model_path"):
        config["embedding"]["model_path"] = str(Path(overrides["model_path"]).expanduser().resolve())
    else:
        config["embedding"]["model_path"] = str(Path(config["embedding"]["model_path"]).expanduser().resolve())
    if overrides.get("device"):
        config["embedding"]["device"] = overrides["device"]
    config["created_at_utc"] = utc_now()
    config["project_root"] = str(PROJECT_ROOT.resolve())
    config["script_sha256"] = sha256_file(Path(__file__).resolve())
    frozen = run_dir / "experiment_config.json"
    write_json(frozen, config)

    provenance_dir = run_dir / "provenance"
    provenance_dir.mkdir(parents=True, exist_ok=True)
    shutil.copy2(Path(__file__).resolve(), provenance_dir / "run_experiment.py")
    shutil.copy2(config_path.resolve(), provenance_dir / "config_source.json")
    for name in ["requirements.txt", "README.md"]:
        source = SCRIPT_DIR / name
        if source.is_file():
            shutil.copy2(source, provenance_dir / name)
    write_json(
        provenance_dir / "implementation_identity.json",
        {
            "created_at_utc": utc_now(),
            "experiment_schema": EXPERIMENT_SCHEMA,
            "run_experiment_sha256": sha256_file(Path(__file__).resolve()),
            "config_source_sha256": sha256_file(config_path.resolve()),
        },
    )
    return config


def load_existing_run_config(run_dir: Path) -> dict[str, Any]:
    config_path = run_dir / "experiment_config.json"
    if not config_path.is_file():
        raise FileNotFoundError(f"Missing frozen run config: {config_path}")
    config = read_json(config_path)
    if config.get("script_sha256") != sha256_file(Path(__file__).resolve()):
        raise RuntimeError(
            "run_experiment.py changed after the run was created. Start a new run instead of mixing code versions."
        )
    return config


def stage_prepare_pilot(
    repo_root: Path,
    run_dir: Path,
    config: dict[str, Any],
    logger: logging.Logger,
    *,
    validation_timeout: int,
) -> tuple[list[dict[str, Any]], dict[str, Any], dict[str, Any]]:
    extraction = extract_all_pairs(repo_root, run_dir, logger)
    validation = validate_pairs(repo_root, run_dir, extraction.samples, logger, validation_timeout)
    if not validation["all_reference_controls_valid"]:
        invalid = [task for task, row in validation["tasks"].items() if not row["valid"]]
        raise RuntimeError(
            "Reference validation failed. Do not continue to TDA. Invalid pairs: " + ", ".join(invalid)
        )
    samples = read_json(run_dir / "dataset" / "dataset_manifest.json")
    emb = config["embedding"]
    cloud_cfg = config["point_cloud"]
    generate_all_embeddings(
        run_dir,
        samples,
        model_path=emb["model_path"],
        device=emb["device"],
        max_tokens=int(emb["max_tokens"]),
        overlap_tokens=int(emb["overlap_tokens"]),
        points_per_sample=int(cloud_cfg["points_per_sample"]),
        window_tokens=int(cloud_cfg["window_tokens"]),
        allow_download=bool(emb.get("allow_download", False)),
        logger=logger,
    )
    topo = config["topology"]
    pilot = pilot_topology(
        run_dir,
        samples,
        maxdim=int(topo["maxdim"]),
        min_persistence_abs=float(topo["minimum_persistence_absolute"]),
        min_persistence_fraction=float(topo["minimum_persistence_fraction"]),
        significant_viability_threshold=float(topo["pilot_h1_significant_viability_threshold"]),
        logger=logger,
    )
    write_source_length_manifest(run_dir, samples, logger)
    build_share_bundle(run_dir, logger, pilot_only=True)
    return samples, validation, pilot


def stage_analyze(
    run_dir: Path,
    config: dict[str, Any],
    logger: logging.Logger,
) -> dict[str, Any]:
    samples_path = run_dir / "dataset" / "dataset_manifest.json"
    validation_path = run_dir / "validation" / "validation_summary.json"
    pilot_path = run_dir / "pilot" / "pilot_report.json"
    if not samples_path.is_file() or not validation_path.is_file() or not pilot_path.is_file():
        raise RuntimeError("This run has not completed the prepare-pilot stage")
    samples = read_json(samples_path)
    validation = read_json(validation_path)
    pilot = read_json(pilot_path)
    if not validation.get("all_reference_controls_valid"):
        raise RuntimeError("Cannot analyze an invalid reference-control dataset")
    if not pilot.get("h1_viable_for_primary_interpretation"):
        raise RuntimeError(
            "The persistence-filtered H1 pilot viability criterion was not satisfied. "
            "Do not continue the prespecified H1 analysis with this representation."
        )

    topo = config["topology"]
    stats_cfg = config["statistics"]
    metrics, diagrams, epsilon_grid = compute_all_topology(
        run_dir,
        samples,
        maxdim=int(topo["maxdim"]),
        min_persistence_abs=float(topo["minimum_persistence_absolute"]),
        min_persistence_fraction=float(topo["minimum_persistence_fraction"]),
        betti_grid_points=int(topo["betti_grid_points"]),
        logger=logger,
    )
    paired_diagram_distances(
        run_dir,
        samples,
        diagrams,
        maxdim=int(topo["maxdim"]),
        logger=logger,
    )
    group_top = group_level_topology(
        run_dir,
        samples,
        maxdim=int(topo["maxdim"]),
        min_persistence_abs=float(topo["minimum_persistence_absolute"]),
        min_persistence_fraction=float(topo["minimum_persistence_fraction"]),
        logger=logger,
    )
    scalar_tests = scalar_statistics(
        run_dir,
        metrics,
        permutations=int(stats_cfg["paired_permutations"]),
        bootstrap_resamples=int(stats_cfg["bootstrap_resamples"]),
        seed=int(stats_cfg["random_seed"]),
        logger=logger,
    )
    confound_analysis = length_complexity_confound_analysis(
        run_dir,
        metrics,
        permutations=int(stats_cfg["paired_permutations"]),
        bootstrap_resamples=int(stats_cfg["bootstrap_resamples"]),
        seed=int(stats_cfg["random_seed"]),
        logger=logger,
    )
    betti_tests = betti_global_tests(
        run_dir,
        metrics,
        diagrams,
        epsilon_grid,
        maxdim=int(topo["maxdim"]),
        permutations=int(stats_cfg["paired_permutations"]),
        seed=int(stats_cfg["random_seed"]),
        logger=logger,
    )
    group_tests = group_level_permutation_test(
        run_dir,
        samples,
        maxdim=int(topo["maxdim"]),
        permutations=int(stats_cfg["group_level_tda_permutations"]),
        seed=int(stats_cfg["random_seed"]),
        logger=logger,
    )
    classification = exploratory_classifier(
        run_dir,
        metrics,
        seed=int(stats_cfg["random_seed"]),
        permutations=int(stats_cfg["classifier_permutations"]),
        logger=logger,
    )
    make_figures(
        run_dir,
        metrics,
        diagrams,
        epsilon_grid,
        maxdim=int(topo["maxdim"]),
        logger=logger,
    )
    summary = summarize_results(
        run_dir,
        validation,
        pilot,
        scalar_tests,
        betti_tests,
        group_tests,
        classification,
        group_top,
        confound_analysis,
        logger,
    )
    bundle = build_share_bundle(run_dir, logger, pilot_only=False)
    summary["share_bundle"] = str(bundle.resolve())
    write_json(run_dir / "reports" / "analysis_summary.json", summary)
    return summary


def print_run_instructions(run_dir: Path, stage: str) -> None:
    print("\n" + "=" * 78)
    print("RUN DIRECTORY:", run_dir)
    if stage in {"pilot", "all"}:
        pilot_bundle = run_dir / "pilot_results_to_share.zip"
        if pilot_bundle.is_file():
            print("PILOT BUNDLE TO UPLOAD:", pilot_bundle)
    final_bundle = run_dir / "results_to_share.zip"
    if final_bundle.is_file():
        print("FINAL BUNDLE TO UPLOAD:", final_bundle)
    print("=" * 78 + "\n")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=(
            "Independent matched-pair TDA experiment over all 20 Python/Flask CWEval secure/unsafe controls. "
            "Writes only under tda_statistical_experiment/runs/."
        )
    )
    parser.add_argument(
        "--stage",
        choices=["pilot", "analyze", "all"],
        default="pilot",
        help=(
            "pilot: extract, validate, embed, and run the five-CWE topology pilot; "
            "analyze: continue an existing pilot run through all statistics; "
            "all: execute both stages in one run."
        ),
    )
    parser.add_argument("--run-dir", type=Path, help="Existing run directory required for --stage analyze")
    parser.add_argument("--config", type=Path, default=SCRIPT_DIR / "config.json")
    parser.add_argument("--model-path", help="Override config model path, e.g. $HOME/models/codebert-base")
    parser.add_argument("--device", choices=["auto", "cpu", "cuda"], help="Override embedding device")
    parser.add_argument("--validation-timeout", type=int, default=900)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    if args.stage == "analyze":
        if args.run_dir is None:
            raise SystemExit("--run-dir is required for --stage analyze")
        run_dir = args.run_dir.expanduser().resolve()
        config = load_existing_run_config(run_dir)
        logger = setup_logging(run_dir)
        logger.info("Continuing frozen run at analysis stage: %s", run_dir)
        stage_analyze(run_dir, config, logger)
        print_run_instructions(run_dir, args.stage)
        return 0

    run_dir = create_run_dir(SCRIPT_DIR)
    logger = setup_logging(run_dir)
    config = copy_and_freeze_config(
        args.config.resolve(),
        run_dir,
        {"model_path": args.model_path, "device": args.device},
    )
    logger.info("Created independent TDA statistical run: %s", run_dir)
    logger.info("Original project artifacts will not be modified")
    try:
        stage_prepare_pilot(
            PROJECT_ROOT,
            run_dir,
            config,
            logger,
            validation_timeout=args.validation_timeout,
        )
        if args.stage == "all":
            stage_analyze(run_dir, config, logger)
    except Exception as exc:
        logger.error("Experiment failed: %s", exc)
        logger.error(traceback.format_exc())
        write_json(
            run_dir / "failure.json",
            {
                "created_at_utc": utc_now(),
                "error_type": type(exc).__name__,
                "error": str(exc),
                "traceback": traceback.format_exc(),
            },
        )
        print_run_instructions(run_dir, args.stage)
        return 2

    print_run_instructions(run_dir, args.stage)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
