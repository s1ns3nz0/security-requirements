#!/usr/bin/env python3
"""Inspect Kubernetes image provenance and CI-to-cluster deployment paths."""

from __future__ import annotations

import argparse
import json
import re
from pathlib import Path
from typing import Any

import yaml

import kubernetes_graph


def _containers(obj: dict[str, Any]) -> list[dict[str, Any]]:
    spec = kubernetes_graph._pod_template(obj)
    return (spec.get("containers", []) or []) + (spec.get("initContainers", []) or [])


def analyze(path: Path) -> dict[str, Any]:
    docs, notes = kubernetes_graph._load(path)
    findings: list[dict[str, Any]] = []
    images: list[dict[str, Any]] = []
    for obj in docs:
        if obj.get("kind") not in kubernetes_graph.WORKLOADS:
            continue
        for container in _containers(obj):
            image = str(container.get("image", ""))
            record = {"resource": kubernetes_graph._id(obj["kind"], kubernetes_graph._namespace(obj), kubernetes_graph._name(obj)),
                      "container": container.get("name"), "image": image}
            images.append(record)
            if not image or ":latest" in image or ("@sha256:" not in image and ":" not in image.rsplit("/", 1)[-1]):
                findings.append({"type": "benchmark_check", "severity": "medium",
                                 "reason": "mutable_or_unpinned_image", **record})
    for filename in kubernetes_graph._files(path):
        if filename.suffix not in {".yml", ".yaml", ".json"} and ".github" not in filename.parts:
            continue
        try:
            text = filename.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue
        if re.search(r"\bkubectl\s+(apply|patch|create)\b", text) or re.search(r"helm\s+upgrade", text):
            findings.append({"type": "design_derived", "severity": "high",
                             "reason": "ci_deploys_to_cluster", "evidence": str(filename)})
        if "docker build" in text and "--provenance" not in text:
            findings.append({"type": "coverage_gap", "severity": "medium",
                             "reason": "image_provenance_not_declared", "evidence": str(filename)})
    return {"version": "1", "mode": "kubernetes_supply_chain_analysis",
            "images": images, "findings": findings, "parse_notes": notes,
            "review_required": bool(findings)}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input", type=Path, required=True)
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args(argv)
    result = analyze(args.input)
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(result, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    print(f"wrote {args.out} ({len(result['images'])} images)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
