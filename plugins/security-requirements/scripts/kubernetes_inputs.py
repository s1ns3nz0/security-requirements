#!/usr/bin/env python3
"""Produce a normalized Kubernetes graph from declarative deployment inputs.

Helm and Kustomize are rendered with their own CLIs when requested. Terraform
plan JSON is converted without contacting Terraform or a Kubernetes cluster.
All generated graphs retain the selected source mode for review and evidence.
"""

from __future__ import annotations

import argparse
import json
import shutil
import subprocess
import tempfile
from pathlib import Path
from typing import Any

import yaml

import kubernetes_graph


def _run(command: list[str], cwd: Path | None = None) -> str:
    try:
        result = subprocess.run(command, cwd=cwd, check=True, capture_output=True, text=True)
    except FileNotFoundError as exc:
        raise RuntimeError(f"required renderer is not installed: {command[0]}") from exc
    except subprocess.CalledProcessError as exc:
        raise RuntimeError(f"renderer failed: {' '.join(command)}\n{exc.stderr.strip()}") from exc
    return result.stdout


def _terraform_resources(value: dict[str, Any]) -> list[dict[str, Any]]:
    result: list[dict[str, Any]] = []

    def visit(module: dict[str, Any]) -> None:
        for resource in module.get("resources", []) or []:
            rtype = resource.get("type", "")
            values = resource.get("values") or {}
            if not rtype.startswith("kubernetes_"):
                continue
            if rtype == "kubernetes_manifest" and isinstance(values.get("manifest"), dict):
                result.append(values["manifest"])
                continue
            kind = rtype.removeprefix("kubernetes_").replace("_", " ").title().replace(" ", "")
            metadata = values.get("metadata")
            if isinstance(metadata, list):
                metadata = metadata[0] if metadata else {}
            if not isinstance(metadata, dict):
                metadata = {}
            obj = {"apiVersion": "v1", "kind": kind, "metadata": metadata}
            for key in ("spec", "data", "type", "stringData"):
                if key in values:
                    obj[key] = values[key]
            result.append(obj)
        for child in module.get("child_modules", []) or []:
            visit(child)

    root = value.get("planned_values", {}).get("root_module", {})
    if isinstance(root, dict):
        visit(root)
    return result


def build(args: argparse.Namespace) -> dict[str, Any]:
    source_mode = "manifest"
    source_files: list[str] = []
    with tempfile.TemporaryDirectory(prefix="k8s-input-") as temporary:
        temp = Path(temporary) / "rendered.yaml"
        if args.input:
            graph = kubernetes_graph.build(args.input)
            source_mode = "manifest"
            source_files = [str(args.input)]
        elif args.helm_chart:
            if not shutil.which("helm"):
                raise RuntimeError("--helm-chart requires helm on PATH")
            command = ["helm", "template", args.release_name, str(args.helm_chart)]
            for values in args.values:
                command.extend(["--values", str(values)])
            temp.write_text(_run(command), encoding="utf-8")
            graph = kubernetes_graph.build(temp)
            source_mode = "helm_rendered"
            source_files = [str(args.helm_chart), *[str(v) for v in args.values]]
        elif args.kustomize_dir:
            renderer = "kustomize" if shutil.which("kustomize") else "kubectl"
            command = [renderer, "build", str(args.kustomize_dir)] if renderer == "kustomize" else [renderer, "kustomize", str(args.kustomize_dir)]
            temp.write_text(_run(command), encoding="utf-8")
            graph = kubernetes_graph.build(temp)
            source_mode = "kustomize_rendered"
            source_files = [str(args.kustomize_dir)]
        elif args.terraform_plan:
            plan = json.loads(args.terraform_plan.read_text(encoding="utf-8"))
            manifests = _terraform_resources(plan)
            temp.write_text("\n---\n".join(yaml.safe_dump(item, sort_keys=False) for item in manifests), encoding="utf-8")
            graph = kubernetes_graph.build(temp)
            source_mode = "terraform_plan"
            source_files = [str(args.terraform_plan)]
        else:
            raise RuntimeError("one of --input, --helm-chart, --kustomize-dir, or --terraform-plan is required")
    graph["input_provenance"] = {"mode": source_mode, "sources": source_files,
                                 "rendered": source_mode != "manifest"}
    return graph


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--input", type=Path)
    group.add_argument("--helm-chart", type=Path)
    group.add_argument("--kustomize-dir", type=Path)
    group.add_argument("--terraform-plan", type=Path)
    parser.add_argument("--release-name", default="security-review")
    parser.add_argument("--values", type=Path, action="append", default=[])
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args(argv)
    result = build(args)
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(yaml.safe_dump(result, sort_keys=False, allow_unicode=True), encoding="utf-8")
    print(f"wrote {args.out} ({result['input_provenance']['mode']})")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
