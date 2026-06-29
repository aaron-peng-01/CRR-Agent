from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path

import _bootstrap  # noqa: F401

from crr_agent.real_data import audit_xes, load_dataset_manifest


def main() -> None:
    parser = argparse.ArgumentParser(description="Audit real XES schemas and verify source files.")
    parser.add_argument("--manifest", default="data/manifests/datasets.json")
    parser.add_argument("--dataset", action="append", default=[])
    parser.add_argument("--max-cases", type=int, default=None)
    parser.add_argument("--out-dir", default="outputs/raw/audit")
    args = parser.parse_args()

    manifest = load_dataset_manifest(args.manifest)
    selected = args.dataset or list(manifest)
    out_dir = Path(args.out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    for dataset_id in selected:
        entry = manifest[dataset_id]
        path = Path(entry["file"])
        if not path.exists():
            raise FileNotFoundError(path)
        if _md5(path) != entry["md5"]:
            raise RuntimeError(f"MD5 mismatch: {path}")
        result = audit_xes(path, dataset_id, args.max_cases)
        result["source"] = entry
        target = out_dir / f"{dataset_id}_schema.json"
        target.write_text(json.dumps(result, indent=2), encoding="utf-8")
        print(f"audited {dataset_id}: {result['cases']} cases, {result['events']} events")


def _md5(path: Path) -> str:
    value = hashlib.md5()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(8 * 1024 * 1024), b""):
            value.update(chunk)
    return value.hexdigest()


if __name__ == "__main__":
    main()
