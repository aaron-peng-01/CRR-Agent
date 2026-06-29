# CRR-Agent_repo

This directory is the slim code repository for CRR-Agent. It is intentionally narrower than the full research workspace.

Included:

- `crr_agent/`: core implementation.
- `experiments/`: experiment entry points.
- `configs/`: minimal runtime configuration.
- `scripts/run_all.ps1`, `scripts/run_all.sh`: lightweight launch helpers.
- `tests/`: focused code checks.
- `pyproject.toml`, `requirements.txt`: packaging and dependency metadata.

Excluded on purpose:

- datasets and downloaded raw files
- `paper_springer_blind/` and other manuscript assets
- `outputs/` and all generated result files
- `docs/`, `plan*`, analysis, audit, and other agent-produced process files

This repo is meant to publish the implementation cleanly. Data and experiment outputs should be created locally after cloning and should remain untracked.

## Quick start

Install dependencies:

```powershell
python -m pip install -r requirements.txt
```

Run tests:

```powershell
python -m pytest tests
```

Run the pipeline helper:

```powershell
.\scripts\run_all.ps1 -Config configs/default.json -OutDir outputs
```

## Notes

- The real-data experiment code expects official BPI files to be prepared locally by the user.
- Output directories such as `outputs/` are intentionally ignored in this slim repo.
