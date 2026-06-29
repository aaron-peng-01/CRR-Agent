from __future__ import annotations

from .ablations import ablation_mode, apply_ablation
from .adjudicator import CRRAdjudicator
from .baselines import build_baseline
from .crypto import HMACSigner
from .metrics import estimate_storage_overhead, summarize_reports
from .receipts import ReceiptInstrumentor
from .types import AdjudicationReport, BenchmarkCase


class ExperimentRunner:
    def __init__(self, config: dict):
        self.config = config
        self.instrumentor = ReceiptInstrumentor(HMACSigner("crr-agent-experiment-key"))
        self.adjudicator = CRRAdjudicator.from_config(config, self.instrumentor)

    def run_baseline(self, cases: list[BenchmarkCase], baseline_name: str) -> dict:
        baseline = build_baseline(baseline_name)
        reports = [baseline.adjudicate(case, self.adjudicator) for case in cases]
        return self._package_result(baseline.name, reports)

    def run_all_baselines(self, cases: list[BenchmarkCase]) -> dict:
        return {
            name: self.run_baseline(cases, name)
            for name in self.config.get("baselines", [])
        }

    def run_ablation(self, cases: list[BenchmarkCase], ablation_name: str) -> dict:
        reports: list[AdjudicationReport] = []
        for case in cases:
            trace = apply_ablation(case.trace, ablation_name)
            report = self.adjudicator.adjudicate(trace, case.dispute, mode=ablation_mode(ablation_name))
            reports.append(report)
        return self._package_result(ablation_name, reports)

    def run_all_ablations(self, cases: list[BenchmarkCase]) -> dict:
        return {
            name: self.run_ablation(cases, name)
            for name in self.config.get("ablations", [])
        }

    def _package_result(self, name: str, reports: list[AdjudicationReport]) -> dict:
        summary = summarize_reports(reports)
        summary["storage_overhead_bytes"] = estimate_storage_overhead(reports, self.config.get("cost_model", {}))
        return {
            "name": name,
            "summary": summary,
            "reports": [report.to_dict() for report in reports],
        }
