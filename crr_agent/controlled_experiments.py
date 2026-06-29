from __future__ import annotations

import itertools
import time
from collections import defaultdict
from copy import deepcopy
from dataclasses import replace
from statistics import mean, median
from typing import Callable

from .adjudicator import CRRAdjudicator
from .baselines import build_baseline
from .crypto import HMACSigner
from .metrics import summarize_reports
from .receipts import ReceiptInstrumentor
from .scenarios import ScenarioGenerator
from .selector import MinimalReplaySelector
from .types import BenchmarkCase, NodeType, ReplaySubgraph, Verdict, WorkflowEdge, WorkflowTrace


TAMPER_TYPES = [
    "payload_digest",
    "actor",
    "predecessor",
    "delegation_scope",
    "policy_version",
    "missing_receipt",
    "deleted_node",
    "reordered_edge",
]


NATIVE_AGENT_METHODS = [
    "signed_receipts",
    "agent_sentry_bounds",
    "full_replay_oracle",
    "crr_agent",
]


def make_adjudicator(config: dict) -> CRRAdjudicator:
    instrumentor = ReceiptInstrumentor(HMACSigner("crr-agent-experiment-key"))
    return CRRAdjudicator.from_config(config, instrumentor)


def run_native_agent_workflow(config: dict, cases_per_scenario: int = 250) -> dict:
    cases = _balanced_native_cases(config, cases_per_scenario)
    adjudicator = make_adjudicator(config)
    output = {
        "evidence_tier": "S",
        "role": "controlled native agent workflow experiment",
        "cases": len(cases),
        "cases_per_scenario": cases_per_scenario,
        "scenario_count": len({case.scenario for case in cases}),
        "methods": {},
    }
    for method in NATIVE_AGENT_METHODS:
        baseline = build_baseline(method)
        reports = [baseline.adjudicate(case, adjudicator) for case in cases]
        summary = summarize_reports(reports)
        summary["weighted_disclosure_score"] = summary.pop("privacy_leakage_surface")
        summary["scenario_accuracy"] = _scenario_accuracy(cases, reports)
        output["methods"][method] = {
            "summary": summary,
            "sample_reports": [report.to_dict() for report in reports[:10]],
        }
    return output


def run_tamper_fault_injection(config: dict, cases_per_tamper: int = 200) -> dict:
    base_cases = _authorized_cases(config, cases_per_tamper)
    methods = ["signed_receipts", "agent_sentry_bounds", "full_replay_oracle", "crr_agent"]
    adjudicator = make_adjudicator(config)
    rows = []
    samples = []

    for tamper_type in TAMPER_TYPES:
        tampered_cases = [_tamper_case(case, tamper_type) for case in base_cases]
        for method in methods:
            baseline = build_baseline(method)
            reports = [baseline.adjudicate(case, adjudicator) for case in tampered_cases]
            detected = [report.verdict != Verdict.AUTHORIZED for report in reports]
            false_accept = [report.verdict == Verdict.AUTHORIZED for report in reports]
            ambiguous = [report.verdict == Verdict.AMBIGUOUS for report in reports]
            unauthorized = [report.verdict == Verdict.UNAUTHORIZED for report in reports]
            rows.append(
                {
                    "tamper_type": tamper_type,
                    "method": method,
                    "n": len(reports),
                    "detection_rate": mean(detected),
                    "false_accept_rate": mean(false_accept),
                    "ambiguous_rate": mean(ambiguous),
                    "unauthorized_rate": mean(unauthorized),
                    "weighted_disclosure_score": mean(report.subgraph.leakage for report in reports),
                    "opened_nodes": mean(len(report.subgraph.opened_node_ids) for report in reports),
                }
            )
            samples.extend(
                {
                    "tamper_type": tamper_type,
                    "method": method,
                    "case_id": case.case_id,
                    "verdict": report.verdict.value,
                    "reasons": report.replay.reasons,
                }
                for case, report in zip(tampered_cases[:3], reports[:3])
            )

    return {
        "evidence_tier": "S",
        "role": "controlled fault injection over signed native agent traces",
        "cases_per_tamper": cases_per_tamper,
        "tamper_types": TAMPER_TYPES,
        "rows": rows,
        "sample_decisions": samples,
        "method_summary": _method_summary(rows),
    }


def run_selector_analysis(config: dict, num_cases: int = 250) -> dict:
    cases = ScenarioGenerator({**config, "num_cases": num_cases}).generate(num_cases)
    adjudicator = make_adjudicator(config)
    heuristic_rows = []
    optimal_rows = []
    runtime_rows = []

    for case in cases:
        t0 = time.perf_counter()
        report = adjudicator.adjudicate(case.trace, case.dispute, mode="minimal")
        elapsed_ms = (time.perf_counter() - t0) * 1000.0
        runtime_rows.append(
            {
                "case_id": case.case_id,
                "scenario": case.scenario,
                "node_count": len(case.trace.nodes),
                "opened_nodes": len(report.subgraph.opened_node_ids),
                "runtime_ms": elapsed_ms,
            }
        )
        heuristic_rows.append(
            {
                "case_id": case.case_id,
                "scenario": case.scenario,
                "objective": _objective(config, report.subgraph),
                "opened_nodes": len(report.subgraph.opened_node_ids),
                "weighted_disclosure_score": report.subgraph.leakage,
            }
        )
        if len(case.trace.nodes) <= 12:
            optimal = _exact_opening_search(config, adjudicator, case)
            optimal_rows.append(
                {
                    "case_id": case.case_id,
                    "scenario": case.scenario,
                    "optimal_objective": optimal["objective"],
                    "heuristic_objective": heuristic_rows[-1]["objective"],
                    "optimal_opened_nodes": optimal["opened_nodes"],
                    "heuristic_opened_nodes": heuristic_rows[-1]["opened_nodes"],
                    "objective_gap_pct": _pct_gap(heuristic_rows[-1]["objective"], optimal["objective"]),
                }
            )

    sensitivity = []
    for depth in [4, 8, 12, 16, None]:
        for leak_weight in [1.0, 2.0, 4.0, 8.0]:
            swept = deepcopy(config)
            selector = dict(swept.get("selector", {}))
            selector["ancestor_depth"] = 99 if depth is None else depth
            selector["lambda_leak"] = leak_weight
            swept["selector"] = selector
            runner = make_adjudicator(swept)
            reports = [runner.adjudicate(case.trace, case.dispute, mode="minimal") for case in cases]
            summary = summarize_reports(reports)
            sensitivity.append(
                {
                    "depth": "inf" if depth is None else depth,
                    "lambda_leak": leak_weight,
                    "agreement": summary["dispute_adjudication_accuracy"],
                    "ambiguous_rate": summary["verdict_counts"].get("ambiguous", 0) / len(reports),
                    "opened_nodes": mean(len(report.subgraph.opened_node_ids) for report in reports),
                    "weighted_disclosure_score": summary["privacy_leakage_surface"],
                }
            )

    runtime_values = [row["runtime_ms"] for row in runtime_rows]
    return {
        "evidence_tier": "S",
        "role": "selector optimality, sensitivity, and wall-clock analysis",
        "num_cases": num_cases,
        "optimality": {
            "eligible_cases": len(optimal_rows),
            "mean_gap_pct": mean(row["objective_gap_pct"] for row in optimal_rows) if optimal_rows else 0.0,
            "p95_gap_pct": _percentile([row["objective_gap_pct"] for row in optimal_rows], 0.95),
            "rows": optimal_rows[:25],
        },
        "sensitivity": sensitivity,
        "wall_clock_ms": {
            "p50": median(runtime_values),
            "p95": _percentile(runtime_values, 0.95),
            "p99": _percentile(runtime_values, 0.99),
            "mean": mean(runtime_values),
        },
        "runtime_rows": runtime_rows[:50],
    }


def _balanced_native_cases(config: dict, cases_per_scenario: int) -> list[BenchmarkCase]:
    cases: list[BenchmarkCase] = []
    seed = int(config.get("seed", 42))
    for scenario in ["procurement", "finance", "email_support", "data_access", "multi_agent"]:
        scenario_config = deepcopy(config)
        scenario_config["seed"] = seed + len(cases)
        scenario_config["scenario_mix"] = {scenario: 1.0}
        scenario_config["num_cases"] = cases_per_scenario
        cases.extend(ScenarioGenerator(scenario_config).generate(cases_per_scenario))
    return cases


def _authorized_cases(config: dict, count: int) -> list[BenchmarkCase]:
    tamper_config = deepcopy(config)
    tamper_config["scenario_mix"] = {
        "procurement": 0.2,
        "finance": 0.2,
        "email_support": 0.2,
        "data_access": 0.2,
        "multi_agent": 0.2,
    }
    tamper_config["attack_mix"] = {"benign": 1.0}
    tamper_config["num_cases"] = count
    return ScenarioGenerator(tamper_config).generate(count)


def _tamper_case(case: BenchmarkCase, tamper_type: str) -> BenchmarkCase:
    trace = deepcopy(case.trace)
    action_id = next(node_id for node_id, node in trace.nodes.items() if node.node_type == NodeType.ACTION)
    action = trace.nodes[action_id]
    receipt = trace.receipts.get(action_id)

    if tamper_type == "payload_digest":
        trace.nodes[action_id] = replace(action, payload={**action.payload, "amount": float(action.payload.get("amount", 0)) + 10000})
    elif tamper_type == "actor":
        trace.nodes[action_id] = replace(action, actor="unauthorized_agent")
    elif tamper_type == "predecessor" and receipt is not None:
        trace.receipts[action_id] = replace(receipt, predecessor_hash="tampered-predecessor-hash")
    elif tamper_type == "delegation_scope":
        delegation_id = next(node_id for node_id, node in trace.nodes.items() if node.node_type == NodeType.DELEGATION)
        delegation = trace.nodes[delegation_id]
        trace.nodes[delegation_id] = replace(delegation, payload={**delegation.payload, "allowed_scopes": []})
    elif tamper_type == "policy_version":
        decision = trace.policy_decisions[action_id]
        trace.policy_decisions[action_id] = replace(decision, policy_version="policy-v0-tampered")
    elif tamper_type == "missing_receipt":
        trace.receipts.pop(action_id, None)
    elif tamper_type == "deleted_node":
        prompt_id = next(node_id for node_id, node in trace.nodes.items() if node.node_type == NodeType.PROMPT)
        trace.nodes.pop(prompt_id, None)
        trace.edges = [edge for edge in trace.edges if edge.source != prompt_id and edge.target != prompt_id]
    elif tamper_type == "reordered_edge":
        trace.edges = _tamper_edges(trace.edges, action_id)
    else:
        raise ValueError(f"unknown tamper type: {tamper_type}")

    trace.metadata = {**trace.metadata, "tamper_type": tamper_type}
    dispute = replace(case.dispute, expected_verdict=Verdict.UNAUTHORIZED)
    return replace(case, case_id=f"{case.case_id}:{tamper_type}", trace=trace, dispute=dispute)


def _tamper_edges(edges: list[WorkflowEdge], action_id: str) -> list[WorkflowEdge]:
    edited = []
    for edge in edges:
        if edge.target == action_id and edge.relation == "authorizes":
            continue
        else:
            edited.append(edge)
    return edited


def _scenario_accuracy(cases: list[BenchmarkCase], reports) -> dict[str, float]:
    buckets: dict[str, list[bool]] = defaultdict(list)
    for case, report in zip(cases, reports):
        buckets[case.scenario].append(report.verdict == report.expected_verdict)
    return {scenario: mean(values) for scenario, values in sorted(buckets.items())}


def _method_summary(rows: list[dict]) -> dict[str, dict]:
    buckets: dict[str, list[dict]] = defaultdict(list)
    for row in rows:
        buckets[row["method"]].append(row)
    return {
        method: {
            "mean_detection_rate": mean(row["detection_rate"] for row in method_rows),
            "mean_false_accept_rate": mean(row["false_accept_rate"] for row in method_rows),
            "mean_ambiguous_rate": mean(row["ambiguous_rate"] for row in method_rows),
            "mean_weighted_disclosure_score": mean(row["weighted_disclosure_score"] for row in method_rows),
        }
        for method, method_rows in sorted(buckets.items())
    }


def _exact_opening_search(config: dict, adjudicator: CRRAdjudicator, case: BenchmarkCase) -> dict:
    selector = MinimalReplaySelector(config.get("selector", {}), config.get("cost_model", {}))
    base = selector.select(case.trace, case.dispute.side_effect_id, mode="minimal")
    required = {
        node_id
        for node_id in base.node_ids
        if case.trace.nodes[node_id].node_type in {NodeType.ACTION, NodeType.SIDE_EFFECT, NodeType.POLICY}
    }
    optional = sorted(base.node_ids - required)
    best = None
    for size in range(len(optional) + 1):
        for subset in itertools.combinations(optional, size):
            opened = required | set(subset)
            subgraph = _score_opening(config, case.trace, base.node_ids, opened)
            replay = adjudicator.replay_engine.replay(case.trace, subgraph, case.dispute.side_effect_id)
            verdict = _verdict_from_replay(replay)
            if verdict != case.dispute.expected_verdict:
                continue
            objective = _objective(config, subgraph)
            if best is None or objective < best["objective"]:
                best = {
                    "objective": objective,
                    "opened_nodes": len(opened),
                    "weighted_disclosure_score": subgraph.leakage,
                }
    return best or {
        "objective": _objective(config, base),
        "opened_nodes": len(base.opened_node_ids),
        "weighted_disclosure_score": base.leakage,
    }


def _score_opening(config: dict, trace: WorkflowTrace, node_ids: set[str], opened: set[str]) -> ReplaySubgraph:
    cost_model = config.get("cost_model", {})
    opened_ids = set(opened)
    commitment_only = set(node_ids) - opened_ids
    leakage = sum(trace.nodes[nid].sensitivity for nid in opened_ids)
    estimated_time_ms = (
        len(opened_ids) * float(cost_model.get("node_open_ms", 0.8))
        + len([nid for nid in node_ids if nid in trace.receipts]) * float(cost_model.get("receipt_verify_ms", 0.25))
        + len([nid for nid in node_ids if nid in trace.policy_decisions]) * float(cost_model.get("policy_replay_ms", 1.5))
    )
    return ReplaySubgraph(
        node_ids=set(node_ids),
        opened_node_ids=opened_ids,
        commitment_only_node_ids=commitment_only,
        cost=len(node_ids) + len(opened_ids) * 0.5,
        leakage=leakage,
        estimated_time_ms=estimated_time_ms,
    )


def _verdict_from_replay(replay) -> Verdict:
    if replay.verified and replay.side_effect_matches and replay.policy_verdict == Verdict.AUTHORIZED:
        return Verdict.AUTHORIZED
    if replay.verified and replay.policy_verdict == Verdict.UNAUTHORIZED:
        return Verdict.UNAUTHORIZED
    return Verdict.AMBIGUOUS


def _objective(config: dict, subgraph: ReplaySubgraph) -> float:
    selector = config.get("selector", {})
    return (
        float(selector.get("lambda_cost", 1.0)) * subgraph.cost
        + float(selector.get("lambda_leak", 4.0)) * subgraph.leakage
        + float(selector.get("lambda_time", 0.5)) * subgraph.estimated_time_ms
    )


def _pct_gap(heuristic: float, optimal: float) -> float:
    if optimal == 0:
        return 0.0
    return max(0.0, (heuristic - optimal) / optimal * 100.0)


def _percentile(values: list[float], q: float) -> float:
    if not values:
        return 0.0
    ordered = sorted(values)
    idx = min(len(ordered) - 1, max(0, int(round((len(ordered) - 1) * q))))
    return ordered[idx]
