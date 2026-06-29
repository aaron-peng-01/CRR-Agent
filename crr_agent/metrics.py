from __future__ import annotations

from collections import Counter, defaultdict
from statistics import mean

from .types import AdjudicationReport, Verdict


def summarize_reports(reports: list[AdjudicationReport]) -> dict:
    if not reports:
        return {}

    correct = [r.verdict == r.expected_verdict for r in reports]
    unauthorized_expected = [r for r in reports if r.expected_verdict == Verdict.UNAUTHORIZED]
    authorized_expected = [r for r in reports if r.expected_verdict == Verdict.AUTHORIZED]
    unauthorized_detected = [r.verdict == Verdict.UNAUTHORIZED for r in unauthorized_expected]
    false_accusations = [r.verdict == Verdict.UNAUTHORIZED for r in authorized_expected]

    by_claim: dict[str, list[AdjudicationReport]] = defaultdict(list)
    for report in reports:
        by_claim[report.claim.value].append(report)

    return {
        "count": len(reports),
        "dispute_adjudication_accuracy": mean(correct),
        "unauthorized_action_detection_rate": mean(unauthorized_detected) if unauthorized_detected else 0.0,
        "false_accusation_rate": mean(false_accusations) if false_accusations else 0.0,
        "partial_replay_fidelity": mean(r.replay.replay_fidelity for r in reports),
        "privacy_leakage_surface": mean(r.subgraph.leakage for r in reports),
        "opened_node_ratio": mean(len(r.subgraph.opened_node_ids) / max(1, len(r.subgraph.node_ids)) for r in reports),
        "latency_overhead_ms": mean(r.replay.latency_ms for r in reports),
        "receipt_verification_time_ms": mean(r.replay.receipt_verification_time_ms for r in reports),
        "policy_replay_time_ms": mean(r.replay.policy_replay_time_ms for r in reports),
        "node_open_time_ms": mean(r.replay.node_open_time_ms for r in reports),
        "side_effect_rollback_success_rate": mean(r.replay.rollback_success for r in reports),
        "verdict_counts": dict(Counter(r.verdict.value for r in reports)),
        "by_claim_accuracy": {
            claim: mean(r.verdict == r.expected_verdict for r in claim_reports)
            for claim, claim_reports in sorted(by_claim.items())
        },
    }


def estimate_storage_overhead(reports: list[AdjudicationReport], cost_model: dict) -> float:
    receipt_bytes = float(cost_model.get("storage_bytes_per_receipt", 640))
    node_bytes = float(cost_model.get("storage_bytes_per_node", 512))
    return mean((len(r.subgraph.node_ids) * node_bytes) + receipt_bytes for r in reports) if reports else 0.0
