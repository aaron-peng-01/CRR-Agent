from __future__ import annotations

from .types import (
    ActionReceipt,
    BenchmarkCase,
    ClaimType,
    Dispute,
    NodeType,
    PolicyDecision,
    Verdict,
    WorkflowEdge,
    WorkflowNode,
    WorkflowTrace,
)


def case_from_dict(data: dict) -> BenchmarkCase:
    trace_data = data["trace"]
    trace = WorkflowTrace(
        trace_id=trace_data["trace_id"],
        nodes={
            node_id: WorkflowNode(
                node_id=node["node_id"],
                node_type=NodeType(node["node_type"]),
                actor=node["actor"],
                label=node["label"],
                payload=node["payload"],
                sensitivity=node.get("sensitivity", 0.0),
                deterministic=node.get("deterministic", True),
                revealable=node.get("revealable", True),
            )
            for node_id, node in trace_data["nodes"].items()
        },
        edges=[
            WorkflowEdge(source=edge["source"], target=edge["target"], relation=edge["relation"])
            for edge in trace_data.get("edges", [])
        ],
        receipts={
            action_id: ActionReceipt(
                receipt_id=receipt["receipt_id"],
                action_id=receipt["action_id"],
                actor=receipt["actor"],
                authority_hash=receipt["authority_hash"],
                instruction_hash=receipt["instruction_hash"],
                payload_digest=receipt["payload_digest"],
                predecessor_hash=receipt["predecessor_hash"],
                policy_digest=receipt["policy_digest"],
                issued_at=receipt["issued_at"],
                signature=receipt["signature"],
            )
            for action_id, receipt in trace_data.get("receipts", {}).items()
        },
        policy_decisions={
            action_id: PolicyDecision(
                decision_id=decision["decision_id"],
                action_id=decision["action_id"],
                verdict=Verdict(decision["verdict"]),
                reasons=decision["reasons"],
                input_digest=decision["input_digest"],
                policy_version=decision["policy_version"],
            )
            for action_id, decision in trace_data.get("policy_decisions", {}).items()
        },
        root_commitment=trace_data.get("root_commitment", ""),
        metadata=trace_data.get("metadata", {}),
    )
    dispute_data = data["dispute"]
    dispute = Dispute(
        dispute_id=dispute_data["dispute_id"],
        trace_id=dispute_data["trace_id"],
        side_effect_id=dispute_data["side_effect_id"],
        claim=ClaimType(dispute_data["claim"]),
        claimant=dispute_data["claimant"],
        raised_at=dispute_data["raised_at"],
        expected_verdict=Verdict(dispute_data["expected_verdict"]),
    )
    return BenchmarkCase(
        case_id=data["case_id"],
        scenario=data["scenario"],
        attack=ClaimType(data["attack"]),
        trace=trace,
        dispute=dispute,
    )


def cases_from_rows(rows: list[dict]) -> list[BenchmarkCase]:
    return [case_from_dict(row) for row in rows]
