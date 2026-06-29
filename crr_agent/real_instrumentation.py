from __future__ import annotations

from .crypto import HMACSigner
from .dag import CausalDAGStore
from .policy import PolicyEngine
from .real_data import RealProcessCase, stable_split
from .real_rules import ConformanceFinding
from .receipts import ReceiptInstrumentor
from .types import BenchmarkCase, ClaimType, Dispute, NodeType, WorkflowNode


def instrument_real_case(case: RealProcessCase, finding: ConformanceFinding, policy_config: dict) -> BenchmarkCase:
    trace_id = f"{case.dataset_id}:{case.case_id}"
    store = CausalDAGStore(
        trace_id,
        metadata={
            "dataset_id": case.dataset_id,
            "case_id": case.case_id,
            "split": stable_split(case.dataset_id, case.case_id),
            "event_count": len(case.events),
            "rule_id": finding.rule_id,
            "data_kind": "real_business_event_log",
        },
    )
    event_nodes: list[WorkflowNode] = []
    for event in case.events:
        payload = dict(event.attributes)
        payload.update({"activity": event.activity, "timestamp": event.timestamp, "resource": event.resource})
        node = WorkflowNode(
            node_id=f"{trace_id}:event:{event.index:06d}",
            node_type=NodeType.OBSERVATION,
            actor=event.resource,
            label=event.activity,
            payload=payload,
            sensitivity=_event_sensitivity(payload),
            deterministic=True,
            revealable=True,
        )
        event_nodes.append(node)
        store.add_node(node)
    for previous, current in zip(event_nodes, event_nodes[1:]):
        store.add_edge(previous.node_id, current.node_id, "observed_sequence")

    delegation = WorkflowNode(
        node_id=f"{trace_id}:delegation",
        node_type=NodeType.DELEGATION,
        actor="recorded_process_owner",
        label="delegate_recorded_transition",
        payload={
            "allowed_scopes": ["real_process_transition"],
            "delegatees": [case.events[-1].resource],
            "source": "recorded_org_resource",
        },
        sensitivity=0.2,
    )
    store.add_node(delegation)
    store.add_edge(event_nodes[-1].node_id, delegation.node_id, "recorded_actor_assignment")

    action = WorkflowNode(
        node_id=f"{trace_id}:action",
        node_type=NodeType.ACTION,
        actor=case.events[-1].resource,
        label="adjudicate_recorded_process_side_effect",
        payload={
            "action_type": "real_process_transition",
            "terminal_activity": finding.side_effect_activity,
            "supported_terminal": finding.verdict.value != "ambiguous",
            "source_case_id": case.case_id,
            "required_scope": "real_process_transition",
        },
        sensitivity=0.25,
    )
    store.add_node(action)
    store.add_edge(delegation.node_id, action.node_id, "authorizes")

    policy_engine = PolicyEngine(policy_config)
    decision = policy_engine.evaluate(action, authority=delegation)
    policy_node = WorkflowNode(
        node_id=f"{trace_id}:policy",
        node_type=NodeType.POLICY,
        actor="conformance_policy_engine",
        label=finding.rule_id,
        payload=decision.to_dict(),
        sensitivity=0.1,
    )
    side_effect = WorkflowNode(
        node_id=f"{trace_id}:side_effect",
        node_type=NodeType.SIDE_EFFECT,
        actor=case.events[-1].resource,
        label=finding.side_effect_activity,
        payload={
            "source_event_index": finding.evidence_event_indices[-1] if finding.evidence_event_indices else len(case.events) - 1,
            "rationale": finding.rationale,
            "rollback_possible": False,
            "mismatch": False,
        },
        sensitivity=0.3,
    )
    store.add_node(policy_node)
    store.add_node(side_effect)
    store.add_edge(action.node_id, policy_node.node_id, "evaluated_by")
    store.add_edge(policy_node.node_id, side_effect.node_id, "adjudicates")
    store.add_edge(action.node_id, side_effect.node_id, "describes")
    for index in finding.evidence_event_indices:
        if 0 <= index < len(event_nodes):
            store.add_edge(event_nodes[index].node_id, side_effect.node_id, "real_evidence_for")

    store.add_policy_decision(decision)
    instrumentor = ReceiptInstrumentor(HMACSigner("crr-agent-experiment-key"))
    receipt = instrumentor.create_action_receipt(
        action=action,
        authority=delegation,
        instruction=None,
        predecessors=sorted(event_nodes, key=lambda node: node.node_id) + [delegation],
        policy_decision=decision,
        issued_at=float(len(case.events)),
    )
    store.add_receipt(receipt)
    trace = store.finalize()

    dispute = Dispute(
        dispute_id=f"{trace_id}:dispute",
        trace_id=trace_id,
        side_effect_id=side_effect.node_id,
        claim=ClaimType.PROCESS_NONCOMPLIANCE,
        claimant="process_auditor",
        raised_at=0.0,
        expected_verdict=finding.verdict,
    )
    return BenchmarkCase(
        case_id=trace_id,
        scenario=case.dataset_id,
        attack=ClaimType.PROCESS_NONCOMPLIANCE,
        trace=trace,
        dispute=dispute,
    )


def _event_sensitivity(payload: dict[str, str]) -> float:
    keys = " ".join(payload).lower()
    if any(token in keys for token in ["amount", "vendor", "loan", "credit", "resource"]):
        return 0.6
    return 0.25
