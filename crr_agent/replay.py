from __future__ import annotations

from .dag import CausalDAGStore
from .policy import PolicyEngine
from .receipts import ReceiptInstrumentor
from .types import NodeType, ReplayResult, ReplaySubgraph, Verdict, WorkflowNode, WorkflowTrace


class PartialReplayEngine:
    def __init__(self, instrumentor: ReceiptInstrumentor, cost_model: dict, policy_config: dict | None = None):
        self.instrumentor = instrumentor
        self.cost_model = cost_model
        self.policy_engine = PolicyEngine(policy_config or {})

    def replay(self, trace: WorkflowTrace, subgraph: ReplaySubgraph, side_effect_id: str) -> ReplayResult:
        reasons: list[str] = []
        verified = True
        verified_receipts = 0
        receipt_time = 0.0
        policy_time = 0.0
        node_open_time = len(subgraph.opened_node_ids) * float(self.cost_model.get("node_open_ms", 0.8))
        store = CausalDAGStore(trace.trace_id)
        store.trace = trace

        for action_id, receipt in trace.receipts.items():
            if action_id in subgraph.node_ids:
                verified_receipts += 1
                receipt_time += float(self.cost_model.get("receipt_verify_ms", 0.25))
                action = trace.nodes.get(action_id)
                authority = _first_ancestor_of_type(trace, action_id, NodeType.DELEGATION)
                instruction = _first_ancestor_of_type(trace, action_id, NodeType.PROMPT)
                predecessors = _ordered_evidence_predecessors(trace, action_id)
                decision = trace.policy_decisions.get(action_id)
                receipt_ok, receipt_reasons = self.instrumentor.verify_against_trace(
                    receipt, action, authority, instruction, predecessors, decision
                )
                if not receipt_ok:
                    verified = False
                    reasons.extend([f"{reason}:{action_id}" for reason in receipt_reasons])

        policy_verdict = Verdict.AMBIGUOUS
        action_nodes = [
            node for node in trace.nodes.values()
            if node.node_type == NodeType.ACTION and node.node_id in subgraph.node_ids
        ]
        for action in action_nodes:
            policy_time += float(self.cost_model.get("policy_replay_ms", 1.5))
            authority = _first_ancestor_of_type(trace, action.node_id, NodeType.DELEGATION)
            replayed_decision = self.policy_engine.evaluate(action, authority=authority)
            stored_decision = trace.policy_decisions.get(action.node_id)
            if stored_decision is None:
                verified = False
                policy_verdict = Verdict.AMBIGUOUS
                reasons.append(f"policy_record_missing:{action.node_id}")
            elif replayed_decision.to_dict() != stored_decision.to_dict():
                verified = False
                policy_verdict = Verdict.AMBIGUOUS
                mismatch_fields = _policy_mismatch_fields(replayed_decision.to_dict(), stored_decision.to_dict())
                reasons.append(f"policy_replay_mismatch:{action.node_id}:{'|'.join(mismatch_fields)}")
            else:
                policy_verdict = replayed_decision.verdict
                reasons.extend(replayed_decision.reasons)

        side_effect = trace.nodes.get(side_effect_id)
        side_effect_matches = True
        if side_effect is None or side_effect_id not in subgraph.node_ids:
            verified = False
            side_effect_matches = False
            reasons.append("side_effect_not_replayed")
        elif side_effect.payload.get("mismatch", False):
            side_effect_matches = False
            policy_verdict = Verdict.UNAUTHORIZED
            reasons.append("side_effect_mismatch")

        for action in action_nodes:
            if action.payload.get("action_type") != "real_process_transition":
                continue
            evidence_nodes = [
                trace.nodes[edge.source]
                for edge in trace.edges
                if edge.target == side_effect_id
                and edge.relation == "real_evidence_for"
                and edge.source in trace.nodes
                and edge.source in subgraph.opened_node_ids
            ]
            terminal_activity = str(action.payload.get("terminal_activity", ""))
            if not evidence_nodes:
                verified = False
                reasons.append("real_evidence_not_opened")
            elif terminal_activity not in {node.label for node in evidence_nodes}:
                verified = False
                reasons.append("real_terminal_activity_evidence_mismatch")

        deterministic_nodes = [
            trace.nodes[nid]
            for nid in subgraph.node_ids
            if nid in trace.nodes and trace.nodes[nid].deterministic
        ]
        replay_fidelity = len(deterministic_nodes) / max(1, len(subgraph.node_ids))
        if verified_receipts == 0:
            verified = False
            replay_fidelity *= 0.7
            reasons.append("no_receipts_in_replay")

        latency_ms = node_open_time + receipt_time + policy_time
        if policy_verdict == Verdict.AMBIGUOUS:
            latency_ms += 2.0

        if not reasons:
            reasons.append("replay_consistent")

        rollback_success = _rollback_success(policy_verdict, verified, side_effect)

        return ReplayResult(
            verified=verified,
            replay_fidelity=replay_fidelity,
            policy_verdict=policy_verdict,
            side_effect_matches=side_effect_matches,
            reasons=reasons,
            latency_ms=latency_ms,
            receipt_verification_time_ms=receipt_time,
            policy_replay_time_ms=policy_time,
            node_open_time_ms=node_open_time,
            rollback_success=rollback_success,
        )


def _first_ancestor_of_type(trace: WorkflowTrace, node_id: str, node_type: NodeType) -> WorkflowNode | None:
    store = CausalDAGStore(trace.trace_id)
    store.trace = trace
    candidates = [
        trace.nodes[ancestor_id]
        for ancestor_id in store.ancestors(node_id)
        if ancestor_id in trace.nodes and trace.nodes[ancestor_id].node_type == node_type
    ]
    return sorted(candidates, key=lambda node: node.node_id)[0] if candidates else None


def _ordered_evidence_predecessors(trace: WorkflowTrace, action_id: str) -> list[WorkflowNode]:
    store = CausalDAGStore(trace.trace_id)
    store.trace = trace
    order = {
        NodeType.OBSERVATION: 0,
        NodeType.PROMPT: 1,
        NodeType.DELEGATION: 2,
    }
    nodes = [
        trace.nodes[ancestor_id]
        for ancestor_id in store.ancestors(action_id)
        if ancestor_id in trace.nodes and trace.nodes[ancestor_id].node_type in order
    ]
    return sorted(nodes, key=lambda node: (order[node.node_type], node.node_id))


def _rollback_success(policy_verdict: Verdict, verified: bool, side_effect: WorkflowNode | None) -> float:
    if side_effect is None:
        return 0.0
    if policy_verdict != Verdict.UNAUTHORIZED:
        return 1.0
    if verified and side_effect.payload.get("rollback_possible", False):
        return 1.0
    if verified:
        return 0.5
    return 0.0


def _policy_mismatch_fields(replayed: dict, stored: dict) -> list[str]:
    fields = sorted(set(replayed) | set(stored))
    return [field for field in fields if replayed.get(field) != stored.get(field)]
