from __future__ import annotations

from .adjudicator import CRRAdjudicator
from .crypto import digest
from .types import AdjudicationReport, BenchmarkCase, NodeType, ReplayResult, ReplaySubgraph, Verdict, WorkflowNode


class Baseline:
    name = "baseline"
    opened_ratio = 0.3

    def adjudicate(self, case: BenchmarkCase, adjudicator: CRRAdjudicator) -> AdjudicationReport:
        raise NotImplementedError


class PlainLogsBaseline(Baseline):
    name = "plain_logs"
    opened_ratio = 0.15

    def adjudicate(self, case: BenchmarkCase, adjudicator: CRRAdjudicator) -> AdjudicationReport:
        action = _action(case)
        side_effect = case.trace.nodes[case.dispute.side_effect_id]
        reasons = ["log_event_sequence_only"]
        if side_effect.payload.get("mismatch"):
            return _report_from_baseline(case, Verdict.AMBIGUOUS, reasons + ["log_cannot_bind_side_effect_to_intent"], self.opened_ratio)
        if action.payload.get("ambiguous"):
            return _report_from_baseline(case, Verdict.AMBIGUOUS, reasons + ["ambiguous_text_log"], self.opened_ratio)
        return _report_from_baseline(case, Verdict.AUTHORIZED, reasons, self.opened_ratio)


class OTelLogsBaseline(Baseline):
    name = "otel_logs"
    opened_ratio = 0.35

    def adjudicate(self, case: BenchmarkCase, adjudicator: CRRAdjudicator) -> AdjudicationReport:
        action = _action(case)
        decision = case.trace.policy_decisions.get(action.node_id)
        reasons = ["otel_span_links", "tool_call_attributes"]
        if decision and decision.verdict == Verdict.UNAUTHORIZED:
            return _report_from_baseline(case, Verdict.UNAUTHORIZED, reasons + decision.reasons, self.opened_ratio)
        if action.payload.get("tool_binding_ok") is False:
            return _report_from_baseline(case, Verdict.UNAUTHORIZED, reasons + ["otel_tool_binding_attribute_failed"], self.opened_ratio)
        return _report_from_baseline(case, Verdict.AUTHORIZED, reasons, self.opened_ratio)


class SignedReceiptsBaseline(Baseline):
    name = "signed_receipts"
    opened_ratio = 0.3

    def adjudicate(self, case: BenchmarkCase, adjudicator: CRRAdjudicator) -> AdjudicationReport:
        action = _action(case)
        receipt = case.trace.receipts.get(action.node_id)
        reasons = ["signed_action_receipt_only"]
        if receipt is None:
            return _report_from_baseline(case, Verdict.AMBIGUOUS, reasons + ["receipt_missing"], self.opened_ratio)
        signature_ok = adjudicator.replay_engine.instrumentor.verify(receipt)
        payload_ok = receipt.payload_digest == digest(action.payload)
        if not signature_ok or not payload_ok:
            return _report_from_baseline(case, Verdict.UNAUTHORIZED, reasons + ["receipt_integrity_failed"], self.opened_ratio)
        return _report_from_baseline(case, Verdict.AUTHORIZED, reasons + ["receipt_integrity_ok"], self.opened_ratio)


class AIPDelegationBaseline(Baseline):
    name = "aip_delegation"
    opened_ratio = 0.4

    def adjudicate(self, case: BenchmarkCase, adjudicator: CRRAdjudicator) -> AdjudicationReport:
        action = _action(case)
        delegation = _node_of_type(case, NodeType.DELEGATION)
        scopes = set(delegation.payload.get("allowed_scopes", []))
        delegatees = set(delegation.payload.get("delegatees", []))
        reasons = ["aip_like_delegation_token", f"scopes={sorted(scopes)}"]
        if action.payload.get("required_scope") not in scopes:
            return _report_from_baseline(case, Verdict.UNAUTHORIZED, reasons + ["delegation_scope_violation"], self.opened_ratio)
        if action.actor not in delegatees:
            return _report_from_baseline(case, Verdict.UNAUTHORIZED, reasons + ["delegatee_not_authorized"], self.opened_ratio)
        return _report_from_baseline(case, Verdict.AUTHORIZED, reasons + ["delegation_token_valid"], self.opened_ratio)


class AgentDIDIdentityBaseline(Baseline):
    name = "agentdid_identity"
    opened_ratio = 0.32

    def adjudicate(self, case: BenchmarkCase, adjudicator: CRRAdjudicator) -> AdjudicationReport:
        action = _action(case)
        receipt = case.trace.receipts.get(action.node_id)
        reasons = ["agentdid_like_actor_binding"]
        actor_bound = receipt is not None and receipt.actor == action.actor and action.actor not in {"", "unknown", "NONE"}
        if not actor_bound:
            return _report_from_baseline(case, Verdict.UNAUTHORIZED, reasons + ["actor_binding_failed"], self.opened_ratio)
        return _report_from_baseline(case, Verdict.AUTHORIZED, reasons + ["actor_binding_valid"], self.opened_ratio)


class SUDPSecretDelegationBaseline(Baseline):
    name = "sudp_secret_delegation"
    opened_ratio = 0.38

    def adjudicate(self, case: BenchmarkCase, adjudicator: CRRAdjudicator) -> AdjudicationReport:
        action = _action(case)
        reasons = ["sudp_like_secret_use_record"]
        secret = action.payload.get("uses_secret")
        if secret and not action.payload.get("secret_delegated", False):
            return _report_from_baseline(case, Verdict.UNAUTHORIZED, reasons + [f"secret_not_delegated:{secret}"], self.opened_ratio)
        if secret:
            return _report_from_baseline(case, Verdict.AUTHORIZED, reasons + [f"secret_delegated:{secret}"], self.opened_ratio)
        return _report_from_baseline(case, Verdict.AUTHORIZED, reasons + ["no_secret_use"], self.opened_ratio)


class AgentSentryBoundsBaseline(Baseline):
    name = "agent_sentry_bounds"
    opened_ratio = 0.45

    def adjudicate(self, case: BenchmarkCase, adjudicator: CRRAdjudicator) -> AdjudicationReport:
        action = _action(case)
        decision = case.trace.policy_decisions.get(action.node_id)
        reasons = ["agent_sentry_execution_bounds"]
        if action.payload.get("tool_binding_ok") is False:
            return _report_from_baseline(case, Verdict.UNAUTHORIZED, reasons + ["tool_bound_violation"], self.opened_ratio)
        if decision and decision.verdict == Verdict.UNAUTHORIZED:
            return _report_from_baseline(case, Verdict.UNAUTHORIZED, reasons + decision.reasons, self.opened_ratio)
        if action.payload.get("ambiguous"):
            return _report_from_baseline(case, Verdict.AMBIGUOUS, reasons + ["bounds_cannot_resolve_ambiguity"], self.opened_ratio)
        return _report_from_baseline(case, Verdict.AUTHORIZED, reasons + ["bounds_valid"], self.opened_ratio)


class FullReplayOracle(Baseline):
    name = "full_replay_oracle"

    def adjudicate(self, case: BenchmarkCase, adjudicator: CRRAdjudicator) -> AdjudicationReport:
        return adjudicator.adjudicate(case.trace, case.dispute, mode="full_replay")


class CRRBaseline(Baseline):
    name = "crr_agent"

    def adjudicate(self, case: BenchmarkCase, adjudicator: CRRAdjudicator) -> AdjudicationReport:
        return adjudicator.adjudicate(case.trace, case.dispute, mode="minimal")


def build_baseline(name: str) -> Baseline:
    baselines: dict[str, type[Baseline]] = {
        "plain_logs": PlainLogsBaseline,
        "otel_logs": OTelLogsBaseline,
        "signed_receipts": SignedReceiptsBaseline,
        "aip_delegation": AIPDelegationBaseline,
        "agentdid_identity": AgentDIDIdentityBaseline,
        "sudp_secret_delegation": SUDPSecretDelegationBaseline,
        "agent_sentry_bounds": AgentSentryBoundsBaseline,
        "full_replay_oracle": FullReplayOracle,
        "crr_agent": CRRBaseline,
    }
    try:
        return baselines[name]()
    except KeyError as exc:
        raise ValueError(f"unknown baseline: {name}") from exc


def _action(case: BenchmarkCase) -> WorkflowNode:
    return _node_of_type(case, NodeType.ACTION)


def _node_of_type(case: BenchmarkCase, node_type: NodeType) -> WorkflowNode:
    return next(node for node in case.trace.nodes.values() if node.node_type == node_type)


def _report_from_baseline(case: BenchmarkCase, verdict: Verdict, reasons: list[str], opened_ratio: float) -> AdjudicationReport:
    node_count = len(case.trace.nodes)
    opened = _baseline_opened_nodes(case, reasons[0] if reasons else "")
    opened_count = len(opened)
    latency = float(opened_count)
    subgraph = ReplaySubgraph(
        node_ids=opened,
        opened_node_ids=opened,
        commitment_only_node_ids=set(),
        cost=float(opened_count),
        leakage=sum(case.trace.nodes[nid].sensitivity for nid in opened),
        estimated_time_ms=latency,
    )
    replay = ReplayResult(
        verified=verdict != Verdict.AMBIGUOUS,
        replay_fidelity=opened_count / max(1, node_count),
        policy_verdict=verdict,
        side_effect_matches=case.attack.value != "side_effect_mismatch",
        reasons=reasons,
        latency_ms=latency,
        receipt_verification_time_ms=0.25 if any("receipt" in reason for reason in reasons) else 0.0,
        policy_replay_time_ms=1.0 if any("policy" in reason or "bound" in reason for reason in reasons) else 0.0,
        node_open_time_ms=latency,
        rollback_success=1.0 if verdict == Verdict.UNAUTHORIZED else 0.0,
    )
    return AdjudicationReport(
        dispute_id=case.dispute.dispute_id,
        trace_id=case.trace.trace_id,
        claim=case.dispute.claim,
        verdict=verdict,
        expected_verdict=case.dispute.expected_verdict,
        evidence_digest=f"{case.case_id}:{verdict.value}:{digest(reasons)[:12]}",
        root_commitment=case.trace.root_commitment,
        subgraph=subgraph,
        replay=replay,
        responsibility_chain=[],
    )


def _baseline_opened_nodes(case: BenchmarkCase, evidence_kind: str) -> set[str]:
    nodes = case.trace.nodes
    by_type = {
        node_type: {node_id for node_id, node in nodes.items() if node.node_type == node_type}
        for node_type in NodeType
    }
    if evidence_kind == "log_event_sequence_only":
        return by_type[NodeType.OBSERVATION] | by_type[NodeType.SIDE_EFFECT]
    if evidence_kind == "otel_span_links":
        return set(nodes)
    if evidence_kind == "signed_action_receipt_only":
        return by_type[NodeType.ACTION] | by_type[NodeType.SIDE_EFFECT]
    if evidence_kind == "aip_like_delegation_token":
        return by_type[NodeType.DELEGATION] | by_type[NodeType.ACTION] | by_type[NodeType.SIDE_EFFECT]
    if evidence_kind == "agentdid_like_actor_binding":
        return by_type[NodeType.ACTION] | by_type[NodeType.SIDE_EFFECT]
    if evidence_kind == "sudp_like_secret_use_record":
        return by_type[NodeType.ACTION] | by_type[NodeType.SIDE_EFFECT]
    if evidence_kind == "agent_sentry_execution_bounds":
        return by_type[NodeType.DELEGATION] | by_type[NodeType.ACTION] | by_type[NodeType.POLICY] | by_type[NodeType.SIDE_EFFECT]
    return set(nodes)
