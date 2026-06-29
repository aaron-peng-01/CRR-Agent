from __future__ import annotations

from .dag import CausalDAGStore
from .types import NodeType, ReplaySubgraph, WorkflowTrace


class MinimalReplaySelector:
    def __init__(self, config: dict, cost_model: dict):
        self.config = config
        self.cost_model = cost_model

    def select(self, trace: WorkflowTrace, side_effect_id: str, mode: str = "minimal") -> ReplaySubgraph:
        store = CausalDAGStore(trace.trace_id)
        store.trace = trace

        if mode == "full_replay":
            node_ids = set(trace.nodes)
        elif mode == "action_only_replay":
            node_ids = {side_effect_id}
            for edge in trace.edges:
                if edge.target == side_effect_id and trace.nodes[edge.source].node_type.value == "action":
                    node_ids.add(edge.source)
        elif mode == "no_ancestor_replay":
            node_ids = {side_effect_id}
        else:
            depth = int(self.config.get("ancestor_depth", 8))
            node_ids = store.ancestors(side_effect_id, max_depth=depth)

        return self._select_opening_strategy(trace, node_ids, mode=mode)

    def _select_opening_strategy(self, trace: WorkflowTrace, node_ids: set[str], mode: str) -> ReplaySubgraph:
        allow_commitment = bool(self.config.get("allow_commitment_only_nodes", True))
        if mode == "full_replay" or not allow_commitment:
            return self._score(trace, node_ids, opened=set(node_ids))

        required_open = {
            node_id
            for node_id in node_ids
            if trace.nodes[node_id].node_type in {NodeType.ACTION, NodeType.SIDE_EFFECT, NodeType.POLICY}
        }
        required_open.update(
            edge.source
            for edge in trace.edges
            if edge.relation == "real_evidence_for" and edge.source in node_ids
        )
        optional = sorted(node_ids - required_open)
        strategies: list[set[str]] = [set(required_open)]

        low_sensitivity = {nid for nid in optional if trace.nodes[nid].sensitivity <= 0.3}
        deterministic_context = {nid for nid in optional if trace.nodes[nid].deterministic and trace.nodes[nid].sensitivity <= 0.6}
        full_context = set(optional)
        strategies.extend([
            required_open | low_sensitivity,
            required_open | deterministic_context,
            required_open | full_context,
        ])

        best = min(
            (self._score(trace, node_ids, opened=strategy) for strategy in strategies),
            key=self._objective,
        )
        return best

    def _score(self, trace: WorkflowTrace, node_ids: set[str], opened: set[str]) -> ReplaySubgraph:
        opened_ids: set[str] = set()
        commitment_only: set[str] = set()

        for node_id in node_ids:
            node = trace.nodes[node_id]
            if node_id in opened:
                opened_ids.add(node_id)
            else:
                commitment_only.add(node_id)

        leakage = sum(trace.nodes[nid].sensitivity for nid in opened_ids)
        uncertainty_cost = sum(_commitment_uncertainty(trace.nodes[nid].node_type) for nid in commitment_only)
        cost = len(node_ids) + len(opened_ids) * 0.5 + uncertainty_cost
        estimated_time_ms = (
            len(opened_ids) * float(self.cost_model.get("node_open_ms", 0.8))
            + len([nid for nid in node_ids if nid in trace.receipts]) * float(self.cost_model.get("receipt_verify_ms", 0.25))
            + len([nid for nid in node_ids if nid in trace.policy_decisions]) * float(self.cost_model.get("policy_replay_ms", 1.5))
        )
        return ReplaySubgraph(
            node_ids=node_ids,
            opened_node_ids=opened_ids,
            commitment_only_node_ids=commitment_only,
            cost=cost,
            leakage=leakage,
            estimated_time_ms=estimated_time_ms,
        )

    def _objective(self, subgraph: ReplaySubgraph) -> float:
        return (
            float(self.config.get("lambda_cost", 1.0)) * subgraph.cost
            + float(self.config.get("lambda_leak", 4.0)) * subgraph.leakage
            + float(self.config.get("lambda_time", 0.5)) * subgraph.estimated_time_ms
        )


def _commitment_uncertainty(node_type: NodeType) -> float:
    if node_type == NodeType.DELEGATION:
        return 1.4
    if node_type == NodeType.PROMPT:
        return 1.0
    if node_type == NodeType.OBSERVATION:
        return 0.5
    return 0.2
