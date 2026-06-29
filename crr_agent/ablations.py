from __future__ import annotations

from copy import deepcopy

from .dag import CausalDAGStore
from .types import NodeType, WorkflowTrace


def apply_ablation(trace: WorkflowTrace, name: str) -> WorkflowTrace:
    mutated = deepcopy(trace)
    mutated.trace_id = f"{trace.trace_id}:{name}"
    mutated.metadata = dict(mutated.metadata)
    mutated.metadata["ablation"] = name

    if name == "no_receipt":
        mutated.receipts = {}
    elif name == "no_causal_dag":
        mutated.edges = []
    elif name == "no_policy_record":
        mutated.policy_decisions = {}
        policy_nodes = {node_id for node_id, node in mutated.nodes.items() if node.node_type == NodeType.POLICY}
        mutated.nodes = {node_id: node for node_id, node in mutated.nodes.items() if node_id not in policy_nodes}
        mutated.edges = [
            edge for edge in mutated.edges
            if edge.source not in policy_nodes and edge.target not in policy_nodes
        ]
    elif name in {"no_minimal_selector", "full_replay", "action_only_replay", "no_ancestor_replay"}:
        mutated.metadata["selector_ablation_only"] = True
    else:
        raise ValueError(f"unknown ablation: {name}")

    mutated.root_commitment = CausalDAGStore.compute_root_for(mutated)
    return mutated


def ablation_mode(name: str) -> str:
    if name in {"no_minimal_selector", "full_replay"}:
        return "full_replay"
    if name == "action_only_replay":
        return "action_only_replay"
    if name == "no_ancestor_replay":
        return "no_ancestor_replay"
    return "minimal"
