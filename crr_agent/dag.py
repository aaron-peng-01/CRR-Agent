from __future__ import annotations

from collections import defaultdict, deque
from copy import deepcopy

from .crypto import digest, merkle_root
from .types import ActionReceipt, PolicyDecision, WorkflowEdge, WorkflowNode, WorkflowTrace


class CausalDAGStore:
    def __init__(self, trace_id: str, metadata: dict | None = None):
        self.trace = WorkflowTrace(trace_id=trace_id, metadata=metadata or {})

    def add_node(self, node: WorkflowNode) -> None:
        self.trace.nodes[node.node_id] = node

    def add_edge(self, source: str, target: str, relation: str) -> None:
        if source not in self.trace.nodes or target not in self.trace.nodes:
            raise KeyError(f"unknown DAG edge endpoint: {source}->{target}")
        self.trace.edges.append(WorkflowEdge(source=source, target=target, relation=relation))

    def add_receipt(self, receipt: ActionReceipt) -> None:
        self.trace.receipts[receipt.action_id] = receipt
        self.trace.root_commitment = self.compute_root()

    def add_policy_decision(self, decision: PolicyDecision) -> None:
        self.trace.policy_decisions[decision.action_id] = decision

    def compute_root(self) -> str:
        receipt_hashes = [digest(r.to_dict()) for r in self.trace.receipts.values()]
        node_commitments = [digest(n.to_dict()) for n in self.trace.nodes.values()]
        edge_commitments = [digest(e.to_dict()) for e in self.trace.edges]
        return merkle_root(receipt_hashes + node_commitments + edge_commitments)

    def ancestors(self, node_id: str, max_depth: int | None = None) -> set[str]:
        parents: dict[str, list[str]] = defaultdict(list)
        for edge in self.trace.edges:
            parents[edge.target].append(edge.source)
        seen: set[str] = set()
        queue: deque[tuple[str, int]] = deque([(node_id, 0)])
        while queue:
            current, depth = queue.popleft()
            if current in seen:
                continue
            seen.add(current)
            if max_depth is not None and depth >= max_depth:
                continue
            for parent in parents.get(current, []):
                queue.append((parent, depth + 1))
        return seen

    def successors(self, node_id: str) -> set[str]:
        children: dict[str, list[str]] = defaultdict(list)
        for edge in self.trace.edges:
            children[edge.source].append(edge.target)
        seen: set[str] = set()
        queue: deque[str] = deque([node_id])
        while queue:
            current = queue.popleft()
            if current in seen:
                continue
            seen.add(current)
            queue.extend(children.get(current, []))
        return seen

    def subtrace(self, node_ids: set[str]) -> WorkflowTrace:
        sub = WorkflowTrace(
            trace_id=f"{self.trace.trace_id}:sub",
            nodes={nid: self.trace.nodes[nid] for nid in node_ids if nid in self.trace.nodes},
            edges=[e for e in self.trace.edges if e.source in node_ids and e.target in node_ids],
            receipts={aid: r for aid, r in self.trace.receipts.items() if aid in node_ids},
            policy_decisions={aid: p for aid, p in self.trace.policy_decisions.items() if aid in node_ids},
            metadata=deepcopy(self.trace.metadata),
        )
        sub.root_commitment = self.compute_root_for(sub)
        return sub

    @staticmethod
    def compute_root_for(trace: WorkflowTrace) -> str:
        receipt_hashes = [digest(r.to_dict()) for r in trace.receipts.values()]
        node_commitments = [digest(n.to_dict()) for n in trace.nodes.values()]
        edge_commitments = [digest(e.to_dict()) for e in trace.edges]
        return merkle_root(receipt_hashes + node_commitments + edge_commitments)

    def finalize(self) -> WorkflowTrace:
        self.trace.root_commitment = self.compute_root()
        return self.trace
