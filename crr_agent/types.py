from __future__ import annotations

from dataclasses import asdict, dataclass, field
from enum import Enum
from typing import Any


class NodeType(str, Enum):
    OBSERVATION = "observation"
    PROMPT = "prompt"
    DELEGATION = "delegation"
    ACTION = "action"
    SIDE_EFFECT = "side_effect"
    POLICY = "policy"


class Verdict(str, Enum):
    AUTHORIZED = "authorized"
    UNAUTHORIZED = "unauthorized"
    AMBIGUOUS = "ambiguous"


class ClaimType(str, Enum):
    BENIGN = "benign"
    PROMPT_INJECTION = "prompt_injection"
    TOOL_POISONING = "tool_poisoning"
    SCOPE_DRIFT = "scope_drift"
    OVER_DELEGATION = "over_delegation"
    SECRET_MISUSE = "secret_misuse"
    AMBIGUOUS_INSTRUCTION = "ambiguous_instruction"
    MALICIOUS_SUB_AGENT = "malicious_sub_agent"
    STALE_POLICY = "stale_policy"
    WRONG_TOOL_BINDING = "wrong_tool_binding"
    SIDE_EFFECT_MISMATCH = "side_effect_mismatch"
    PROCESS_NONCOMPLIANCE = "process_noncompliance"


@dataclass(frozen=True)
class WorkflowNode:
    node_id: str
    node_type: NodeType
    actor: str
    label: str
    payload: dict[str, Any]
    sensitivity: float = 0.0
    deterministic: bool = True
    revealable: bool = True

    def to_dict(self) -> dict[str, Any]:
        data = asdict(self)
        data["node_type"] = self.node_type.value
        return data


@dataclass(frozen=True)
class WorkflowEdge:
    source: str
    target: str
    relation: str

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True)
class PolicyDecision:
    decision_id: str
    action_id: str
    verdict: Verdict
    reasons: list[str]
    input_digest: str
    policy_version: str

    def to_dict(self) -> dict[str, Any]:
        data = asdict(self)
        data["verdict"] = self.verdict.value
        return data


@dataclass(frozen=True)
class ActionReceipt:
    receipt_id: str
    action_id: str
    actor: str
    authority_hash: str
    instruction_hash: str
    payload_digest: str
    predecessor_hash: str
    policy_digest: str
    issued_at: float
    signature: str

    def signed_payload(self) -> dict[str, Any]:
        return {
            "receipt_id": self.receipt_id,
            "action_id": self.action_id,
            "actor": self.actor,
            "authority_hash": self.authority_hash,
            "instruction_hash": self.instruction_hash,
            "payload_digest": self.payload_digest,
            "predecessor_hash": self.predecessor_hash,
            "policy_digest": self.policy_digest,
            "issued_at": self.issued_at,
        }

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class WorkflowTrace:
    trace_id: str
    nodes: dict[str, WorkflowNode] = field(default_factory=dict)
    edges: list[WorkflowEdge] = field(default_factory=list)
    receipts: dict[str, ActionReceipt] = field(default_factory=dict)
    policy_decisions: dict[str, PolicyDecision] = field(default_factory=dict)
    root_commitment: str = ""
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "trace_id": self.trace_id,
            "nodes": {k: v.to_dict() for k, v in self.nodes.items()},
            "edges": [e.to_dict() for e in self.edges],
            "receipts": {k: v.to_dict() for k, v in self.receipts.items()},
            "policy_decisions": {k: v.to_dict() for k, v in self.policy_decisions.items()},
            "root_commitment": self.root_commitment,
            "metadata": self.metadata,
        }


@dataclass(frozen=True)
class Dispute:
    dispute_id: str
    trace_id: str
    side_effect_id: str
    claim: ClaimType
    claimant: str
    raised_at: float
    expected_verdict: Verdict

    def to_dict(self) -> dict[str, Any]:
        data = asdict(self)
        data["claim"] = self.claim.value
        data["expected_verdict"] = self.expected_verdict.value
        return data


@dataclass(frozen=True)
class ReplaySubgraph:
    node_ids: set[str]
    opened_node_ids: set[str]
    commitment_only_node_ids: set[str]
    cost: float
    leakage: float
    estimated_time_ms: float

    def to_dict(self) -> dict[str, Any]:
        return {
            "node_ids": sorted(self.node_ids),
            "opened_node_ids": sorted(self.opened_node_ids),
            "commitment_only_node_ids": sorted(self.commitment_only_node_ids),
            "cost": self.cost,
            "leakage": self.leakage,
            "estimated_time_ms": self.estimated_time_ms,
        }


@dataclass(frozen=True)
class ReplayResult:
    verified: bool
    replay_fidelity: float
    policy_verdict: Verdict
    side_effect_matches: bool
    reasons: list[str]
    latency_ms: float
    receipt_verification_time_ms: float = 0.0
    policy_replay_time_ms: float = 0.0
    node_open_time_ms: float = 0.0
    rollback_success: float = 0.0

    def to_dict(self) -> dict[str, Any]:
        data = asdict(self)
        data["policy_verdict"] = self.policy_verdict.value
        return data


@dataclass(frozen=True)
class AdjudicationReport:
    dispute_id: str
    trace_id: str
    claim: ClaimType
    verdict: Verdict
    expected_verdict: Verdict
    evidence_digest: str
    root_commitment: str
    subgraph: ReplaySubgraph
    replay: ReplayResult
    responsibility_chain: list[str]

    def to_dict(self) -> dict[str, Any]:
        return {
            "dispute_id": self.dispute_id,
            "trace_id": self.trace_id,
            "claim": self.claim.value,
            "verdict": self.verdict.value,
            "expected_verdict": self.expected_verdict.value,
            "evidence_digest": self.evidence_digest,
            "root_commitment": self.root_commitment,
            "subgraph": self.subgraph.to_dict(),
            "replay": self.replay.to_dict(),
            "responsibility_chain": self.responsibility_chain,
        }


@dataclass(frozen=True)
class BenchmarkCase:
    case_id: str
    scenario: str
    attack: ClaimType
    trace: WorkflowTrace
    dispute: Dispute

    def to_dict(self) -> dict[str, Any]:
        return {
            "case_id": self.case_id,
            "scenario": self.scenario,
            "attack": self.attack.value,
            "trace": self.trace.to_dict(),
            "dispute": self.dispute.to_dict(),
        }
