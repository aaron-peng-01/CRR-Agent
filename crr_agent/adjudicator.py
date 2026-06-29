from __future__ import annotations

from .crypto import digest
from .receipts import ReceiptInstrumentor
from .replay import PartialReplayEngine
from .selector import MinimalReplaySelector
from .types import AdjudicationReport, Dispute, Verdict, WorkflowTrace


class CRRAdjudicator:
    def __init__(self, selector: MinimalReplaySelector, replay_engine: PartialReplayEngine):
        self.selector = selector
        self.replay_engine = replay_engine

    @classmethod
    def from_config(cls, config: dict, instrumentor: ReceiptInstrumentor) -> "CRRAdjudicator":
        selector = MinimalReplaySelector(config.get("selector", {}), config.get("cost_model", {}))
        replay = PartialReplayEngine(instrumentor, config.get("cost_model", {}), config.get("policy", {}))
        return cls(selector=selector, replay_engine=replay)

    def adjudicate(self, trace: WorkflowTrace, dispute: Dispute, mode: str = "minimal") -> AdjudicationReport:
        subgraph = self.selector.select(trace, dispute.side_effect_id, mode=mode)
        replay = self.replay_engine.replay(trace, subgraph, dispute.side_effect_id)

        if replay.verified and replay.side_effect_matches and replay.policy_verdict == Verdict.AUTHORIZED:
            verdict = Verdict.AUTHORIZED
        elif replay.verified and replay.policy_verdict == Verdict.UNAUTHORIZED:
            verdict = Verdict.UNAUTHORIZED
        else:
            verdict = Verdict.AMBIGUOUS

        evidence_digest = digest(
            {
                "trace_id": trace.trace_id,
                "dispute": dispute.to_dict(),
                "subgraph": subgraph.to_dict(),
                "replay": replay.to_dict(),
            }
        )
        return AdjudicationReport(
            dispute_id=dispute.dispute_id,
            trace_id=trace.trace_id,
            claim=dispute.claim,
            verdict=verdict,
            expected_verdict=dispute.expected_verdict,
            evidence_digest=evidence_digest,
            root_commitment=trace.root_commitment,
            subgraph=subgraph,
            replay=replay,
            responsibility_chain=self._responsibility_chain(trace, subgraph.opened_node_ids),
        )

    @staticmethod
    def _responsibility_chain(trace: WorkflowTrace, opened: set[str]) -> list[str]:
        chain: list[str] = []
        for edge in trace.edges:
            if edge.source in opened and edge.target in opened:
                src = trace.nodes[edge.source]
                dst = trace.nodes[edge.target]
                chain.append(f"{src.actor}:{src.label}->{dst.actor}:{dst.label}")
        return chain
