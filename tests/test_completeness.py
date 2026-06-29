from dataclasses import replace

from crr_agent.ablations import apply_ablation
from crr_agent.baselines import build_baseline
from crr_agent.crypto import HMACSigner
from crr_agent.experiment import ExperimentRunner
from crr_agent.replay import PartialReplayEngine
from crr_agent.receipts import ReceiptInstrumentor
from crr_agent.scenarios import ScenarioGenerator
from crr_agent.selector import MinimalReplaySelector
from crr_agent.types import ActionReceipt, ClaimType, NodeType, Verdict


def _config() -> dict:
    return {
        "seed": 3,
        "num_cases": 2,
        "scenario_mix": {
            "procurement": 0.2,
            "finance": 0.2,
            "email_support": 0.2,
            "data_access": 0.2,
            "multi_agent": 0.2,
        },
        "attack_mix": {claim.value: 1.0 for claim in ClaimType},
        "policy": {
            "max_transfer_amount": 5000,
            "max_purchase_amount": 2000,
            "allowed_email_domains": ["customer.example", "vendor.example", "internal.example"],
            "allowed_data_exports": ["aggregate", "redacted"],
            "require_human_approval_for": ["payment_execute", "purchase_order_submit"],
            "secret_labels": ["api_key", "bank_token", "customer_pii"],
        },
        "selector": {"lambda_cost": 1.0, "lambda_leak": 4.0, "lambda_time": 0.5, "ancestor_depth": 8, "allow_commitment_only_nodes": True},
        "cost_model": {"node_open_ms": 0.8, "receipt_verify_ms": 0.25, "policy_replay_ms": 1.5},
        "baselines": [
            "plain_logs",
            "otel_logs",
            "signed_receipts",
            "aip_delegation",
            "agentdid_identity",
            "sudp_secret_delegation",
            "agent_sentry_bounds",
            "full_replay_oracle",
            "crr_agent",
        ],
        "ablations": [
            "no_receipt",
            "no_causal_dag",
            "no_policy_record",
            "no_minimal_selector",
            "full_replay",
            "action_only_replay",
            "no_ancestor_replay",
        ],
    }


def test_all_configured_baselines_are_constructible():
    for name in _config()["baselines"]:
        assert build_baseline(name).name == name


def test_all_structural_ablations_mutate_or_select_trace():
    case = ScenarioGenerator(_config()).generate(1)[0]
    assert apply_ablation(case.trace, "no_receipt").receipts == {}
    assert apply_ablation(case.trace, "no_causal_dag").edges == []
    assert apply_ablation(case.trace, "no_policy_record").policy_decisions == {}


def test_selector_weights_affect_opening_strategy():
    case = ScenarioGenerator(_config()).generate(1)[0]
    low_leak = dict(_config()["selector"])
    low_leak.update({"lambda_cost": 8.0, "lambda_leak": 0.1})
    high_leak = dict(_config()["selector"])
    high_leak.update({"lambda_cost": 0.1, "lambda_leak": 10.0})
    cost_model = _config()["cost_model"]
    open_more = MinimalReplaySelector(low_leak, cost_model).select(case.trace, case.dispute.side_effect_id)
    open_less = MinimalReplaySelector(high_leak, cost_model).select(case.trace, case.dispute.side_effect_id)
    assert len(open_more.opened_node_ids) >= len(open_less.opened_node_ids)


def test_receipt_tamper_is_detectable_against_trace():
    case = ScenarioGenerator(_config()).generate(1)[0]
    action_id, receipt = next(iter(case.trace.receipts.items()))
    action = case.trace.nodes[action_id]
    instrumentor = ReceiptInstrumentor(HMACSigner("crr-agent-experiment-key"))
    ok, reasons = instrumentor.verify_against_trace(
        receipt,
        action,
        next(node for node in case.trace.nodes.values() if node.node_type.value == "delegation"),
        next(node for node in case.trace.nodes.values() if node.node_type.value == "prompt"),
        [node for node in case.trace.nodes.values() if node.node_type.value in {"observation", "prompt", "delegation"}][:3],
        case.trace.policy_decisions[action_id],
    )
    assert ok, reasons

    tampered_payload = dict(action.payload)
    tampered_payload["amount"] = 999999
    tampered_action = replace(action, payload=tampered_payload)
    ok, reasons = instrumentor.verify_against_trace(
        receipt,
        tampered_action,
        next(node for node in case.trace.nodes.values() if node.node_type.value == "delegation"),
        next(node for node in case.trace.nodes.values() if node.node_type.value == "prompt"),
        [node for node in case.trace.nodes.values() if node.node_type.value in {"observation", "prompt", "delegation"}][:3],
        case.trace.policy_decisions[action_id],
    )
    assert not ok
    assert "receipt_payload_digest_mismatch" in reasons


def test_receipt_action_id_mismatch_is_explicit():
    case = ScenarioGenerator(_config()).generate(1)[0]
    action_id, receipt = next(iter(case.trace.receipts.items()))
    bad_receipt = ActionReceipt(**{**receipt.to_dict(), "action_id": f"{action_id}:other"})
    action = case.trace.nodes[action_id]
    instrumentor = ReceiptInstrumentor(HMACSigner("crr-agent-experiment-key"))
    ok, reasons = instrumentor.verify_against_trace(
        bad_receipt,
        action,
        next(node for node in case.trace.nodes.values() if node.node_type == NodeType.DELEGATION),
        next(node for node in case.trace.nodes.values() if node.node_type == NodeType.PROMPT),
        [node for node in case.trace.nodes.values() if node.node_type in {NodeType.OBSERVATION, NodeType.PROMPT, NodeType.DELEGATION}][:3],
        case.trace.policy_decisions[action_id],
    )
    assert not ok
    assert "receipt_action_id_mismatch" in reasons


def test_policy_replay_detects_same_verdict_record_drift():
    case = ScenarioGenerator(_config()).generate(1)[0]
    action_id = next(iter(case.trace.receipts))
    stored = case.trace.policy_decisions[action_id]
    case.trace.policy_decisions[action_id] = replace(stored, reasons=["policy_allow", "extra_drift"])
    subgraph = MinimalReplaySelector(_config()["selector"], _config()["cost_model"]).select(case.trace, case.dispute.side_effect_id)
    replay = PartialReplayEngine(
        ReceiptInstrumentor(HMACSigner("crr-agent-experiment-key")),
        _config()["cost_model"],
        _config()["policy"],
    ).replay(case.trace, subgraph, case.dispute.side_effect_id)
    assert not replay.verified
    assert any("policy_replay_mismatch" in reason for reason in replay.reasons)


def test_every_non_benign_attack_has_evidence_node():
    config = _config()
    generator = ScenarioGenerator(config)
    for attack in ClaimType:
        if attack == ClaimType.BENIGN:
            continue
        case = generator._build_case(0, "procurement", attack)
        evidence = [
            node for node in case.trace.nodes.values()
            if node.node_id not in {
                f"{case.trace.trace_id}:obs",
                f"{case.trace.trace_id}:prompt",
                f"{case.trace.trace_id}:delegation",
                f"{case.trace.trace_id}:action",
                f"{case.trace.trace_id}:policy",
                f"{case.trace.trace_id}:side_effect",
            }
        ]
        assert evidence, attack


def test_baseline_evidence_boundaries_have_distinct_behavior():
    generator = ScenarioGenerator(_config())
    runner = ExperimentRunner(_config())
    secret_case = generator._build_case(0, "data_access", ClaimType.SECRET_MISUSE)
    did_case = generator._build_case(1, "multi_agent", ClaimType.MALICIOUS_SUB_AGENT)
    sudp_verdict = build_baseline("sudp_secret_delegation").adjudicate(secret_case, runner.adjudicator).verdict
    did_verdict = build_baseline("agentdid_identity").adjudicate(did_case, runner.adjudicator).verdict
    receipt_verdict = build_baseline("signed_receipts").adjudicate(secret_case, runner.adjudicator).verdict
    assert sudp_verdict == Verdict.UNAUTHORIZED
    assert did_verdict == Verdict.UNAUTHORIZED
    assert receipt_verdict == Verdict.AUTHORIZED
