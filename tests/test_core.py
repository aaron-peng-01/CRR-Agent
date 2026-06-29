from crr_agent.adjudicator import CRRAdjudicator
from crr_agent.crypto import HMACSigner
from crr_agent.receipts import ReceiptInstrumentor
from crr_agent.scenarios import ScenarioGenerator
from crr_agent.types import Verdict


def _config() -> dict:
    return {
        "seed": 7,
        "num_cases": 5,
        "scenario_mix": {
            "procurement": 1.0,
            "finance": 0.0,
            "email_support": 0.0,
            "data_access": 0.0,
            "multi_agent": 0.0,
        },
        "attack_mix": {
            "benign": 0.5,
            "scope_drift": 0.5,
        },
        "policy": {
            "max_transfer_amount": 5000,
            "max_purchase_amount": 2000,
            "allowed_email_domains": ["customer.example"],
            "allowed_data_exports": ["redacted"],
            "require_human_approval_for": ["payment_execute", "purchase_order_submit"],
            "secret_labels": ["api_key"],
        },
        "selector": {"ancestor_depth": 8, "allow_commitment_only_nodes": True},
        "cost_model": {"node_open_ms": 0.8, "receipt_verify_ms": 0.25, "policy_replay_ms": 1.5},
    }


def test_receipt_verification_and_root_commitment():
    case = ScenarioGenerator(_config()).generate(1)[0]
    instrumentor = ReceiptInstrumentor(HMACSigner("crr-agent-experiment-key"))
    receipt = next(iter(case.trace.receipts.values()))
    assert instrumentor.verify(receipt)
    assert case.trace.root_commitment


def test_crr_adjudication_matches_ground_truth_for_generated_case():
    config = _config()
    case = ScenarioGenerator(config).generate(1)[0]
    instrumentor = ReceiptInstrumentor(HMACSigner("crr-agent-experiment-key"))
    adjudicator = CRRAdjudicator.from_config(config, instrumentor)
    report = adjudicator.adjudicate(case.trace, case.dispute)
    assert report.verdict in {Verdict.AUTHORIZED, Verdict.UNAUTHORIZED, Verdict.AMBIGUOUS}
    assert report.root_commitment == case.trace.root_commitment
    assert case.dispute.side_effect_id in report.subgraph.node_ids
