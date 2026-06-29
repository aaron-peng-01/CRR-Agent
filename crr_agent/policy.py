from __future__ import annotations

from .crypto import digest
from .types import PolicyDecision, Verdict, WorkflowNode


class PolicyEngine:
    def __init__(self, policy_config: dict, policy_version: str = "policy-v1"):
        self.config = policy_config
        self.policy_version = policy_version

    def evaluate(self, action: WorkflowNode, authority: WorkflowNode | None = None) -> PolicyDecision:
        payload = action.payload
        action_type = payload.get("action_type", "")
        reasons: list[str] = []
        verdict = Verdict.AUTHORIZED

        if payload.get("ambiguous", False):
            verdict = Verdict.AMBIGUOUS
            reasons.append("instruction_ambiguous")

        if action_type == "real_process_transition" and not payload.get("supported_terminal", True):
            verdict = Verdict.AMBIGUOUS
            reasons.append("process_conformance_ambiguous")

        terminal_activity = str(payload.get("terminal_activity", "")).strip().lower()
        unauthorized_real = {str(value).lower() for value in self.config.get("unauthorized_real_activities", [])}
        if action_type == "real_process_transition" and terminal_activity in unauthorized_real:
            verdict = Verdict.UNAUTHORIZED
            reasons.append(f"recorded_unauthorized_terminal:{terminal_activity}")

        if payload.get("uses_secret") in self.config.get("secret_labels", []):
            if not payload.get("secret_delegated", False):
                verdict = Verdict.UNAUTHORIZED
                reasons.append("secret_not_delegated")

        if action_type == "payment_execute":
            amount = float(payload.get("amount", 0))
            if amount > float(self.config.get("max_transfer_amount", 0)):
                verdict = Verdict.UNAUTHORIZED
                reasons.append("transfer_amount_exceeds_policy")

        if action_type == "purchase_order_submit":
            amount = float(payload.get("amount", 0))
            if amount > float(self.config.get("max_purchase_amount", 0)):
                verdict = Verdict.UNAUTHORIZED
                reasons.append("purchase_amount_exceeds_policy")

        if action_type == "email_send":
            domain = payload.get("recipient_domain")
            if domain not in set(self.config.get("allowed_email_domains", [])):
                verdict = Verdict.UNAUTHORIZED
                reasons.append("recipient_domain_not_allowed")

        if action_type == "data_export":
            export_mode = payload.get("export_mode")
            if export_mode not in set(self.config.get("allowed_data_exports", [])):
                verdict = Verdict.UNAUTHORIZED
                reasons.append("data_export_mode_not_allowed")

        if action_type in set(self.config.get("require_human_approval_for", [])):
            if not payload.get("human_approved", False):
                verdict = Verdict.UNAUTHORIZED
                reasons.append("missing_human_approval")

        if payload.get("tool_binding_ok") is False:
            verdict = Verdict.UNAUTHORIZED
            reasons.append("wrong_tool_binding")

        if payload.get("tool_poisoned") is True:
            verdict = Verdict.UNAUTHORIZED
            reasons.append("tool_poisoning_detected")

        if payload.get("policy_stale") is True:
            verdict = Verdict.UNAUTHORIZED
            reasons.append("stale_policy")

        if authority is not None:
            allowed_scope = set(authority.payload.get("allowed_scopes", []))
            required_scope = payload.get("required_scope")
            if required_scope and required_scope not in allowed_scope:
                verdict = Verdict.UNAUTHORIZED
                reasons.append("scope_not_authorized")

            allowed_delegatees = set(authority.payload.get("delegatees", []))
            if action.actor not in allowed_delegatees and action.actor != authority.actor:
                verdict = Verdict.UNAUTHORIZED
                reasons.append("actor_not_delegated")

        if not reasons:
            reasons.append("policy_allow")

        decision_id = digest({"action": action.node_id, "payload": payload, "version": self.policy_version})[:16]
        return PolicyDecision(
            decision_id=decision_id,
            action_id=action.node_id,
            verdict=verdict,
            reasons=reasons,
            input_digest=digest({"action": action.to_dict(), "authority": authority.to_dict() if authority else None}),
            policy_version=self.policy_version,
        )
