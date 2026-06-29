from __future__ import annotations

import time

from .crypto import HMACSigner, digest
from .types import ActionReceipt, PolicyDecision, WorkflowNode


class ReceiptInstrumentor:
    def __init__(self, signer: HMACSigner):
        self.signer = signer

    def create_action_receipt(
        self,
        action: WorkflowNode,
        authority: WorkflowNode | None,
        instruction: WorkflowNode | None,
        predecessors: list[WorkflowNode],
        policy_decision: PolicyDecision,
        issued_at: float | None = None,
    ) -> ActionReceipt:
        receipt_id = digest({"action": action.node_id, "actor": action.actor, "payload": action.payload})[:20]
        payload = {
            "receipt_id": receipt_id,
            "action_id": action.node_id,
            "actor": action.actor,
            "authority_hash": digest(authority.to_dict()) if authority else digest(None),
            "instruction_hash": digest(instruction.to_dict()) if instruction else digest(None),
            "payload_digest": digest(action.payload),
            "predecessor_hash": digest([node.to_dict() for node in predecessors]),
            "policy_digest": digest(policy_decision.to_dict()),
            "issued_at": issued_at if issued_at is not None else time.time(),
        }
        signature = self.signer.sign(payload)
        return ActionReceipt(signature=signature, **payload)

    def verify(self, receipt: ActionReceipt) -> bool:
        return self.signer.verify(receipt.signed_payload(), receipt.signature)

    def verify_against_trace(
        self,
        receipt: ActionReceipt,
        action: WorkflowNode | None,
        authority: WorkflowNode | None,
        instruction: WorkflowNode | None,
        predecessors: list[WorkflowNode],
        policy_decision: PolicyDecision | None,
    ) -> tuple[bool, list[str]]:
        reasons: list[str] = []
        if not self.verify(receipt):
            reasons.append("receipt_signature_invalid")
        if action is None:
            reasons.append("receipt_action_missing")
            return False, reasons
        if receipt.action_id != action.node_id:
            reasons.append("receipt_action_id_mismatch")
        if receipt.actor != action.actor:
            reasons.append("receipt_actor_mismatch")
        if receipt.payload_digest != digest(action.payload):
            reasons.append("receipt_payload_digest_mismatch")
        if receipt.authority_hash != (digest(authority.to_dict()) if authority else digest(None)):
            reasons.append("receipt_authority_hash_mismatch")
        if receipt.instruction_hash != (digest(instruction.to_dict()) if instruction else digest(None)):
            reasons.append("receipt_instruction_hash_mismatch")
        if receipt.predecessor_hash != digest([node.to_dict() for node in predecessors]):
            reasons.append("receipt_predecessor_hash_mismatch")
        if receipt.policy_digest != (digest(policy_decision.to_dict()) if policy_decision else digest(None)):
            reasons.append("receipt_policy_digest_mismatch")
        return not reasons, reasons
