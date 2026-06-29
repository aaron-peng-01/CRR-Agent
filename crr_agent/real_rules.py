from __future__ import annotations

from dataclasses import dataclass

from .real_data import RealProcessCase
from .types import Verdict


@dataclass(frozen=True)
class ConformanceFinding:
    verdict: Verdict
    rule_id: str
    rationale: str
    side_effect_activity: str
    evidence_event_indices: list[int]


def evaluate_real_case(case: RealProcessCase) -> ConformanceFinding:
    if case.dataset_id == "bpi2017":
        return evaluate_bpi2017(case)
    if case.dataset_id == "bpi2019":
        return evaluate_bpi2019(case)
    return ConformanceFinding(Verdict.AMBIGUOUS, "unsupported_dataset", "No frozen rule set", case.events[-1].activity, [])


def evaluate_bpi2017(case: RealProcessCase) -> ConformanceFinding:
    activities = [event.activity for event in case.events]
    pending = _first_index(activities, "A_Pending")
    denied = _first_index(activities, "A_Denied")
    cancelled = _first_index(activities, "A_Cancelled")
    adverse = [idx for idx in [denied, cancelled] if idx is not None]
    if adverse:
        terminal = min(adverse)
        return ConformanceFinding(
            Verdict.UNAUTHORIZED,
            "bpi2017_recorded_adverse_terminal",
            "The real process recorded a denied or cancelled terminal application outcome",
            activities[terminal],
            [terminal],
        )
    if pending is not None:
        return ConformanceFinding(
            Verdict.AUTHORIZED,
            "bpi2017_recorded_pending_terminal",
            "The real process recorded a pending terminal application outcome",
            activities[pending],
            [pending],
        )
    return ConformanceFinding(
        Verdict.AMBIGUOUS,
        "bpi2017_no_supported_terminal",
        "Trace has no supported terminal application state",
        activities[-1],
        [len(activities) - 1],
    )


def evaluate_bpi2019(case: RealProcessCase) -> ConformanceFinding:
    activities = [event.activity.lower() for event in case.events]
    invoice_indices = [i for i, name in enumerate(activities) if "invoice" in name]
    goods_indices = [i for i, name in enumerate(activities) if "goods receipt" in name or "record goods" in name]
    clear_indices = [i for i, name in enumerate(activities) if "clear invoice" in name or "payment" in name]

    reversal_markers = {
        "delete purchase order item",
        "cancel invoice receipt",
        "cancel goods receipt",
        "cancel subsequent invoice",
        "block purchase order item",
        "set payment block",
        "reactivate purchase order item",
        "srm: transfer failed (e.sys.)",
        "srm: deleted",
        "srm: incomplete",
        "srm: held",
        "change rejection indicator",
    }
    reversal_indices = [i for i, name in enumerate(activities) if name in reversal_markers]

    if reversal_indices:
        index = reversal_indices[0]
        return ConformanceFinding(
            Verdict.UNAUTHORIZED,
            "bpi2019_recorded_reversal_block_or_failure",
            "The real process contains a cancellation, deletion, block, reactivation, rejection, or transfer-failure event",
            case.events[index].activity,
            [index],
        )
    terminal = clear_indices[-1] if clear_indices else len(case.events) - 1
    return ConformanceFinding(
        Verdict.AUTHORIZED,
        "bpi2019_recorded_ordering_conformant",
        "Observed ordering is consistent with the frozen invoice/goods-receipt rules",
        case.events[terminal].activity,
        ([goods_indices[0]] if goods_indices else []) + ([invoice_indices[0]] if invoice_indices else []) + [terminal],
    )


def _first_index(values: list[str], target: str) -> int | None:
    try:
        return values.index(target)
    except ValueError:
        return None
