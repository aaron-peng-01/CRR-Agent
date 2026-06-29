from __future__ import annotations

import gzip
import hashlib
import json
import xml.etree.ElementTree as ET
from collections import Counter
from dataclasses import dataclass
from pathlib import Path
from typing import Iterator


@dataclass(frozen=True)
class RealEvent:
    index: int
    activity: str
    timestamp: str
    resource: str
    attributes: dict[str, str]


@dataclass(frozen=True)
class RealProcessCase:
    dataset_id: str
    case_id: str
    attributes: dict[str, str]
    events: list[RealEvent]


def iter_xes_cases(path: str | Path, dataset_id: str) -> Iterator[RealProcessCase]:
    path = Path(path)
    opener = gzip.open if path.suffix.lower() == ".gz" else open
    with opener(path, "rb") as stream:
        for _, elem in ET.iterparse(stream, events=("end",)):
            if _local_name(elem.tag) != "trace":
                continue
            trace_attrs: dict[str, str] = {}
            events: list[RealEvent] = []
            for child in elem:
                if _local_name(child.tag) == "event":
                    attrs = _attributes(child)
                    events.append(
                        RealEvent(
                            index=len(events),
                            activity=attrs.get("concept:name", "unknown"),
                            timestamp=attrs.get("time:timestamp", ""),
                            resource=attrs.get("org:resource", "unknown"),
                            attributes=attrs,
                        )
                    )
                elif "key" in child.attrib:
                    trace_attrs[child.attrib["key"]] = child.attrib.get("value", "")
            case_id = trace_attrs.get("concept:name") or trace_attrs.get("case:concept:name")
            if case_id and events:
                yield RealProcessCase(dataset_id, case_id, trace_attrs, events)
            elem.clear()


def stable_split(dataset_id: str, case_id: str) -> str:
    value = int(hashlib.sha256(f"{dataset_id}:{case_id}".encode("utf-8")).hexdigest()[:8], 16) % 100
    return "validation" if value < 10 else "test"


def audit_xes(path: str | Path, dataset_id: str, max_cases: int | None = None) -> dict:
    activities: Counter[str] = Counter()
    event_attributes: Counter[str] = Counter()
    trace_attributes: Counter[str] = Counter()
    resources: Counter[str] = Counter()
    event_counts: list[int] = []
    split_counts: Counter[str] = Counter()
    for index, case in enumerate(iter_xes_cases(path, dataset_id)):
        if max_cases is not None and index >= max_cases:
            break
        trace_attributes.update(case.attributes.keys())
        event_counts.append(len(case.events))
        split_counts[stable_split(dataset_id, case.case_id)] += 1
        for event in case.events:
            activities[event.activity] += 1
            resources[event.resource] += 1
            event_attributes.update(event.attributes.keys())
    return {
        "dataset_id": dataset_id,
        "cases": len(event_counts),
        "events": sum(event_counts),
        "min_events_per_case": min(event_counts) if event_counts else 0,
        "max_events_per_case": max(event_counts) if event_counts else 0,
        "mean_events_per_case": (sum(event_counts) / len(event_counts)) if event_counts else 0.0,
        "split_counts": dict(split_counts),
        "activities": dict(activities.most_common()),
        "event_attributes": dict(event_attributes.most_common()),
        "trace_attributes": dict(trace_attributes.most_common()),
        "resource_count": len(resources),
    }


def load_dataset_manifest(path: str | Path) -> dict[str, dict]:
    data = json.loads(Path(path).read_text(encoding="utf-8"))
    return {entry["id"]: entry for entry in data["datasets"]}


def _attributes(element: ET.Element) -> dict[str, str]:
    return {
        child.attrib["key"]: child.attrib.get("value", "")
        for child in element
        if "key" in child.attrib
    }


def _local_name(tag: str) -> str:
    return tag.rsplit("}", 1)[-1]
