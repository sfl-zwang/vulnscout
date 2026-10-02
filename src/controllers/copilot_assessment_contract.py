# Copyright (C) 2026 Savoir-faire Linux, Inc.
# SPDX-License-Identifier: GPL-3.0-only

"""Read-only validation boundary for Copilot assessment selections and results."""

import json
from dataclasses import dataclass
from uuid import UUID

from ..models.assessment import (
    RESPONSES_CDX_VEX,
    VALID_JUSTIFICATION_CDX_VEX,
    VALID_JUSTIFICATION_OPENVEX,
    VALID_STATUS_OPENVEX,
)
from ..models.variant import Variant
from ..routes._assessment_write import find_valid_finding, resolve_package


class CandidateError(ValueError):
    """A safe, actionable scope or candidate validation failure."""


@dataclass(frozen=True)
class Target:
    variant_id: UUID
    package: str


@dataclass(frozen=True)
class Selection:
    project_id: UUID
    vuln_id: str
    targets: tuple[Target, ...]


@dataclass(frozen=True)
class Candidate:
    targets: tuple[Target, ...]
    status: str
    justification: str | None
    status_notes: str
    impact_statement: str | None
    workaround: str | None
    responses: tuple[str, ...]
    confidence: str
    evidence: tuple[str, ...]


def _fields(value: object, required: set[str], label: str) -> dict:
    if not isinstance(value, dict):
        raise CandidateError(f"{label} must be an object")
    missing = required - value.keys()
    extra = value.keys() - required
    if missing or extra:
        raise CandidateError(f"{label} has missing or unknown keys")
    return value


def _nonempty(value: object, label: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise CandidateError(f"{label} must be a non-empty string")
    return value


def _target(value: object) -> Target:
    data = _fields(value, {"variant_id", "package"}, "target")
    try:
        if not isinstance(data["variant_id"], str):
            raise ValueError
        variant_id = UUID(data["variant_id"])
    except (ValueError, AttributeError):
        raise CandidateError("target variant_id must be a UUID") from None
    return Target(variant_id, _nonempty(data["package"], "target package"))


def _targets(value: object) -> tuple[Target, ...]:
    if not isinstance(value, list) or not value:
        raise CandidateError("targets must be a non-empty list")
    targets = tuple(_target(item) for item in value)
    if len({target.variant_id for target in targets}) != len(targets):
        raise CandidateError("Select one package per variant")
    return targets


def _validate_observed(selection: Selection) -> None:
    for target in selection.targets:
        variant = Variant.get_by_id(target.variant_id)
        if variant is None:
            raise CandidateError("Selected variant no longer exists")
        if variant.project_id != selection.project_id:
            raise CandidateError("Selected variant belongs to a different project")
        package = resolve_package(target.package)
        if package is None or package.string_id != target.package:
            raise CandidateError("Selected package no longer exists")
        if find_valid_finding(package.id, selection.vuln_id, target.variant_id) is None:
            raise CandidateError("Selected package/CVE pair was not observed in this variant")


def parse_selection(project_id: str, vuln_id: str, targets: list[dict[str, str]]) -> Selection:
    """Resolve each selected variant/package/CVE against current or historical scans."""
    try:
        if not isinstance(project_id, str):
            raise ValueError
        project_uuid = UUID(project_id)
    except (ValueError, AttributeError):
        raise CandidateError("project_id must be a UUID") from None
    selection = Selection(project_uuid, _nonempty(vuln_id, "vuln_id").upper(), _targets(targets))
    _validate_observed(selection)
    return selection


_GROUP_FIELDS = {
    "targets", "status", "justification", "status_notes", "impact_statement",
    "workaround", "responses", "confidence", "evidence",
}


def _optional_text(value: object, label: str) -> str | None:
    if value is not None and (not isinstance(value, str) or not value.strip()):
        raise CandidateError(f"{label} must be a non-empty string or null")
    return value


def _strings(value: object, label: str, *, nonempty: bool = False) -> tuple[str, ...]:
    if not isinstance(value, list) or (nonempty and not value):
        raise CandidateError(f"{label} must be {'a non-empty' if nonempty else 'a'} list of strings")
    return tuple(_nonempty(item, label) for item in value)


def _candidate(raw_group: object) -> Candidate:
    data = _fields(raw_group, _GROUP_FIELDS, "group")
    targets = _targets(data["targets"])
    status = data["status"]
    if not isinstance(status, str) or status not in VALID_STATUS_OPENVEX:
        raise CandidateError("group status must be an allowed VEX status")
    justification = data["justification"]
    if status == "not_affected":
        if (not isinstance(justification, str) or justification not in
                (*VALID_JUSTIFICATION_OPENVEX, *VALID_JUSTIFICATION_CDX_VEX)):
            raise CandidateError("not_affected requires an allowed justification")
    elif justification is not None:
        raise CandidateError("justification is only applicable to not_affected")
    notes = _nonempty(data["status_notes"], "status_notes")
    impact = _optional_text(data["impact_statement"], "impact_statement")
    workaround = _optional_text(data["workaround"], "workaround")
    if justification in VALID_JUSTIFICATION_CDX_VEX and impact is None:
        raise CandidateError("CycloneDX justification requires impact_statement")
    responses = _strings(data["responses"], "responses")
    if any(response not in RESPONSES_CDX_VEX for response in responses):
        raise CandidateError("responses contains an unsupported VEX response")
    confidence = data["confidence"]
    if not isinstance(confidence, str) or confidence not in ("HIGH", "MEDIUM", "LOW"):
        raise CandidateError("confidence must be HIGH, MEDIUM, or LOW")
    if confidence == "LOW" and status != "under_investigation":
        raise CandidateError("LOW confidence requires under_investigation")
    evidence = _strings(data["evidence"], "evidence", nonempty=True)
    return Candidate(targets, status, justification, notes, impact, workaround,
                     responses, confidence, evidence)


def _unique_keys(pairs: list[tuple[str, object]]) -> dict:
    result = {}
    for key, value in pairs:
        if key in result:
            raise CandidateError("Candidate JSON has duplicate keys")
        result[key] = value
    return result


def parse_candidates(raw: str, selection: Selection) -> list[Candidate]:
    """Reject malformed or out-of-scope model output without making any writes."""
    if not isinstance(raw, str):
        raise CandidateError("Candidate output must be JSON text")
    try:
        document = json.loads(raw, object_pairs_hook=_unique_keys)
    except json.JSONDecodeError:
        raise CandidateError("Candidate output must be valid JSON") from None
    data = _fields(document, {"version", "groups"}, "result")
    if type(data["version"]) is not int or data["version"] != 1:
        raise CandidateError("Unsupported candidate version")
    if not isinstance(data["groups"], list) or not data["groups"]:
        raise CandidateError("groups must be a non-empty list")
    groups = [_candidate(item) for item in data["groups"]]
    selected = {(target.variant_id, target.package) for target in selection.targets}
    produced = [(target.variant_id, target.package)
                for group in groups for target in group.targets]
    if len(produced) != len(selected) or set(produced) != selected:
        raise CandidateError("Result must cover every selected finding exactly once")
    _validate_observed(selection)
    return groups
