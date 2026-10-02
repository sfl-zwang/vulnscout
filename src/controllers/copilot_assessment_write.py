# Copyright (C) 2026 Savoir-faire Linux, Inc.
# SPDX-License-Identifier: GPL-3.0-only

"""Atomic pending AI assessment persistence for validated Copilot candidates."""

import hashlib
import json
from dataclasses import dataclass, replace
from uuid import UUID

from ..extensions import batch_session, db, write_lock
from ..models.assessment import Assessment
from ..models.assessment_review import fingerprint_assessment
from ..models.variant import Variant
from ..routes._assessment_write import (
    _replace_pending_ai, create_assessment_record, find_valid_finding, resolve_package,
)
from .copilot_assessment_contract import Candidate, CandidateError, Selection


class PendingConflict(ValueError):
    """Pending AI work changed after the replacement warning."""


@dataclass(frozen=True)
class PendingSnapshot:
    rows: tuple[tuple[str, str], ...]


def pending_snapshot(selection: Selection) -> PendingSnapshot:
    """Fingerprint full content and target membership of overlapping pending rows."""
    selected_variants = {target.variant_id for target in selection.targets}
    rows = []
    for row in Assessment.get_by_vulnerability(selection.vuln_id):
        if row.origin != "ai" or not any(
            target.variant_id in selected_variants for target in row.target_rows
        ):
            continue
        payload = (
            fingerprint_assessment(row),
            row.timestamp.isoformat() if row.timestamp else None,
            sorted((str(target.variant_id), str(target.finding_id))
                   for target in row.target_rows),
        )
        digest = hashlib.sha256(json.dumps(payload, separators=(",", ":")).encode()).hexdigest()
        rows.append((str(row.id), digest))
    return PendingSnapshot(tuple(sorted(rows)))


def exact_findings(selection: Selection, candidate: Candidate) -> list[tuple[UUID, UUID]]:
    """Re-resolve only the chosen pairs and refuse stale or foreign findings."""
    resolved = []
    for target in candidate.targets:
        variant = Variant.get_by_id(target.variant_id)
        if variant is None or variant.project_id != selection.project_id:
            raise CandidateError("Selected variant no longer belongs to the project")
        package = resolve_package(target.package)
        if package is None or package.string_id != target.package:
            raise CandidateError("Selected package no longer exists")
        finding = find_valid_finding(package.id, selection.vuln_id, target.variant_id)
        if finding is None:
            raise CandidateError("Selected package/CVE pair was not observed in this variant")
        resolved.append((target.variant_id, finding.id))
    return resolved


def dto_for(selection: Selection, candidate: Candidate) -> Assessment:
    """Copy validated model content to an unsaved assessment, including evidence."""
    if len(candidate.evidence) > 20 or any(
        not isinstance(ref, str) or not ref.strip() or len(ref) > 500
        or any(ord(char) < 32 or ord(char) == 127 for char in ref)
        for ref in candidate.evidence
    ):
        raise CandidateError("Evidence references must be single-line references (up to 20, 500 characters each)")
    if len(candidate.status_notes) > 10000:
        raise CandidateError("status_notes is too long")
    dto = Assessment.new_dto(selection.vuln_id, [target.package for target in candidate.targets])
    dto.status = candidate.status
    dto.justification = candidate.justification
    dto.status_notes = candidate.status_notes + "\n\nEvidence references:\n" + "\n".join(
        f"- {reference}" for reference in candidate.evidence
    )
    dto.impact_statement = candidate.impact_statement
    dto.workaround = candidate.workaround
    dto.responses = list(candidate.responses)
    return dto


def _content_key(candidate: Candidate) -> tuple:
    return (
        candidate.status, candidate.justification, candidate.status_notes,
        candidate.impact_statement, candidate.workaround, candidate.responses,
        candidate.confidence, candidate.evidence,
    )


def save_candidates(
    selection: Selection, candidates: list[Candidate], expected_snapshot: PendingSnapshot,
) -> list[str]:
    """Replace selected pending work and save all grouped verdicts in one transaction."""
    selected = {(target.variant_id, target.package) for target in selection.targets}
    produced = [(target.variant_id, target.package)
                for candidate in candidates for target in candidate.targets]
    if not selected or len(produced) != len(selected) or set(produced) != selected:
        raise CandidateError("Result must cover every selected finding exactly once")
    grouped: dict[tuple, list[Candidate]] = {}
    for candidate in candidates:
        grouped.setdefault(_content_key(candidate), []).append(candidate)
    groups = [
        replace(members[0], targets=tuple(
            target for candidate in members for target in candidate.targets
        ))
        for members in grouped.values()
    ]
    with write_lock():
        with batch_session():
            if db.engine.dialect.name == "sqlite":
                # Reserve the writer slot across processes before reading pending work.
                connection = db.session.connection()
                driver = connection.connection.driver_connection
                if driver is None or driver.in_transaction:
                    raise RuntimeError("Copilot save requires a fresh SQLite transaction")
                connection.exec_driver_sql("BEGIN IMMEDIATE")
            resolved = [(dto_for(selection, group), exact_findings(selection, group))
                        for group in groups]
            if pending_snapshot(selection) != expected_snapshot:
                raise PendingConflict("Pending AI work changed during assessment")
            _replace_pending_ai(selection.vuln_id, [target.variant_id for target in selection.targets])
            created = [create_assessment_record(dto, targets, origin="ai", commit=False)
                       for dto, targets in resolved]
            return [str(row.id) for row in created]
