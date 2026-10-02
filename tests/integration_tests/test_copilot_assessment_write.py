# Copyright (C) 2026 Savoir-faire Linux, Inc.
# SPDX-License-Identifier: GPL-3.0-only

"""Atomic persistence of exact Copilot assessment candidates."""

import json
import os
from uuid import uuid4

import pytest

from src.controllers.copilot_assessment_contract import CandidateError, parse_candidates, parse_selection
from src.controllers.copilot_assessment_write import PendingConflict, pending_snapshot, save_candidates
from src.extensions import db
from src.models.assessment import Assessment
from src.models.finding import Finding
from src.models.observation import Observation
from src.models.package import Package
from src.models.scan import Scan
from src.models.variant import Variant
from src.models.vulnerability import Vulnerability

VULN = "CVE-2026-1234"
EVIDENCE = "https://nvd.nist.gov/vuln/detail/CVE-2026-1234"


@pytest.fixture()
def app():
    from src.bin.webapp import create_app

    os.environ["FLASK_SQLALCHEMY_DATABASE_URI"] = "sqlite:///:memory:"
    try:
        application = create_app()
        application.config.update(TESTING=True, SCAN_FILE="/dev/null")
        with application.app_context():
            db.create_all()
            yield application
            db.drop_all()
    finally:
        os.environ.pop("FLASK_SQLALCHEMY_DATABASE_URI", None)


def observed(project_id, name):
    variant = Variant.create(name=name, project_id=project_id)
    package = Package.create(name=name, version="1.0")
    if db.session.get(Vulnerability, VULN) is None:
        Vulnerability.create_record(id=VULN)
    finding = Finding.create(package.id, VULN)
    scan = Scan.create(description="observed", variant_id=variant.id)
    Observation.create(finding.id, scan.id)
    return variant, package, finding


def selection_for(project_id, *pairs):
    return parse_selection(str(project_id), VULN, [
        {"variant_id": str(variant.id), "package": package.string_id}
        for variant, package, _ in pairs
    ])


def group(*pairs, status="affected", notes="Reviewed the vulnerable path"):
    return {
        "targets": [{"variant_id": str(variant.id), "package": package.string_id}
                    for variant, package, _ in pairs],
        "status": status, "justification": None, "status_notes": notes,
        "impact_statement": None, "workaround": None, "responses": [],
        "confidence": "HIGH", "evidence": [EVIDENCE],
    }


def candidates(selection, *groups):
    return parse_candidates(json.dumps({"version": 1, "groups": list(groups)}), selection)


def ai_rows():
    return [row for row in Assessment.get_by_vulnerability(VULN) if row.origin == "ai"]


def test_identical_verdict_and_content_share_one_row_with_exact_targets(app):
    project = uuid4()
    a, b = observed(project, "openssl"), observed(project, "zlib")
    selection = selection_for(project, a, b)
    created = save_candidates(selection, candidates(selection, group(a), group(b)),
                              pending_snapshot(selection))
    assert len(created) == 1
    assert {str(t.variant_id) for t in ai_rows()[0].target_rows} == {str(a[0].id), str(b[0].id)}
    assert {t.finding_id for t in ai_rows()[0].target_rows} == {a[2].id, b[2].id}
    assert EVIDENCE in ai_rows()[0].status_notes


def test_different_verdicts_replace_only_selected_variants_and_preserve_custom(app):
    project = uuid4()
    a, b, c = (observed(project, name) for name in ("openssl", "zlib", "curl"))
    old = Assessment.create(status="affected", targets=[(a[0].id, a[2].id),
                            (c[0].id, c[2].id)], origin="ai")
    custom = Assessment.create(status="fixed", targets=[(b[0].id, b[2].id)], origin="custom")
    selection = selection_for(project, a, b)
    created = save_candidates(selection, candidates(selection, group(a), group(b, status="fixed")),
                              pending_snapshot(selection))
    assert len(created) == 2
    assert {str(t.variant_id) for t in Assessment.get_by_id(old.id).target_rows} == {str(c[0].id)}
    assert Assessment.get_by_id(custom.id).origin == "custom"
    assert {row.status: {t.variant_id for t in row.target_rows} for row in ai_rows()
            if str(row.id) in created} == {"affected": {a[0].id}, "fixed": {b[0].id}}


def test_overlapping_single_variant_pending_is_deleted_but_unselected_pending_survives(app):
    project = uuid4()
    a, b = observed(project, "openssl"), observed(project, "zlib")
    replaced = Assessment.create(status="affected", targets=[(a[0].id, a[2].id)], origin="ai")
    untouched = Assessment.create(status="affected", targets=[(b[0].id, b[2].id)], origin="ai")
    selection = selection_for(project, a)
    created = save_candidates(selection, candidates(selection, group(a, status="fixed")),
                              pending_snapshot(selection))
    assert Assessment.get_by_id(replaced.id) is None
    assert {str(row.id) for row in ai_rows()} == {str(untouched.id), *created}


def test_changed_pending_content_or_membership_conflicts_without_writing(app):
    project = uuid4()
    a, b = observed(project, "openssl"), observed(project, "zlib")
    old = Assessment.create(status="affected", targets=[(a[0].id, a[2].id),
                            (b[0].id, b[2].id)], origin="ai")
    selection = selection_for(project, a)
    before = pending_snapshot(selection)
    old.update(status_notes="Human work since the warning")
    with pytest.raises(PendingConflict):
        save_candidates(selection, candidates(selection, group(a)), before)
    assert pending_snapshot(selection) != before
    before = pending_snapshot(selection)
    old.target_rows.remove(next(t for t in old.target_rows if t.variant_id == b[0].id))
    db.session.commit()
    with pytest.raises(PendingConflict):
        save_candidates(selection, candidates(selection, group(a)), before)
    assert {str(row.id) for row in ai_rows()} == {str(old.id)}


def test_new_pending_row_since_warning_conflicts(app):
    project = uuid4()
    a = observed(project, "openssl")
    selection = selection_for(project, a)
    before = pending_snapshot(selection)
    new = Assessment.create(status="affected", targets=[(a[0].id, a[2].id)], origin="ai")
    with pytest.raises(PendingConflict):
        save_candidates(selection, candidates(selection, group(a)), before)
    assert {str(row.id) for row in ai_rows()} == {str(new.id)}


def test_second_group_failure_rolls_back_first_creation_and_replacement(app, monkeypatch):
    from src.controllers import copilot_assessment_write as writer

    project = uuid4()
    a, b = observed(project, "openssl"), observed(project, "zlib")
    old = Assessment.create(status="affected", targets=[(a[0].id, a[2].id)], origin="ai")
    selection = selection_for(project, a, b)
    before = pending_snapshot(selection)
    create = writer.create_assessment_record
    calls = 0

    def fail_second(*args, **kwargs):
        nonlocal calls
        calls += 1
        if calls == 2:
            raise RuntimeError("second group failed")
        return create(*args, **kwargs)

    monkeypatch.setattr(writer, "create_assessment_record", fail_second)
    parsed = candidates(selection, group(a), group(b, status="fixed"))
    with pytest.raises(RuntimeError, match="second group failed"):
        save_candidates(selection, parsed, before)
    assert {str(row.id) for row in ai_rows()} == {str(old.id)}
    assert pending_snapshot(selection) == before


def test_stale_exact_pair_blocks_all_writes(app):
    project = uuid4()
    a, b = observed(project, "openssl"), observed(project, "zlib")
    selection = selection_for(project, a, b)
    parsed = candidates(selection, group(a), group(b, status="fixed"))
    db.session.delete(b[2])
    db.session.commit()
    with pytest.raises(CandidateError, match="observed"):
        save_candidates(selection, parsed, pending_snapshot(selection))
    assert ai_rows() == []
