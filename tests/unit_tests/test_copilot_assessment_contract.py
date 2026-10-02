# Copyright (C) 2026 Savoir-faire Linux, Inc.
# SPDX-License-Identifier: GPL-3.0-only

"""Contract tests for exact, observed Copilot assessment targets."""

import json
import os
from dataclasses import FrozenInstanceError
from uuid import UUID, uuid4

import pytest

from src.controllers.copilot_assessment_contract import (
    CandidateError, parse_candidates, parse_selection,
)

VULN = "CVE-2026-1234"


@pytest.fixture()
def app():
    from src.bin.webapp import create_app
    from src.extensions import db

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


def observed_pair(project_id=None, variant_name="default", package_name="openssl",
                  vuln_id=VULN):
    from src.extensions import db
    from src.models.finding import Finding
    from src.models.observation import Observation
    from src.models.package import Package
    from src.models.scan import Scan
    from src.models.variant import Variant
    from src.models.vulnerability import Vulnerability

    project_id = project_id or uuid4()
    variant = Variant.create(name=variant_name, project_id=project_id)
    package = Package.create(name=package_name, version="3.0.0")
    if db.session.get(Vulnerability, vuln_id) is None:
        Vulnerability.create_record(id=vuln_id)
    finding = Finding.create(package.id, vuln_id)
    scan = Scan.create(description="observed scan", variant_id=variant.id)
    Observation.create(finding.id, scan.id)
    return {"project_id": str(project_id), "variant_id": str(variant.id),
            "package": package.string_id, "finding": finding, "scan": scan}


def target(pair):
    return {"variant_id": pair["variant_id"], "package": pair["package"]}


def group(*targets):
    return {
        "targets": list(targets), "status": "not_affected",
        "justification": "vulnerable_code_not_in_execute_path",
        "status_notes": "The affected code path is disabled.",
        "impact_statement": None, "workaround": None, "responses": [],
        "confidence": "HIGH", "evidence": [
            "https://nvd.nist.gov/vuln/detail/CVE-2026-1234"],
    }


def document(*groups):
    return json.dumps({"version": 1, "groups": list(groups)})


def test_selection_resolves_exact_observed_pair_and_is_immutable(app):
    pair = observed_pair()
    selection = parse_selection(pair["project_id"], VULN, [target(pair)])
    assert selection.project_id == UUID(pair["project_id"])
    assert selection.vuln_id == VULN
    assert selection.targets[0].package == pair["package"]
    with pytest.raises(FrozenInstanceError):
        selection.targets[0].package = "other"
    with pytest.raises(FrozenInstanceError):
        selection.targets = ()


def test_selection_accepts_historical_observation(app):
    pair = observed_pair()
    from src.models.scan import Scan
    Scan.create(description="newer scan without this finding",
                variant_id=pair["scan"].variant_id)
    selection = parse_selection(pair["project_id"], VULN, [target(pair)])
    assert selection.targets[0].package == pair["package"]
    assert parse_candidates(document(group(target(pair))), selection)[0].targets == selection.targets


@pytest.mark.parametrize("change,diagnostic", [
    ({"project_id": str(uuid4())}, "project"),
    ({"variant_id": str(uuid4())}, "variant"),
    ({"package": "unknown@3.0.0"}, "package"),
])
def test_selection_rejects_foreign_or_missing_targets(app, change, diagnostic):
    pair = observed_pair()
    payload = {**pair, **change}
    with pytest.raises(CandidateError, match=diagnostic):
        parse_selection(payload["project_id"], VULN, [target(payload)])


def test_selection_rejects_unobserved_pair_even_when_finding_exists(app):
    pair = observed_pair()
    other = observed_pair(project_id=pair["scan"].variant.project_id,
                          variant_name="other", package_name="zlib")
    with pytest.raises(CandidateError, match="observed"):
        parse_selection(pair["project_id"], VULN,
                        [{"variant_id": other["variant_id"], "package": pair["package"]}])


def test_selection_rejects_finding_for_another_cve(app):
    pair = observed_pair()
    with pytest.raises(CandidateError, match="observed"):
        parse_selection(pair["project_id"], "CVE-2026-9999", [target(pair)])


def test_selection_rejects_package_observed_only_for_a_different_cve(app):
    pair = observed_pair()
    other = observed_pair(project_id=pair["scan"].variant.project_id,
                          variant_name="other", package_name="zlib",
                          vuln_id="CVE-2026-9999")
    with pytest.raises(CandidateError, match="observed"):
        parse_selection(pair["project_id"], VULN, [target(other)])


def test_duplicate_variant_rejected(app):
    pair = observed_pair()
    with pytest.raises(CandidateError, match="one package per variant"):
        parse_selection(pair["project_id"], VULN, [target(pair)] * 2)


def test_two_observed_packages_in_one_variant_still_rejected(app):
    pair = observed_pair()
    other = observed_pair(project_id=pair["scan"].variant.project_id,
                          variant_name="other", package_name="zlib")
    from src.models.observation import Observation
    Observation.create(other["finding"].id, pair["scan"].id)
    with pytest.raises(CandidateError, match="one package per variant"):
        parse_selection(pair["project_id"], VULN, [
            target(pair), {"variant_id": pair["variant_id"], "package": other["package"]}])


@pytest.mark.parametrize("project,vuln,targets", [
    ("bad", VULN, []), (str(uuid4()), "", []),
    (str(uuid4()), VULN, []), (str(uuid4()), VULN, [{}]),
    (str(uuid4()), VULN, [{"variant_id": "bad", "package": "x@1"}]),
    (str(uuid4()), VULN, [{"variant_id": str(uuid4()), "package": " "}]),
    (str(uuid4()), VULN, [{"variant_id": str(uuid4()), "package": "x@1", "extra": 1}]),
])
def test_selection_rejects_malformed_scope(app, project, vuln, targets):
    with pytest.raises(CandidateError):
        parse_selection(project, vuln, targets)


def test_candidate_parses_frozen_fields(app):
    pair = observed_pair()
    selection = parse_selection(pair["project_id"], VULN, [target(pair)])
    candidates = parse_candidates(document(group(target(pair))), selection)
    assert len(candidates) == 1
    candidate = candidates[0]
    assert candidate.targets == selection.targets
    assert candidate.status == "not_affected"
    assert candidate.justification == "vulnerable_code_not_in_execute_path"
    assert candidate.responses == ()
    assert candidate.evidence == ("https://nvd.nist.gov/vuln/detail/CVE-2026-1234",)
    with pytest.raises(FrozenInstanceError):
        candidate.status = "affected"


def test_two_variants_may_share_same_package_in_one_group(app):
    pair = observed_pair()
    other_variant = observed_pair(project_id=pair["scan"].variant.project_id,
                                  variant_name="other", package_name="zlib")
    from src.models.observation import Observation
    Observation.create(pair["finding"].id, other_variant["scan"].id)
    other = {"variant_id": other_variant["variant_id"], "package": pair["package"]}
    selection = parse_selection(pair["project_id"], VULN, [target(pair), other])
    assert parse_candidates(document(group(target(pair), other)), selection)[0].targets == selection.targets


def test_different_groups_may_cover_different_variants(app):
    first = observed_pair()
    second = observed_pair(project_id=first["scan"].variant.project_id,
                           variant_name="second", package_name="zlib")
    selection = parse_selection(first["project_id"], VULN, [target(first), target(second)])
    groups = parse_candidates(document(group(target(first)), group(target(second))), selection)
    assert len(groups) == 2


@pytest.mark.parametrize("raw,diagnostic", [
    ("not json", "JSON"),
    ("[]", "object"),
    ('{"version": 2, "groups": []}', "version"),
    ('{"version": true, "groups": []}', "version"),
    ('{"version": 1, "groups": []}', "groups"),
    ('{"version": 1, "groups": [], "vuln_id": "CVE-1"}', "keys"),
])
def test_candidate_rejects_bad_document(app, raw, diagnostic):
    pair = observed_pair()
    selection = parse_selection(pair["project_id"], VULN, [target(pair)])
    with pytest.raises(CandidateError, match=diagnostic):
        parse_candidates(raw, selection)


def test_candidate_rejects_duplicate_json_keys(app):
    pair = observed_pair()
    selection = parse_selection(pair["project_id"], VULN, [target(pair)])
    raw = document(group(target(pair))).replace('"version": 1', '"version": 1, "version": 1')
    with pytest.raises(CandidateError, match="keys"):
        parse_candidates(raw, selection)


@pytest.mark.parametrize("changes,diagnostic", [
    ({"status": "false_positive"}, "status"),
    ({"justification": "invented"}, "justification"),
    ({"status": "affected", "justification": "code_not_present"}, "justification"),
    ({"status": "not_affected", "justification": None}, "justification"),
    ({"confidence": "LOW"}, "confidence"),
    ({"confidence": "medium"}, "confidence"),
    ({"evidence": []}, "evidence"),
    ({"evidence": [" "]}, "evidence"),
    ({"status_notes": ""}, "status_notes"),
    ({"impact_statement": 123}, "impact_statement"),
    ({"responses": ["bad"]}, "responses"),
    ({"responses": "update"}, "responses"),
    ({"evidence": "https://example.org/advisory"}, "evidence"),
    ({"targets": []}, "targets"),
    ({"targets": [{"variant_id": str(uuid4()), "package": "openssl@3.0.0",
                    "vuln_id": VULN}]}, "keys"),
    ({"ai_generated": True}, "keys"),
])
def test_candidate_rejects_invalid_group(app, changes, diagnostic):
    pair = observed_pair()
    selection = parse_selection(pair["project_id"], VULN, [target(pair)])
    payload = {**group(target(pair)), **changes}
    with pytest.raises(CandidateError, match=diagnostic):
        parse_candidates(document(payload), selection)


def test_under_investigation_low_confidence_accepted(app):
    pair = observed_pair()
    selection = parse_selection(pair["project_id"], VULN, [target(pair)])
    payload = {**group(target(pair)), "status": "under_investigation",
               "justification": None, "confidence": "LOW"}
    assert parse_candidates(document(payload), selection)[0].confidence == "LOW"


@pytest.mark.parametrize("status", ["affected", "fixed", "under_investigation"])
def test_non_not_affected_verdicts_need_no_justification(app, status):
    pair = observed_pair()
    selection = parse_selection(pair["project_id"], VULN, [target(pair)])
    payload = {**group(target(pair)), "status": status, "justification": None,
               "confidence": "MEDIUM"}
    assert parse_candidates(document(payload), selection)[0].status == status


def test_cyclonedx_justification_requires_impact_statement(app):
    pair = observed_pair()
    selection = parse_selection(pair["project_id"], VULN, [target(pair)])
    payload = {**group(target(pair)), "justification": "code_not_reachable"}
    with pytest.raises(CandidateError, match="impact_statement"):
        parse_candidates(document(payload), selection)
    payload["impact_statement"] = "Not reachable in this build"
    assert parse_candidates(document(payload), selection)[0].impact_statement == payload["impact_statement"]


@pytest.mark.parametrize("missing", list(group({"variant_id": str(uuid4()),
                                                  "package": "openssl@3.0.0"})))
def test_candidate_requires_every_group_field(app, missing):
    pair = observed_pair()
    selection = parse_selection(pair["project_id"], VULN, [target(pair)])
    payload = group(target(pair))
    del payload[missing]
    with pytest.raises(CandidateError, match="keys"):
        parse_candidates(document(payload), selection)


@pytest.mark.parametrize("replacement", [
    [], [{"variant_id": str(uuid4()), "package": "openssl@3.0.0"}],
    [{"variant_id": "not-uuid", "package": "openssl@3.0.0"}],
])
def test_candidate_rejects_missing_or_extra_target(app, replacement):
    pair = observed_pair()
    selection = parse_selection(pair["project_id"], VULN, [target(pair)])
    with pytest.raises(CandidateError):
        parse_candidates(document({**group(target(pair)), "targets": replacement}), selection)


def test_candidate_rejects_duplicate_pair_within_or_across_groups(app):
    pair = observed_pair()
    selection = parse_selection(pair["project_id"], VULN, [target(pair)])
    for groups in (document(group(target(pair), target(pair))),
                   document(group(target(pair)), group(target(pair)))):
        with pytest.raises(CandidateError, match="exactly once|one package per variant"):
            parse_candidates(groups, selection)


def test_candidate_does_not_write_or_resolve_newly_unobserved_pair(app):
    from src.extensions import db
    from src.models.observation import Observation
    pair = observed_pair()
    selection = parse_selection(pair["project_id"], VULN, [target(pair)])
    for observation in Observation.get_by_finding(pair["finding"].id):
        db.session.delete(observation)
    db.session.commit()
    with pytest.raises(CandidateError, match="observed"):
        parse_candidates(document(group(target(pair))), selection)
