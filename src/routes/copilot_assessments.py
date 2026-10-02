# Copyright (C) 2026 Savoir-faire Linux, Inc.
# SPDX-License-Identifier: GPL-3.0-only

"""Guarded start endpoint for scoped, pending Copilot assessments."""

import json
import uuid
from typing import cast

from flask import Flask, jsonify, request
from flask.typing import ResponseReturnValue

from ..controllers import copilot_settings
from ..controllers.copilot_assessment_contract import CandidateError, parse_selection
from ..controllers.copilot_assessment_runner import run_assessment
from ..controllers.copilot_assessment_write import pending_snapshot
from ..controllers.job_context import JobContext
from ..controllers.operation_queue import queue
from ..controllers.operation_registry import LANE_ASSESSMENT, registry
from ._agent_access import access_error


def init_app(app: Flask) -> None:
    @app.post("/api/copilot-assessments")
    def start_assessment() -> ResponseReturnValue:
        if error := access_error():
            return error
        body = request.get_json(silent=True)
        if not isinstance(body, dict) or set(body) - {
            "project_id", "vuln_id", "targets", "replace_pending",
        } or ("replace_pending" in body and type(body["replace_pending"]) is not bool):
            return jsonify(error="Invalid assessment request"), 400
        try:
            selection = parse_selection(
                cast(str, body.get("project_id")),
                cast(str, body.get("vuln_id")),
                cast(list[dict[str, str]], body.get("targets")),
            )
        except CandidateError as error:
            return jsonify(error=str(error)), 400

        readiness = copilot_settings.check_readiness()
        if not readiness["ready"]:
            return jsonify(error="Copilot assessment is not ready", errors=readiness["errors"]), 503
        model = copilot_settings.configured_model()
        snapshot = pending_snapshot(selection)
        if snapshot.rows and body.get("replace_pending") is not True:
            return jsonify(error="Existing pending AI assessments require replace_pending: true"), 409

        selection_key = json.dumps([
            selection.vuln_id,
            sorted((str(target.variant_id), target.package) for target in selection.targets),
        ], separators=(",", ":"))
        op_id = str(uuid.uuid4())
        if not registry.create_assessment_if_available(
            op_id, f"Assess {selection.vuln_id}", str(selection.project_id), selection_key,
        ):
            return jsonify(error="An assessment for this selection is already active"), 409
        queue.submit(
            op_id, LANE_ASSESSMENT,
            lambda ctx: run_assessment(ctx, selection, model, snapshot),
            JobContext(op_id),
        )
        return jsonify(op_id=op_id), 202
