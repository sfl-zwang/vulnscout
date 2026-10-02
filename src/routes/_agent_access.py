"""Shared local-only, opt-in access policy for Copilot endpoints."""

import os
from urllib.parse import urlsplit

from flask import jsonify, request


def access_error():
    if os.getenv("VULNSCOUT_AGENT_ENABLED") != "1":
        return jsonify(error="Agent chat is disabled on this server."), 404
    extra_clients = os.getenv("VULNSCOUT_AGENT_TRUSTED_CLIENTS", "").split(",")
    trusted = {"127.0.0.1", "::1"} | {value.strip() for value in extra_clients if value.strip()}
    if request.remote_addr not in trusted:
        return jsonify(error="Agent chat is available only on localhost."), 403
    if urlsplit(request.host_url).hostname not in ("127.0.0.1", "localhost", "::1"):
        return jsonify(error="Agent chat requires a localhost host."), 403
    origin = request.headers.get("Origin")
    if request.method != "GET" and origin and origin.rstrip("/") != request.host_url.rstrip("/"):
        return jsonify(error="Invalid request origin."), 403
    return None
