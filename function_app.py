"""Azure Functions adapter for the deterministic CAE intervention engine."""

from __future__ import annotations

import datetime as dt
import json
import logging
import os
import sys
import urllib.error
import urllib.request
from dataclasses import asdict
from pathlib import Path

import azure.functions as func
from azure.identity import ManagedIdentityCredential

sys.path.insert(0, str(Path(__file__).parent / "src"))
from enforcer import decide, load, policy_from  # noqa: E402

GRAPH_SCOPE = "https://graph.microsoft.com/.default"
STORAGE_SCOPE = "https://storage.azure.com/.default"
GRAPH_PERMISSION = "User.RevokeSessions.All"

app = func.FunctionApp()
credential = ManagedIdentityCredential()
policy = policy_from(load(Path(os.environ.get("POLICY_PATH", "config/policy.json"))))


def _request(url: str, token: str, method: str, body: bytes, headers: dict[str, str]):
    request = urllib.request.Request(
        url,
        data=body,
        method=method,
        headers={"Authorization": f"Bearer {token}", **headers},
    )
    return urllib.request.urlopen(request, timeout=15)


def revoke_sessions(user_id: str) -> str:
    token = credential.get_token(GRAPH_SCOPE).token
    url = f"https://graph.microsoft.com/v1.0/users/{user_id}/revokeSignInSessions"
    with _request(url, token, "POST", b"", {"Content-Length": "0"}) as response:
        if response.status not in (200, 204):
            raise RuntimeError(f"Graph returned status {response.status}")
    return "graph_accepted"


def write_audit(event_id: str, evidence: dict) -> str:
    account = os.environ["AUDIT_STORAGE_ACCOUNT"]
    body = json.dumps(evidence, sort_keys=True, separators=(",", ":")).encode()
    token = credential.get_token(STORAGE_SCOPE).token
    now = dt.datetime.now(dt.timezone.utc).strftime("%a, %d %b %Y %H:%M:%S GMT")
    url = f"https://{account}.blob.core.windows.net/audit/{event_id}.json"
    try:
        with _request(
            url,
            token,
            "PUT",
            body,
            {
                "Content-Length": str(len(body)),
                "Content-Type": "application/json",
                "If-None-Match": "*",
                "x-ms-blob-type": "BlockBlob",
                "x-ms-date": now,
                "x-ms-version": "2023-11-03",
            },
        ) as response:
            return f"blob_{response.status}"
    except urllib.error.HTTPError as exc:
        if exc.code in (409, 412):
            return "blob_duplicate"
        raise


@app.event_grid_trigger(arg_name="event")
def risk_event(event: func.EventGridEvent) -> None:
    raw = event.get_json()
    current = dt.datetime.now(dt.timezone.utc)
    decision = decide(raw, policy, current)
    action_status = "not_executed"
    if decision.action == "revoke_sessions":
        action_status = revoke_sessions(raw["userId"])
    elif decision.action == "require_step_up":
        action_status = "awaiting_preconfigured_ca_integration"
    evidence = {
        "decision": asdict(decision),
        "action_status": action_status,
        "graph_permission": GRAPH_PERMISSION if decision.action == "revoke_sessions" else None,
    }
    audit_status = write_audit(decision.event_id, evidence)
    logging.info(
        "decision_id=%s action=%s audit=%s",
        decision.decision_id,
        decision.action,
        audit_status,
    )
