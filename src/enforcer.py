#!/usr/bin/env python3
"""Deterministic, explainable Entra risk intervention engine."""

from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import json
import sqlite3
import uuid
from dataclasses import dataclass, asdict
from pathlib import Path
from typing import Any


class EnforcerError(ValueError):
    """Policy, event, idempotency, or audit evidence is invalid."""


def canonical(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def canonical_uuid(raw: str, field: str) -> str:
    try:
        value = str(uuid.UUID(str(raw)))
    except (ValueError, AttributeError) as exc:
        raise EnforcerError(f"{field} must be a UUID") from exc
    if str(raw).lower() != value:
        raise EnforcerError(f"{field} must use canonical UUID form")
    return value


def parse_time(raw: str, field: str) -> dt.datetime:
    try:
        value = dt.datetime.fromisoformat(str(raw).replace("Z", "+00:00"))
    except ValueError as exc:
        raise EnforcerError(f"{field} must be ISO-8601") from exc
    if value.tzinfo is None:
        raise EnforcerError(f"{field} requires timezone")
    return value.astimezone(dt.timezone.utc)


def load(path: Path) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise EnforcerError(f"cannot load {path}: {exc}") from exc


@dataclass(frozen=True)
class Policy:
    tenant_id: str
    max_event_age_seconds: int
    future_skew_seconds: int
    revoke_threshold: int
    step_up_threshold: int
    min_signal_domains: int
    signals: dict[str, dict[str, Any]]
    break_glass_users: frozenset[str]


@dataclass(frozen=True)
class Decision:
    decision_id: str
    event_id: str
    subject_ref: str
    action: str
    score: int
    signal_domains: tuple[str, ...]
    reasons: tuple[str, ...]
    evaluated_at: str
    manual_follow_up: bool


def policy_from(value: dict[str, Any]) -> Policy:
    if not isinstance(value, dict) or value.get("schemaVersion") != "1.0":
        raise EnforcerError("unsupported policy schemaVersion")
    tenant = canonical_uuid(value.get("tenantId", ""), "policy.tenantId")
    thresholds = value.get("thresholds", {})
    for field in (
        "maxEventAgeSeconds",
        "futureSkewSeconds",
        "revokeScore",
        "stepUpScore",
        "minSignalDomains",
    ):
        if not isinstance(thresholds.get(field), int):
            raise EnforcerError(f"threshold {field} must be an integer")
    if not (
        30 <= thresholds["maxEventAgeSeconds"] <= 3600
        and 0 <= thresholds["futureSkewSeconds"] <= 300
        and 1 <= thresholds["stepUpScore"] < thresholds["revokeScore"] <= 100
        and 1 <= thresholds["minSignalDomains"] <= 3
    ):
        raise EnforcerError("policy thresholds are unsafe")
    signals = value.get("signals")
    if not isinstance(signals, dict) or not signals:
        raise EnforcerError("policy signals must be non-empty")
    for name, definition in signals.items():
        if (
            not name.replace("_", "").isalnum()
            or not isinstance(definition, dict)
            or definition.get("domain") not in {"identity", "device", "network"}
            or not isinstance(definition.get("weight"), int)
            or not 1 <= definition["weight"] <= 50
        ):
            raise EnforcerError(f"invalid signal definition: {name}")
    break_glass = frozenset(
        canonical_uuid(item, "breakGlassUserIds") for item in value.get("breakGlassUserIds", [])
    )
    if not break_glass:
        raise EnforcerError("at least one break-glass identity is required")
    return Policy(
        tenant,
        thresholds["maxEventAgeSeconds"],
        thresholds["futureSkewSeconds"],
        thresholds["revokeScore"],
        thresholds["stepUpScore"],
        thresholds["minSignalDomains"],
        signals,
        break_glass,
    )


def validate_event(
    raw: dict[str, Any], policy: Policy, now: dt.datetime
) -> dict[str, Any]:
    required = {
        "id",
        "type",
        "tenantId",
        "userId",
        "occurredAt",
        "riskLevel",
        "signals",
        "correlationId",
    }
    if not isinstance(raw, dict) or required - raw.keys():
        raise EnforcerError("event is incomplete")
    if raw["type"] != "risk.signal.v1":
        raise EnforcerError("unsupported event type")
    event = dict(raw)
    event["id"] = canonical_uuid(raw["id"], "event.id")
    event["tenantId"] = canonical_uuid(raw["tenantId"], "event.tenantId")
    event["userId"] = canonical_uuid(raw["userId"], "event.userId")
    if event["tenantId"] != policy.tenant_id:
        raise EnforcerError("cross-tenant event rejected")
    occurred = parse_time(raw["occurredAt"], "event.occurredAt")
    current = now.astimezone(dt.timezone.utc)
    if occurred > current + dt.timedelta(seconds=policy.future_skew_seconds):
        raise EnforcerError("event timestamp is too far in the future")
    if raw["riskLevel"] not in {"low", "medium", "high"}:
        raise EnforcerError("unsupported riskLevel")
    signals = raw["signals"]
    if (
        not isinstance(signals, list)
        or not signals
        or len(signals) != len(set(signals))
        or any(item not in policy.signals for item in signals)
    ):
        raise EnforcerError("signals must be unique known values")
    correlation = str(raw["correlationId"])
    if not 1 <= len(correlation) <= 128 or any(ord(char) < 32 for char in correlation):
        raise EnforcerError("correlationId is invalid")
    event["_occurred"] = occurred
    return event


def decide(raw: dict[str, Any], policy: Policy, now: dt.datetime) -> Decision:
    event = validate_event(raw, policy, now)
    current = now.astimezone(dt.timezone.utc)
    subject = hashlib.sha256(
        f"{event['tenantId']}:{event['userId']}".encode("ascii")
    ).hexdigest()[:24]
    score = sum(policy.signals[name]["weight"] for name in event["signals"])
    domains = tuple(sorted({policy.signals[name]["domain"] for name in event["signals"]}))
    reasons = [f"risk_level={event['riskLevel']}", f"signal_score={score}"]
    age = (current - event["_occurred"]).total_seconds()
    manual = False
    if event["userId"] in policy.break_glass_users:
        action = "break_glass_noop"
        reasons.append("break_glass_identity_requires_human_response")
        manual = True
    elif age > policy.max_event_age_seconds:
        action = "quarantine_stale"
        reasons.append("event_exceeded_freshness_window")
        manual = True
    elif (
        event["riskLevel"] == "high"
        and score >= policy.revoke_threshold
        and len(domains) >= policy.min_signal_domains
    ):
        action = "revoke_sessions"
        reasons.append("high_confidence_multi_domain_threshold_met")
    elif score >= policy.step_up_threshold:
        action = "require_step_up"
        reasons.append("step_up_threshold_met_but_revoke_threshold_not_met")
        manual = True
    else:
        action = "monitor"
        reasons.append("intervention_threshold_not_met")
    decision_id = str(uuid.uuid5(uuid.NAMESPACE_URL, f"cae-enforcer:{event['id']}"))
    return Decision(
        decision_id,
        event["id"],
        subject,
        action,
        score,
        domains,
        tuple(reasons),
        current.isoformat().replace("+00:00", "Z"),
        manual,
    )


class AuditStore:
    """SQLite idempotency and hash-chain evidence for local/replay operation."""

    def __init__(self, path: Path) -> None:
        self.connection = sqlite3.connect(path)
        self.connection.execute(
            """
            CREATE TABLE IF NOT EXISTS decisions (
                sequence INTEGER PRIMARY KEY AUTOINCREMENT,
                event_id TEXT NOT NULL UNIQUE,
                payload_hash TEXT NOT NULL,
                decision_json TEXT NOT NULL,
                previous_hash TEXT NOT NULL,
                chain_hash TEXT NOT NULL UNIQUE
            )
            """
        )
        self.connection.commit()

    def record(
        self, event: dict[str, Any], decision: Decision
    ) -> tuple[Decision, bool]:
        clean_event = {key: value for key, value in event.items() if not key.startswith("_")}
        payload_hash = hashlib.sha256(canonical(clean_event).encode()).hexdigest()
        decision_json = canonical(asdict(decision))
        with self.connection:
            existing = self.connection.execute(
                "SELECT payload_hash, decision_json FROM decisions WHERE event_id = ?",
                (decision.event_id,),
            ).fetchone()
            if existing:
                if existing[0] != payload_hash:
                    raise EnforcerError("event ID collision with different payload")
                return Decision(**json.loads(existing[1])), True
            previous = self.connection.execute(
                "SELECT chain_hash FROM decisions ORDER BY sequence DESC LIMIT 1"
            ).fetchone()
            previous_hash = previous[0] if previous else "0" * 64
            chain_hash = hashlib.sha256(
                f"{previous_hash}:{payload_hash}:{decision_json}".encode()
            ).hexdigest()
            self.connection.execute(
                """
                INSERT INTO decisions
                (event_id, payload_hash, decision_json, previous_hash, chain_hash)
                VALUES (?, ?, ?, ?, ?)
                """,
                (
                    decision.event_id,
                    payload_hash,
                    decision_json,
                    previous_hash,
                    chain_hash,
                ),
            )
        return decision, False

    def evidence(self) -> list[dict[str, Any]]:
        rows = self.connection.execute(
            """
            SELECT sequence, event_id, payload_hash, decision_json,
                   previous_hash, chain_hash
            FROM decisions ORDER BY sequence
            """
        )
        return [
            {
                "sequence": row[0],
                "event_id": row[1],
                "payload_hash": row[2],
                "decision": json.loads(row[3]),
                "previous_hash": row[4],
                "chain_hash": row[5],
            }
            for row in rows
        ]

    def verify(self) -> None:
        previous = "0" * 64
        for item in self.evidence():
            decision_json = canonical(item["decision"])
            expected = hashlib.sha256(
                f"{previous}:{item['payload_hash']}:{decision_json}".encode()
            ).hexdigest()
            if item["previous_hash"] != previous or item["chain_hash"] != expected:
                raise EnforcerError(f"audit chain invalid at sequence {item['sequence']}")
            previous = item["chain_hash"]


def run_replay(args: argparse.Namespace) -> int:
    policy = policy_from(load(Path(args.policy)))
    fixture = load(Path(args.events))
    if not isinstance(fixture, dict) or not isinstance(fixture.get("events"), list):
        raise EnforcerError("event fixture must contain an events list")
    now = parse_time(fixture.get("evaluatedAt", ""), "evaluatedAt")
    store = AuditStore(Path(args.database))
    outcomes = []
    for raw in fixture["events"]:
        decision = decide(raw, policy, now)
        stored, duplicate = store.record(raw, decision)
        outcomes.append({**asdict(stored), "duplicate": duplicate})
    store.verify()
    report = {
        "schemaVersion": "1.0",
        "evaluatedAt": fixture["evaluatedAt"],
        "synthetic": True,
        "outcomes": outcomes,
        "evidence": store.evidence(),
    }
    output = Path(args.output)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(
        f"events={len(outcomes)} unique={len(report['evidence'])} "
        f"duplicates={sum(item['duplicate'] for item in outcomes)} audit=valid"
    )
    return 0


def parser() -> argparse.ArgumentParser:
    value = argparse.ArgumentParser(description=__doc__)
    commands = value.add_subparsers(dest="command", required=True)
    replay = commands.add_parser("replay")
    replay.add_argument("--policy", required=True)
    replay.add_argument("--events", required=True)
    replay.add_argument("--database", required=True)
    replay.add_argument("--output", required=True)
    replay.set_defaults(handler=run_replay)
    return value


if __name__ == "__main__":
    try:
        arguments = parser().parse_args()
        raise SystemExit(arguments.handler(arguments))
    except (EnforcerError, OSError, sqlite3.Error) as exc:
        print(f"error: {exc}")
        raise SystemExit(1) from exc
