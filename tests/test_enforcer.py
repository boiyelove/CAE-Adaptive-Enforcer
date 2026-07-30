import copy
import datetime as dt
import pathlib
import sqlite3
import sys
import tempfile
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from enforcer import (  # noqa: E402
    AuditStore,
    EnforcerError,
    decide,
    load,
    policy_from,
)

NOW = dt.datetime(2026, 7, 30, 17, 36, tzinfo=dt.timezone.utc)


class EnforcerTests(unittest.TestCase):
    def setUp(self):
        self.policy = policy_from(load(ROOT / "config/policy.json"))
        self.events = load(ROOT / "examples/risk-events.json")["events"]

    def test_high_confidence_multi_domain_event_revokes(self):
        decision = decide(self.events[0], self.policy, NOW)
        self.assertEqual("revoke_sessions", decision.action)
        self.assertEqual(("identity", "network"), decision.signal_domains)

    def test_medium_single_domain_requires_step_up(self):
        self.assertEqual("require_step_up", decide(self.events[2], self.policy, NOW).action)

    def test_benign_event_is_monitored(self):
        self.assertEqual("monitor", decide(self.events[3], self.policy, NOW).action)

    def test_break_glass_is_never_automatically_revoked(self):
        decision = decide(self.events[4], self.policy, NOW)
        self.assertEqual("break_glass_noop", decision.action)
        self.assertTrue(decision.manual_follow_up)

    def test_stale_high_risk_event_is_quarantined(self):
        self.assertEqual("quarantine_stale", decide(self.events[5], self.policy, NOW).action)

    def test_single_domain_cannot_meet_revoke_confidence(self):
        event = copy.deepcopy(self.events[0])
        event["signals"] = ["high_user_risk", "impossible_travel"]
        decision = decide(event, self.policy, NOW)
        self.assertEqual("require_step_up", decision.action)

    def test_future_event_is_rejected(self):
        event = copy.deepcopy(self.events[0])
        event["occurredAt"] = "2026-07-30T18:38:00+01:00"
        with self.assertRaisesRegex(EnforcerError, "future"):
            decide(event, self.policy, NOW)

    def test_cross_tenant_event_is_rejected(self):
        event = copy.deepcopy(self.events[0])
        event["tenantId"] = "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb"
        with self.assertRaisesRegex(EnforcerError, "cross-tenant"):
            decide(event, self.policy, NOW)

    def test_unknown_signal_is_rejected(self):
        event = copy.deepcopy(self.events[0])
        event["signals"] = ["high_user_risk", "attacker_supplied"]
        with self.assertRaisesRegex(EnforcerError, "known"):
            decide(event, self.policy, NOW)

    def test_duplicate_event_is_idempotent(self):
        with tempfile.TemporaryDirectory() as temporary:
            store = AuditStore(pathlib.Path(temporary) / "audit.db")
            decision = decide(self.events[0], self.policy, NOW)
            self.assertFalse(store.record(self.events[0], decision)[1])
            self.assertTrue(store.record(self.events[0], decision)[1])
            self.assertEqual(1, len(store.evidence()))

    def test_event_id_collision_is_rejected(self):
        with tempfile.TemporaryDirectory() as temporary:
            store = AuditStore(pathlib.Path(temporary) / "audit.db")
            decision = decide(self.events[0], self.policy, NOW)
            store.record(self.events[0], decision)
            altered = copy.deepcopy(self.events[0])
            altered["riskLevel"] = "medium"
            with self.assertRaisesRegex(EnforcerError, "collision"):
                store.record(altered, decision)

    def test_tampered_audit_chain_is_detected(self):
        with tempfile.TemporaryDirectory() as temporary:
            store = AuditStore(pathlib.Path(temporary) / "audit.db")
            decision = decide(self.events[0], self.policy, NOW)
            store.record(self.events[0], decision)
            store.connection.execute(
                "UPDATE decisions SET chain_hash = ? WHERE sequence = 1", ("f" * 64,)
            )
            store.connection.commit()
            with self.assertRaisesRegex(EnforcerError, "audit chain invalid"):
                store.verify()


if __name__ == "__main__":
    unittest.main()
