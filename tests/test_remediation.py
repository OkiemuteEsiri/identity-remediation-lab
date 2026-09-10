import unittest
from src.remediation import Identity, assess, assess_all, posture_score


class IdentityRemediationTests(unittest.TestCase):
    def make(self, **overrides):
        values = dict(identity_id="usr-1", identity_type="user", privileged=False,
                      mfa_enabled=True, enabled=True, last_signin_days=1,
                      credential_age_days=30, owner="IAM", standing_privilege=False,
                      break_glass=False)
        values.update(overrides)
        return Identity(**values)

    def test_privileged_without_mfa_is_critical(self):
        findings = assess(self.make(privileged=True, mfa_enabled=False))
        self.assertTrue(any(f.control_id == "ID-001" and f.severity == "critical" for f in findings))

    def test_break_glass_excluded_from_mfa_and_standing_checks(self):
        findings = assess(self.make(privileged=True, mfa_enabled=False, standing_privilege=True, break_glass=True))
        ids = {f.control_id for f in findings}
        self.assertNotIn("ID-001", ids)
        self.assertNotIn("ID-002", ids)

    def test_dormant_privileged_identity_is_high(self):
        findings = assess(self.make(privileged=True, last_signin_days=120))
        self.assertTrue(any(f.control_id == "ID-003" and f.severity == "high" for f in findings))

    def test_aged_service_credential_detected(self):
        findings = assess(self.make(identity_type="service", credential_age_days=200))
        self.assertTrue(any(f.control_id == "ID-004" for f in findings))

    def test_missing_owner_detected(self):
        findings = assess(self.make(owner=""))
        self.assertTrue(any(f.control_id == "ID-005" for f in findings))

    def test_finding_id_is_deterministic(self):
        f1 = assess(self.make(owner=""))[0]
        f2 = assess(self.make(owner=""))[0]
        self.assertEqual(f1.finding_id, f2.finding_id)

    def test_invalid_identity_type_rejected(self):
        with self.assertRaises(ValueError):
            self.make(identity_type="robot")

    def test_negative_age_rejected(self):
        with self.assertRaises(ValueError):
            self.make(last_signin_days=-1)

    def test_posture_score_bounded(self):
        identities = [self.make(identity_id="a", privileged=True, mfa_enabled=False, standing_privilege=True),
                      self.make(identity_id="b", owner="")]
        findings = assess_all(identities)
        score = posture_score(findings, len(identities))
        self.assertGreaterEqual(score, 0)
        self.assertLessEqual(score, 100)

    def test_assess_all_orders_by_severity(self):
        findings = assess_all([self.make(identity_id="a", owner=""), self.make(identity_id="b", privileged=True, mfa_enabled=False)])
        self.assertEqual(findings[0].severity, "critical")


if __name__ == "__main__":
    unittest.main()
