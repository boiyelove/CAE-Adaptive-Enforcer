import pathlib
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]


class RepositoryTests(unittest.TestCase):
    def test_goal_build_and_databases_are_ignored(self):
        ignored = (ROOT / ".gitignore").read_text(encoding="utf-8")
        self.assertIn("goal.md", ignored)
        self.assertIn("build/", ignored)
        self.assertIn("*.db", ignored)

    def test_function_uses_managed_identity_and_no_raw_subject_logging(self):
        adapter = (ROOT / "function_app.py").read_text(encoding="utf-8")
        self.assertIn("ManagedIdentityCredential", adapter)
        self.assertIn("User.RevokeSessions.All", adapter)
        self.assertNotIn("logging.info(event", adapter)
        self.assertNotIn("print(event", adapter)

    def test_iac_has_opt_in_identity_and_immutable_evidence(self):
        template = (ROOT / "infra/main.bicep").read_text(encoding="utf-8")
        self.assertIn("param deployPlatform bool = false", template)
        self.assertIn("allowSharedKeyAccess: false", template)
        self.assertIn("immutableStorageWithVersioning", template)
        self.assertIn("User.RevokeSessions.All", template)

    def test_ci_is_read_only_and_produces_sbom(self):
        workflow = (ROOT / ".github/workflows/ci.yml").read_text(encoding="utf-8")
        self.assertIn("contents: read", workflow)
        self.assertIn("anchore/sbom-action@v0.17.2", workflow)
        self.assertIn("gitleaks-action@v2", workflow)


if __name__ == "__main__":
    unittest.main()
