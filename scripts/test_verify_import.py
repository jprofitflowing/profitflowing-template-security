"""Check the approval and upstream freshness gate without external access."""

import json
import unittest
from unittest.mock import patch

import verify_import

REPOSITORY = "example/template"
APPROVED = "a" * 40
CHANGED = "b" * 40


class ImportVerification(unittest.TestCase):
    def test_exact_approval_and_upstream_changes(self):
        manifest = {
            "schema_version": 1,
            "approved_sources": [{
                "repository": REPOSITORY, "commit": APPROVED, "source_path": "theme",
                "security_run": "https://github.com/jprofitflowing/profitflowing-template-security/actions/runs/1",
                "licence_decision": "approved",
            }],
        }
        head = {"sha": APPROVED}

        def metadata(repository, path=""):
            return head if path else {"full_name": REPOSITORY, "visibility": "public"}

        with (patch.object(verify_import.source, "api", side_effect=metadata) as api,
              patch.object(verify_import, "MANIFEST") as file):
            file.read_text.return_value = json.dumps(manifest)
            self.assertIn("No unique approval", verify_import.verify(REPOSITORY, APPROVED, "another"))
            self.assertIn("differs", verify_import.verify(REPOSITORY, CHANGED, "theme"))
            api.assert_not_called()
            self.assertIsNone(verify_import.verify(REPOSITORY, APPROVED, "theme"))
            head["sha"] = CHANGED
            self.assertIn("Upstream HEAD changed", verify_import.verify(REPOSITORY, APPROVED, "theme"))


if __name__ == "__main__":
    unittest.main()
