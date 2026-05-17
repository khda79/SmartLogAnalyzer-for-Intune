import unittest
from pathlib import Path

from modules.wu_parser import WUOrchestratorParser, WUPoliciesParser

FIXTURES = Path(__file__).parent / "fixtures"


class WUParserTests(unittest.TestCase):
    def test_orchestrator_reboot_required_is_decoded(self):
        parser = WUOrchestratorParser()
        self.assertTrue(parser.parse(str(FIXTURES / "wu_orchestrator.reg")))

        self.assertEqual(parser.info["Reboot Required"], "Yes")
        issues = parser.get_issues()
        self.assertTrue(any(i["title"] == "Reboot required" for i in issues))
        self.assertTrue(any("initialization failed" in i["title"] for i in issues))

    def test_policy_parser_finds_windows_update_gpo_keys(self):
        parser = WUPoliciesParser()
        self.assertTrue(parser.scan_reg_files([str(FIXTURES / "wu_policy.reg")]))

        self.assertTrue(parser.entries)
        self.assertEqual(parser.entries[0]["value"], "35")


if __name__ == "__main__":
    unittest.main()
