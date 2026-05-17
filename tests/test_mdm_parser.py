import unittest
from pathlib import Path

from modules.mdm_parser import MDMParser

FIXTURES = Path(__file__).parent / "fixtures"


class MDMParserTests(unittest.TestCase):
    def test_parse_dsreg_enrollment_results_and_firewall(self):
        parser = MDMParser()
        self.assertTrue(parser.parse_dsregcmd(str(FIXTURES / "dsregcmd.log")))
        self.assertTrue(parser.parse_enrollments_reg(str(FIXTURES / "enrollments.reg")))
        self.assertTrue(parser.parse_results_xml(str(FIXTURES / "results.xml")))
        self.assertTrue(parser.parse_firewall(str(FIXTURES / "firewall.log")))

        self.assertEqual(parser.device_info["AAD Joined"], "YES")
        self.assertEqual(parser.device_info["Device ID"], "device-123")
        self.assertEqual(parser.enrollment_info["UPN"], "user@example.com")
        self.assertEqual(len(parser.results_xml.errors), 1)
        issues = parser.get_all_issues()
        self.assertTrue(any(i["category"] == "AAD PRT" for i in issues))
        self.assertTrue(any(i["category"] == "Firewall" for i in issues))


if __name__ == "__main__":
    unittest.main()
