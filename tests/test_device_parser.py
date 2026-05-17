import unittest
from pathlib import Path

from modules.device_parser import DeviceParser

FIXTURES = Path(__file__).parent / "fixtures"


class DeviceParserTests(unittest.TestCase):
    def test_parse_installed_apps_from_uninstall_registry(self):
        reg_path = FIXTURES / "uninstall.reg"
        parser = DeviceParser()
        parser.set_files(uninstall_reg_files=[str(reg_path)])
        parser.parse_all()

        self.assertTrue(parser.apps.parsed)
        self.assertEqual(len(parser.apps.apps), 1)
        app = parser.apps.apps[0]
        self.assertEqual(app.name, "Contoso Agent")
        self.assertEqual(app.version, "1.2.3")
        self.assertEqual(app.install_date, "2026-05-18")
        self.assertEqual(app.arch, "x64")


if __name__ == "__main__":
    unittest.main()
