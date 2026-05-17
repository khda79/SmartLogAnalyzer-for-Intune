import unittest
from pathlib import Path

from modules.error_detector import ErrorDetector

FIXTURES = Path(__file__).parent / "fixtures"


class ErrorDetectorTests(unittest.TestCase):
    def test_scan_ime_log_detects_known_error_code(self):
        log_path = FIXTURES / "appworkload-20260518.log"
        detector = ErrorDetector()
        detector.scan_theme_files("appworkload", [str(log_path)])

        self.assertEqual(detector.get_summary()["error_count"], 1)
        self.assertEqual(detector.events[0].known_code, "APP_INSTALL_FAILED")
        self.assertEqual(detector.events[0].theme, "appworkload")

    def test_scan_plain_text_warning(self):
        log_path = FIXTURES / "plain-warning.log"
        detector = ErrorDetector()
        detector.scan_files([str(log_path)])

        self.assertEqual(detector.get_summary()["warning_count"], 1)
        self.assertEqual(detector.events[0].severity, "WARNING")


if __name__ == "__main__":
    unittest.main()
