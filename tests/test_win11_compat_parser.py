import unittest
from pathlib import Path

from modules.win11_compat_parser import (
    Win11CompatibilityIndicatorsParser,
    Win11CompatibilityIndicator,
    indicator_reason_text,
    is_blocking_indicator,
    safe_indicator_value,
)
from modules.zip_handler import _categorize


FIXTURES = Path(__file__).parent / "fixtures"


class Win11CompatibilityIndicatorsParserTests(unittest.TestCase):
    def test_safe_indicator_value_filters_placeholders_and_truncates(self):
        self.assertEqual("", safe_indicator_value("None"))
        self.assertEqual("", safe_indicator_value(" Not Applicable "))
        self.assertEqual("alpha, beta", safe_indicator_value(["alpha", " beta "]))
        self.assertEqual("abcdefg...", safe_indicator_value("abcdefghijkl", 10))

    def test_blocking_indicator_detects_upex_and_reason_fields(self):
        self.assertTrue(is_blocking_indicator(
            Win11CompatibilityIndicator("NI22H2", up_ex="Green, Hold")))
        self.assertTrue(is_blocking_indicator(
            Win11CompatibilityIndicator("NI22H2", sys_req_issue="Tpm")))
        self.assertFalse(is_blocking_indicator(
            Win11CompatibilityIndicator("GE24H2", up_ex="Green",
                                        gated_block_id="None",
                                        red_reason="N/A",
                                        sys_req_issue="NotApplicable")))

    def test_parse_blocking_registry_export(self):
        parser = Win11CompatibilityIndicatorsParser()
        self.assertTrue(parser.parse(str(FIXTURES / "win11_upgrade_indicators_blocking.reg")))

        self.assertEqual("BlockingConditionDetected", parser.status)
        self.assertEqual(1, len(parser.blocking_indicators))
        indicator = parser.blocking_indicators[0]
        self.assertEqual("NI22H2", indicator.target_version)
        self.assertIn("GatedBlockId=CPUFMS", indicator_reason_text(indicator))

    def test_parse_clear_registry_export(self):
        parser = Win11CompatibilityIndicatorsParser()
        self.assertTrue(parser.parse(str(FIXTURES / "win11_upgrade_indicators_clear.reg")))

        self.assertEqual("NoBlockingConditionDetected", parser.status)
        self.assertEqual(1, len(parser.indicators))
        self.assertEqual([], parser.blocking_indicators)
        self.assertEqual("UpEx=Green", parser.indicators[0].reason_text)

    def test_zip_handler_categorizes_upgrade_indicator_export(self):
        category = _categorize(
            "(12) RegistryKey Win11_Upgrade_Compatibility_Indicators.reg")
        self.assertEqual("reg_win11_upgrade_indicators", category)


if __name__ == "__main__":
    unittest.main()
