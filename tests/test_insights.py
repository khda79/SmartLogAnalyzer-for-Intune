import unittest
from types import SimpleNamespace

from modules.insights import build_insights


class InsightsTests(unittest.TestCase):
    def test_build_insights_prioritizes_actions_and_score(self):
        mdm = SimpleNamespace(
            get_all_issues=lambda: [{
                "severity": "ERROR",
                "title": "Primary Refresh Token not acquired",
                "detail": "AzureAdPrt=NO",
                "recommendation": "Fix user/device auth.",
                "source": "DSRegCmd",
            }]
        )
        event = SimpleNamespace(
            severity="ERROR",
            timestamp="2026-05-18 10:00:00",
            theme="appworkload",
            known_code="APP_INSTALL_FAILED",
            category="Win32App",
            message="Install failed",
            error_code="0x87D11001",
            source_file="appworkload.log",
        )
        detector = SimpleNamespace(events=[event])
        compliance = SimpleNamespace(policy_statuses=[])
        wu = SimpleNamespace(
            get_registry_issues=lambda: [],
            reporting=SimpleNamespace(events=[]),
            etl=SimpleNamespace(events=[]),
            orchestrator=SimpleNamespace(info={"Reboot Required": "Yes"}),
            policies=SimpleNamespace(entries=[]),
        )

        insights = build_insights(
            mdm_parser=mdm,
            error_detector=detector,
            compliance_summary=compliance,
            wu_parser=wu,
        )

        self.assertLess(insights.score.score, 100)
        self.assertTrue(insights.top_actions)
        self.assertTrue(any("Refresh Token" in item.title for item in insights.top_actions))
        self.assertTrue(insights.timeline)
        self.assertEqual(insights.wufb.status, "Review recommended")


if __name__ == "__main__":
    unittest.main()
